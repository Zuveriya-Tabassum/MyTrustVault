import hashlib, hmac, os, re, secrets, time, uuid
from collections import defaultdict
from datetime import date, timedelta
from typing import Literal
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from datetime import datetime
from . import audit, config, ml
from .authz import load_document, search_documents, admin_list_documents, client_ip, doc_meta, peer_grantees, count_documents
from .db import (SessionLocal, init_db, User, SessionRow, Document, Grant, Audit, AppSetting, now)

app = FastAPI(title="TrustVault", docs_url="/docs" if config.ENABLE_DOCS else None,
              redoc_url=None, openapi_url="/openapi.json" if config.ENABLE_DOCS else None)
ph = PasswordHasher()
_DUMMY = ph.hash("dummy-password-for-timing")  # verify against this when user is unknown
SAFE = {"GET", "HEAD", "OPTIONS"}

@app.on_event("startup")
def _startup():
    os.makedirs(config.STORAGE_DIR, exist_ok=True)
    if config.RUN_MIGRATIONS:
        init_db()

@app.middleware("http")
async def headers_and_limits(request: Request, call_next):
    if "\x00" in request.url.path or "\x00" in request.url.query or "%00" in request.url.query.lower():
        return JSONResponse({"detail": "Bad request"}, status_code=400)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > config.MAX_BYTES + 1_000_000:
        return JSONResponse({"detail": "Too large"}, status_code=413)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                               "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                                               "form-action 'self'; frame-ancestors 'none'")
    resp.headers["Cache-Control"] = "no-store"
    return resp

from sqlalchemy.exc import DataError

@app.exception_handler(DataError)
def _bad_data(request: Request, exc: DataError):
    return JSONResponse({"detail": "Invalid input"}, status_code=400)   # e.g. NUL bytes in JSON strings on PostgreSQL

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

# ---------- authentication ----------
def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    tok = request.cookies.get("tv_session")
    if not tok:
        raise HTTPException(401, "Not authenticated")
    s = db.scalar(select(SessionRow).where(SessionRow.token_hash == _sha(tok)))
    if s is None or s.expires_at < now():
        raise HTTPException(401, "Not authenticated")
    user = db.get(User, s.user_id)
    if user is None or not user.active:  # re-checked on EVERY request
        raise HTTPException(401, "Not authenticated")
    if request.method not in SAFE:
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent, s.csrf):
            raise HTTPException(403, "CSRF check failed")
    return user

def require_role(*roles: str):
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if user.role not in roles:
            audit.log(db, actor_id=user.id, action="role_check", outcome="denied",
                      target=request.url.path[:60], reason=f"role_{user.role}", ip=client_ip(request))
            db.commit()
            raise HTTPException(403, "Forbidden")
        return user
    return dep

_fails: dict[str, list[float]] = defaultdict(list)
def _limited(key: str, limit: int) -> bool:
    t = time.time()
    _fails[key] = [x for x in _fails[key] if t - x < 900]
    return len(_fails[key]) >= limit

class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    password: str = Field(max_length=200)

@app.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email, ip = body.email.strip().lower(), client_ip(request)
    if _limited("e:" + email, 5) or _limited("i:" + ip, 30):
        audit.log(db, actor_id=None, action="login", outcome="denied", reason="rate_limited", ip=ip,
                  detail={"email": email[:80]})
        db.commit()
        raise HTTPException(429, "Too many attempts")
    user = db.scalar(select(User).where(User.email == email))
    ok = False
    try:
        ph.verify(user.pw_hash if user else _DUMMY, body.password)  # constant-ish work either way
        ok = user is not None and user.active
    except (VerifyMismatchError, InvalidHashError):
        ok = False
    if not ok:
        _fails["e:" + email].append(time.time()); _fails["i:" + ip].append(time.time())
        audit.log(db, actor_id=user.id if user else None, action="login", outcome="denied",
                  reason="bad_credentials", ip=ip, detail={"email": email[:80]})
        db.commit()
        raise HTTPException(401, "Invalid email or password")  # identical for every failure mode
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(SessionRow(token_hash=_sha(token), csrf=csrf, user_id=user.id,
                      expires_at=now() + timedelta(hours=config.SESSION_HOURS)))
    audit.log(db, actor_id=user.id, action="login", outcome="ok", ip=ip)
    db.commit()
    response.set_cookie("tv_session", token, httponly=True, secure=config.COOKIE_SECURE,
                        samesite="strict", max_age=config.SESSION_HOURS * 3600, path="/")
    return {"csrf": csrf, "role": user.role, "email": user.email}

@app.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(delete(SessionRow).where(SessionRow.token_hash == _sha(request.cookies["tv_session"])))
    audit.log(db, actor_id=user.id, action="logout", outcome="ok", ip=client_ip(request))
    db.commit()
    response.delete_cookie("tv_session", path="/")
    return {"ok": True}

@app.get("/me")
def me(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.scalar(select(SessionRow).where(SessionRow.token_hash == _sha(request.cookies["tv_session"])))
    return {"id": user.id, "email": user.email, "role": user.role, "csrf": s.csrf}

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/public-config")
def public_config(db: Session = Depends(get_db)):
    setting = db.get(AppSetting, "hide_demo_links")
    return {"hide_demo_links": setting is not None and setting.value == "true"}

# ---------- upload validation ----------
ALLOWED = {  # extension -> predicate on first bytes
    "pdf": lambda b: b.startswith(b"%PDF-"),
    "png": lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"),
    "jpg": lambda b: b.startswith(b"\xff\xd8\xff"),
    "jpeg": lambda b: b.startswith(b"\xff\xd8\xff"),
    "docx": lambda b: b.startswith(b"PK\x03\x04"),
    "txt": lambda b: b"\x00" not in b,
}
CAT_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,50}$")

def safe_name(raw: str) -> str:
    n = re.sub(r"[\x00-\x1f\x7f/\\]", "", (raw or "").replace("\\", "/").split("/")[-1]).strip().lstrip(".")
    return n[:200]

# ---------- documents ----------
@app.post("/documents", status_code=201)
def upload(request: Request, file: UploadFile = File(...), category: str = Form("general"),
           user: User = Depends(require_role("owner")), db: Session = Depends(get_db)):
    name = safe_name(file.filename or "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise HTTPException(415, "File type not allowed")
    if not CAT_RE.match(category):
        raise HTTPException(422, "Invalid category")
    key, path, h, size, head = uuid.uuid4().hex, None, hashlib.sha256(), 0, b""
    path = os.path.join(config.STORAGE_DIR, key)
    try:
        with open(path, "xb") as out:
            while chunk := file.file.read(64 * 1024):
                size += len(chunk)
                if size > config.MAX_BYTES:
                    raise HTTPException(413, "File too large")
                if len(head) < 16:
                    head += chunk[: 16 - len(head)]
                h.update(chunk); out.write(chunk)
        if size == 0 or not ALLOWED[ext](head):
            raise HTTPException(415, "File content does not match its type")
        if ext == "txt":
            open(path, "rb").read().decode("utf-8")  # must be valid UTF-8 text
        doc = Document(id=uuid.uuid4().hex, owner_id=user.id, name=name, category=category,
                       storage_key=key, size=size, sha256=h.hexdigest())
        db.add(doc)
        audit.log(db, actor_id=user.id, action="upload", outcome="ok", target=doc.id, ip=client_ip(request),
                  detail={"name": name, "size": size, "sha256": doc.sha256})
        db.commit()
    except UnicodeDecodeError:
        _rm(path); raise HTTPException(415, "File content does not match its type")
    except Exception:
        _rm(path); raise
    return doc_meta(doc, user.email)

def _rm(path):
    try: os.remove(path)
    except OSError: pass

@app.get("/documents")
def list_documents(q: str | None = Query(None, max_length=100), owner: str | None = Query(None, max_length=254),
                   category: str | None = Query(None, max_length=50), date_from: date | None = None, date_to: date | None = None,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    return search_documents(db, user, q, owner, category, date_from, date_to)

@app.get("/documents/{doc_id}")
def get_document(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "read", request)
    owner = db.get(User, doc.owner_id)
    return doc_meta(doc, owner.email)

@app.get("/documents/{doc_id}/download")
def download(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "download", request)
    fpath = os.path.join(config.STORAGE_DIR, doc.storage_key)
    if not os.path.isfile(fpath):   # e.g. ephemeral disk wiped on redeploy: say so, and record it
        audit.log(db, actor_id=user.id, action="download", outcome="error", target=doc.id, reason="file_missing",
                  ip=client_ip(request))
        db.commit()
        raise HTTPException(404, "File unavailable")
    audit.log(db, actor_id=user.id, action="download", outcome="ok", target=doc.id, ip=client_ip(request))
    db.commit()  # logged BEFORE any byte is sent
    return FileResponse(fpath, media_type="application/octet-stream",
                        filename=doc.name, content_disposition_type="attachment")

class DocPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")  # owner_id, storage_key etc. are rejected, not ignored
    name: str | None = Field(None, min_length=1, max_length=200)
    category: str | None = Field(None, pattern=r"^[A-Za-z0-9 ._-]{1,50}$")

@app.patch("/documents/{doc_id}")
def patch_document(doc_id: str, body: DocPatch, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "edit", request)
    before = {"name": doc.name, "category": doc.category}
    if body.name is not None:
        doc.name = safe_name(body.name) or doc.name
    if body.category is not None:
        doc.category = body.category
    audit.log(db, actor_id=user.id, action="update", outcome="ok", target=doc.id, ip=client_ip(request),
              detail={"before": before, "after": {"name": doc.name, "category": doc.category}})
    db.commit()
    return doc_meta(doc, db.get(User, doc.owner_id).email)

@app.delete("/documents/{doc_id}")
def delete_document(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "delete", request)
    doc.deleted_at = now()
    now_ = now()
    for g in db.scalars(select(Grant).where(Grant.doc_id == doc.id, Grant.revoked_at.is_(None))):
        g.revoked_at = now_  # soft delete also closes every grant
    audit.log(db, actor_id=user.id, action="delete", outcome="ok", target=doc.id, ip=client_ip(request))
    db.commit()
    return {"ok": True}

# ---------- grants (owner only) ----------
class GrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    level: Literal["read", "edit"]
    from_suggestion: bool = False  # recorded in the audit so we can tell human vs suggested decisions

@app.get("/documents/{doc_id}/grants")
def list_grants(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "share", request)
    rows = db.execute(select(Grant, User.email).join(User, User.id == Grant.user_id)
                      .where(Grant.doc_id == doc.id, Grant.revoked_at.is_(None))).all()
    return [{"user_id": g.user_id, "email": e, "level": g.level, "granted_at": g.granted_at.isoformat()} for g, e in rows]

@app.put("/documents/{doc_id}/grants")
def put_grant(doc_id: str, body: GrantIn, request: Request, user: User = Depends(current_user),
              db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "share", request)
    target = db.scalar(select(User).where(User.email == body.email.strip().lower(), User.active.is_(True)))
    if target is None:
        audit.log(db, actor_id=user.id, action="grant", outcome="denied", target=doc.id, reason="unknown_grantee",
                  ip=client_ip(request)); db.commit()
        raise HTTPException(404, "User not found")
    if target.id == doc.owner_id:
        raise HTTPException(422, "Owner already has full access")
    existing = db.scalar(select(Grant).where(Grant.doc_id == doc.id, Grant.user_id == target.id,
                                             Grant.revoked_at.is_(None)))
    if existing:
        existing.level, action = body.level, "grant_change"
    else:
        db.add(Grant(doc_id=doc.id, user_id=target.id, level=body.level, granted_by=user.id)); action = "grant"
    audit.log(db, actor_id=user.id, action=action, outcome="ok", target=doc.id, ip=client_ip(request),
              detail={"grantee": target.id, "level": body.level, "from_suggestion": body.from_suggestion})
    try:
        db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409, "Concurrent change, retry")
    return {"ok": True}

@app.delete("/documents/{doc_id}/grants/{user_id}")
def revoke_grant(doc_id: str, user_id: int, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "share", request)
    g = db.scalar(select(Grant).where(Grant.doc_id == doc.id, Grant.user_id == user_id, Grant.revoked_at.is_(None)))
    if g is None:
        raise HTTPException(404, "No active grant")
    g.revoked_at = now()
    audit.log(db, actor_id=user.id, action="revoke", outcome="ok", target=doc.id, ip=client_ip(request),
              detail={"grantee": user_id})
    db.commit()
    return {"ok": True}

# ---------- admin ----------
class AdminSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hide_demo_links: bool

@app.get("/admin/settings")
def admin_settings(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    setting = db.get(AppSetting, "hide_demo_links")
    return {"hide_demo_links": setting is not None and setting.value == "true"}

@app.patch("/admin/settings")
def update_admin_settings(body: AdminSettingsIn, admin: User = Depends(require_role("admin")),
                          db: Session = Depends(get_db)):
    setting = db.get(AppSetting, "hide_demo_links")
    if setting is None:
        setting = AppSetting(key="hide_demo_links", value=str(body.hide_demo_links).lower())
        db.add(setting)
    else:
        setting.value = str(body.hide_demo_links).lower()
    db.commit()
    return {"hide_demo_links": body.hide_demo_links}

class UserIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254)
    password: str = Field(min_length=12, max_length=200)
    role: Literal["admin", "owner", "viewer"]

@app.post("/admin/users", status_code=201)
def create_user(body: UserIn, request: Request, admin: User = Depends(require_role("admin")),
                db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered")
    u = User(email=email, pw_hash=ph.hash(body.password), role=body.role)
    db.add(u); db.flush()
    audit.log(db, actor_id=admin.id, action="user_create", outcome="ok", target=str(u.id), ip=client_ip(request),
              detail={"role": body.role})
    db.commit()
    return {"id": u.id, "email": u.email, "role": u.role}

@app.post("/admin/users/{user_id}/disable")
def disable_user(user_id: int, request: Request, admin: User = Depends(require_role("admin")),
                 db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None or u.id == admin.id:
        raise HTTPException(404, "Not found")
    u.active = False
    db.execute(delete(SessionRow).where(SessionRow.user_id == u.id))  # sessions die immediately
    for g in db.scalars(select(Grant).where(Grant.user_id == u.id, Grant.revoked_at.is_(None))):
        g.revoked_at = now()
    audit.log(db, actor_id=admin.id, action="user_disable", outcome="ok", target=str(u.id), ip=client_ip(request))
    db.commit()
    return {"ok": True}

@app.get("/admin/documents")
def admin_documents(request: Request, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    audit.log(db, actor_id=admin.id, action="admin_list", outcome="ok", ip=client_ip(request)); db.commit()
    return admin_list_documents(db)

@app.get("/admin/audit")
def admin_audit(request: Request, limit: int = 200, action: str | None = None, outcome: str | None = None,
                admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    stmt = select(Audit).order_by(Audit.id.desc()).limit(min(max(limit, 1), 1000))
    if action: stmt = stmt.where(Audit.action == action)
    if outcome: stmt = stmt.where(Audit.outcome == outcome)
    rows = db.scalars(stmt).all()
    return [{k: getattr(a, k) for k in ("id",) + audit.FIELDS + ("hash",)} for a in rows]

@app.get("/admin/audit/verify")
def admin_verify(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return audit.verify(db)

@app.get("/admin/flags")
def admin_flags(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """Things worth noticing: repeated denials, and attempts after a grant was revoked."""
    flags = []
    since = (now() - timedelta(hours=24)).isoformat()
    denied = db.scalars(select(Audit).where(Audit.outcome == "denied", Audit.ts >= since)).all()
    per_actor: dict = defaultdict(int)
    for a in denied:
        if a.actor_id: per_actor[a.actor_id] += 1
    flags += [{"type": "repeated_denials", "actor_id": k, "count": v} for k, v in per_actor.items() if v >= 5]
    for g in db.scalars(select(Grant).where(Grant.revoked_at.is_not(None))):
        n = sum(1 for a in denied if a.actor_id == g.user_id and a.target == g.doc_id and a.ts >= g.revoked_at.isoformat())
        if n:
            flags.append({"type": "access_attempt_after_revoke", "actor_id": g.user_id, "doc_id": g.doc_id, "count": n})
    # statistical detectors (advisory: they flag, they never block)
    week = (now() - timedelta(days=8)).isoformat()
    ev = [(a.actor_id, datetime.fromisoformat(a.ts)) for a in
          db.scalars(select(Audit).where(Audit.action == "download", Audit.outcome == "ok", Audit.ts >= week)) if a.actor_id]
    flags += ml.hourly_bursts(ev, now()) + ml.off_hours(ev, now())
    return flags

@app.get("/admin/stats")
def admin_stats(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    from sqlalchemy import func
    start = now() - timedelta(days=13)
    days = {(start + timedelta(days=i)).date().isoformat(): {"d": (start + timedelta(days=i)).date().isoformat(), "ok": 0, "denied": 0}
            for i in range(14)}
    by_action: dict = defaultdict(int)
    for a in db.scalars(select(Audit).where(Audit.ts >= start.date().isoformat())):
        if a.ts[:10] in days and a.outcome in ("ok", "denied"):
            days[a.ts[:10]][a.outcome] += 1
        by_action[a.action] += 1
    return {"days": list(days.values()), "by_action": dict(by_action),
            "totals": {"users": db.scalar(select(func.count(User.id))), "documents": count_documents(db),
                       "grants": db.scalar(select(func.count(Grant.id)).where(Grant.revoked_at.is_(None))),
                       "audit": db.scalar(select(func.count(Audit.id))),
                       "denied": db.scalar(select(func.count(Audit.id)).where(Audit.outcome == "denied"))}}


# ---------- suggestions: advice only. These routes can never create a grant ----------
@app.get("/documents/{doc_id}/suggestions")
def suggestions(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "share", request)
    already = {g.user_id for g in db.scalars(select(Grant).where(Grant.doc_id == doc.id, Grant.revoked_at.is_(None)))}
    out = [x for x in peer_grantees(db, user, doc) if x["user_id"] not in already]
    audit.log(db, actor_id=user.id, action="ai_suggest", outcome="ok", target=doc.id, ip=client_ip(request),
              detail={"suggested": [x["user_id"] for x in out]})
    db.commit()
    return [{"email": x["email"], "reason": x["reason"], "score": x["score"], "source": x["source"]} for x in out]

@app.get("/documents/{doc_id}/activity")
def activity(doc_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Owner-only: who touched THIS document and when, including refused attempts (read from the audit chain)."""
    doc = load_document(db, user, doc_id, "share", request)
    rows = db.execute(select(Audit, User.email).outerjoin(User, User.id == Audit.actor_id)
                      .where(Audit.target == doc.id).order_by(Audit.id.desc()).limit(50)).all()
    return [{"ts": a.ts, "actor": e or "unknown", "action": a.action, "outcome": a.outcome, "reason": a.reason}
            for a, e in rows]

class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)

@app.post("/documents/{doc_id}/suggestions/reject")
def reject_suggestion(doc_id: str, body: RejectIn, request: Request, user: User = Depends(current_user),
                      db: Session = Depends(get_db)):
    doc = load_document(db, user, doc_id, "share", request)
    audit.log(db, actor_id=user.id, action="ai_reject", outcome="ok", target=doc.id, ip=client_ip(request),
              detail={"email": body.email.strip().lower()[:80]})
    db.commit()
    return {"ok": True}

@app.get("/admin/users")
def admin_users(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return [{"id": u.id, "email": u.email, "role": u.role, "active": u.active}
            for u in db.scalars(select(User).order_by(User.id))]

# ---------- web UI (static files only; no document is ever served from here) ----------
_STATIC = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(_STATIC, "index.html"))
