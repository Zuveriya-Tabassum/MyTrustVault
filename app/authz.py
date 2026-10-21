"""THE ONLY MODULE ALLOWED TO QUERY THE DOCUMENTS TABLE.
Every decision about who may touch a document is made here, from the database, on every call."""
from dataclasses import dataclass
from datetime import date, datetime, time
from fastapi import HTTPException, Request
from sqlalchemy import select, or_, and_
from sqlalchemy.orm import Session
from . import audit
from .db import Document, Grant, User, now

# What each grant level allows. 'share' and 'delete' are owner-only and can never be granted.
LEVEL_ACTIONS = {"read": {"read", "download"}, "edit": {"read", "download", "edit"}}
OWNER_ACTIONS = {"read", "download", "edit", "delete", "share"}

@dataclass
class Decision:
    allowed: bool
    reason: str

def authorize(db: Session, user: User, doc: Document, action: str) -> Decision:
    if doc.deleted_at is not None:
        return Decision(False, "deleted")
    if not user.active:
        return Decision(False, "user_disabled")
    if doc.owner_id == user.id:
        return Decision(action in OWNER_ACTIONS, "owner" if action in OWNER_ACTIONS else "unknown_action")
    # Admins get NO implicit content access: they fall through to the grant check like anyone else.
    g = db.scalar(select(Grant).where(Grant.doc_id == doc.id, Grant.user_id == user.id,
                                      Grant.revoked_at.is_(None)))
    if g is None:
        return Decision(False, "no_grant")
    if action in LEVEL_ACTIONS.get(g.level, set()):
        return Decision(True, f"grant:{g.level}")
    return Decision(False, f"grant_{g.level}_insufficient")

def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""

def load_document(db: Session, user: User, doc_id: str, action: str, request: Request) -> Document:
    """The single door to a document. Returns it only if authorised, else audits and raises."""
    doc = db.get(Document, doc_id)
    if doc is None:
        audit.log(db, actor_id=user.id, action=action, outcome="denied", target=doc_id,
                  reason="not_found", ip=client_ip(request))
        db.commit()
        raise HTTPException(404, "Not found")
    decision = authorize(db, user, doc, action)
    if not decision.allowed:  # AUTHZ-CHECK (mutation_check.py removes this line's effect)
        audit.log(db, actor_id=user.id, action=action, outcome="denied", target=doc.id,
                  reason=decision.reason, ip=client_ip(request))
        db.commit()  # denial must persist even though the request fails
        can_see = authorize(db, user, doc, "read").allowed
        raise HTTPException(403 if can_see else 404, "Forbidden" if can_see else "Not found")
    return doc

def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def search_documents(db: Session, user: User, q=None, owner=None, category=None,
                     date_from: date | None = None, date_to: date | None = None, limit=100):
    """Search, filtered IN SQL by ownership/active grant, so unauthorised rows never leave the DB."""
    has_grant = select(Grant.id).where(Grant.doc_id == Document.id, Grant.user_id == user.id,
                                       Grant.revoked_at.is_(None)).exists()
    stmt = (select(Document, User.email).join(User, User.id == Document.owner_id)
            .where(Document.deleted_at.is_(None), or_(Document.owner_id == user.id, has_grant)))
    if q:
        stmt = stmt.where(Document.name.ilike(f"%{_esc(q)}%", escape="\\"))
    if owner:
        stmt = stmt.where(User.email == owner.strip().lower())
    if category:
        stmt = stmt.where(Document.category == category)
    if date_from:
        stmt = stmt.where(Document.created_at >= datetime.combine(date_from, time.min))
    if date_to:
        stmt = stmt.where(Document.created_at <= datetime.combine(date_to, time.max))
    rows = db.execute(stmt.order_by(Document.created_at.desc()).limit(min(limit, 200))).all()
    return [doc_meta(d, email) for d, email in rows]

def admin_list_documents(db: Session, limit=200):
    """Admin sees METADATA only (never content). Caller must already have enforced role=admin."""
    rows = db.execute(select(Document, User.email).join(User, User.id == Document.owner_id)
                      .order_by(Document.created_at.desc()).limit(limit)).all()
    return [doc_meta(d, email) | {"deleted": d.deleted_at is not None} for d, email in rows]

def doc_meta(d: Document, owner_email: str) -> dict:
    return {"id": d.id, "name": d.name, "category": d.category, "owner": owner_email,
            "size": d.size, "sha256": d.sha256, "created_at": d.created_at.isoformat()}


def peer_grantees(db: Session, owner: User, doc: Document, limit=5):
    """Suggestion basis = METADATA ONLY (names/categories of this owner's other docs and who they were shared with).
    File contents are never read. Output is advice; nothing here writes a grant."""
    from . import ml
    rows = db.execute(
        select(Document.id, Document.name, Document.category, Grant.user_id, User.email)
        .join(Grant, Grant.doc_id == Document.id).join(User, User.id == Grant.user_id)
        .where(Document.owner_id == owner.id, Document.deleted_at.is_(None), Document.id != doc.id,
               User.active.is_(True), Grant.user_id != owner.id)).all()
    hist = [{"doc_id": r[0], "name": r[1], "category": r[2], "user_id": r[3], "email": r[4]} for r in rows]
    cands = ml.rank(doc.name, doc.category, hist, limit)
    return ml.apply_rerank(cands, ml.llm_rerank(doc.name, doc.category, cands))

def count_documents(db: Session) -> int:
    from sqlalchemy import func
    return db.scalar(select(func.count(Document.id)).where(Document.deleted_at.is_(None))) or 0
