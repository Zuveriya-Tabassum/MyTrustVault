import hashlib, json, re
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from .db import Audit, now

GENESIS = "0" * 64
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

def clean(s, n=100) -> str:
    """Strip control chars (log forging / newline injection) and bound length."""
    return _CTRL.sub(" ", str(s))[:n]

def _canon(p: dict) -> str:
    return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def _digest(prev: str, p: dict) -> str:
    return hashlib.sha256((prev + _canon(p)).encode()).hexdigest()

FIELDS = ("ts", "actor_id", "action", "outcome", "target", "reason", "ip", "detail")

def log(db: Session, *, actor_id, action, outcome, target=None, reason="", ip="", detail=None) -> None:
    """Append one chained row. Does NOT commit: callers commit it atomically with the action."""
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(7001)"))  # serialise chain writers
    last = db.scalar(select(Audit).order_by(Audit.id.desc()).limit(1))
    prev = last.hash if last else GENESIS
    row = {"ts": now().isoformat(), "actor_id": actor_id, "action": clean(action, 30), "outcome": outcome,
           "target": clean(target, 64) if target else None, "reason": clean(reason), "ip": clean(ip, 64),
           "detail": clean(_canon(detail or {}), 500)}
    db.add(Audit(**row, prev_hash=prev, hash=_digest(prev, row)))
    db.flush()

def verify(db: Session) -> dict:
    """Recompute the whole chain. Returns head hash so it can be anchored outside the DB."""
    prev, n = GENESIS, 0
    for a in db.scalars(select(Audit).order_by(Audit.id)):
        row = {k: getattr(a, k) for k in FIELDS}
        if a.prev_hash != prev or a.hash != _digest(prev, row):
            return {"ok": False, "first_bad_id": a.id, "rows": n, "head": prev}
        prev, n = a.hash, n + 1
    return {"ok": True, "rows": n, "head": prev}
