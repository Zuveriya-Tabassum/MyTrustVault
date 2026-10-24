"""python -m app.seed  -> creates one demo account per role. ROTATE/DELETE after judging."""
import os
from argon2 import PasswordHasher
from sqlalchemy import select
import hashlib, uuid
from . import audit, config
from .authz import seed_lookup
from .db import SessionLocal, User, Document, Grant, init_db

def seed():
    init_db()
    ph = PasswordHasher()
    pw = os.environ.get("SEED_PASSWORD", "ChangeMe-Demo-2026!")
    with SessionLocal() as db:
        for email, role in [("admin@trustvault.test", "admin"), ("owner@trustvault.test", "owner"),
                            ("owner2@trustvault.test", "owner"), ("viewer@trustvault.test", "viewer"),
                            ("viewer2@trustvault.test", "viewer")]:
            if not db.scalar(select(User).where(User.email == email)):
                db.add(User(email=email, pw_hash=ph.hash(pw), role=role))
        db.commit()
        _demo_docs(db)

DEMO = [  # (owner, name, category, text, grantee)
    ("owner@trustvault.test", "Salary-letter-A-Sharma.txt", "hr", "CONFIDENTIAL demo salary letter.\n", "viewer@trustvault.test"),
    ("owner@trustvault.test", "Contract-ACME-2026.txt", "legal", "CONFIDENTIAL demo contract. Not shared with anyone.\n", None),
    ("owner2@trustvault.test", "Drawing-notes-rev4.txt", "engineering", "CONFIDENTIAL demo drawing notes (owner2 only).\n", None),
]

def _demo_docs(db):
    """Idempotent demo data. Re-writes the file if the disk was wiped (ephemeral hosting)."""
    os.makedirs(config.STORAGE_DIR, exist_ok=True)
    for owner_email, name, cat, body, grantee in DEMO:
        owner = db.scalar(select(User).where(User.email == owner_email))
        data, found = body.encode(), seed_lookup(db, owner.id, name)
        if found is None:
            key = uuid.uuid4().hex
            d = Document(id=uuid.uuid4().hex, owner_id=owner.id, name=name, category=cat, storage_key=key,
                         size=len(data), sha256=hashlib.sha256(data).hexdigest())
            db.add(d)
            audit.log(db, actor_id=owner.id, action="upload", outcome="ok", target=d.id, ip="seed",
                      detail={"name": name, "seed": True})
            if grantee:
                g = db.scalar(select(User).where(User.email == grantee))
                db.add(Grant(doc_id=d.id, user_id=g.id, level="read", granted_by=owner.id))
                audit.log(db, actor_id=owner.id, action="grant", outcome="ok", target=d.id, ip="seed",
                          detail={"grantee": g.id, "level": "read", "seed": True})
            db.commit()
        else:
            key = found[1]
        path = os.path.join(config.STORAGE_DIR, key)
        if not os.path.isfile(path):
            with open(path, "wb") as f:
                f.write(data)

if __name__ == "__main__":
    seed(); print("seeded")
