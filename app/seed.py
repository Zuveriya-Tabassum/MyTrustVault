"""python -m app.seed  -> creates one demo account per role. ROTATE/DELETE after judging."""
import os
from argon2 import PasswordHasher
from sqlalchemy import select
from .db import SessionLocal, User, init_db

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

if __name__ == "__main__":
    seed(); print("seeded")
