import os, tempfile
_tmp = tempfile.mkdtemp()
# Set TEST_DATABASE_URL=postgresql://... to run the whole suite against PostgreSQL instead of SQLite.
os.environ.update(DATABASE_URL=os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_tmp}/t.db"),
                  STORAGE_DIR=f"{_tmp}/files", COOKIE_SECURE="0")
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from app import main
from app.db import Base, engine, init_db, SessionLocal, User

from argon2 import PasswordHasher
main.ph = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)  # fast hashing for tests only
PW = "Test-Password-123!"
_HASH = main.ph.hash(PW)
USERS = [("admin@t.test", "admin"), ("alice@t.test", "owner"), ("bob@t.test", "owner"),
         ("vic@t.test", "viewer"), ("eve@t.test", "viewer")]

class Client:
    def __init__(self, email, pw=PW):
        self.c = TestClient(main.app)
        r = self.c.post("/auth/login", json={"email": email, "password": pw})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf"]
    def req(self, method, url, **kw):
        h = kw.pop("headers", {}); h["X-CSRF-Token"] = self.csrf
        return self.c.request(method, url, headers=h, **kw)
    def upload(self, name="salary.pdf", body=b"%PDF-1.4 TOPSECRET-CONTENT", category="hr"):
        return self.req("POST", "/documents", files={"file": (name, body)}, data={"category": category})

@pytest.fixture(autouse=True)
def fresh():
    Base.metadata.drop_all(engine); init_db(); main._fails.clear()
    os.makedirs(os.environ["STORAGE_DIR"], exist_ok=True)
    with SessionLocal() as db:
        for e, r in USERS:
            db.add(User(email=e, pw_hash=_HASH, role=r))
        db.commit()
    yield

@pytest.fixture
def who():
    return {n: Client(f"{n}@t.test") for n in ("admin", "alice", "bob", "vic", "eve")}

def uid(email):
    with SessionLocal() as db:
        return db.scalar(select(User).where(User.email == email)).id


def drop_audit_triggers(conn):
    """Simulates an attacker with DB superuser rights removing the append-only triggers."""
    from sqlalchemy import text
    if conn.dialect.name == "sqlite":
        conn.execute(text("DROP TRIGGER audit_no_update")); conn.execute(text("DROP TRIGGER audit_no_delete"))
    else:
        conn.execute(text("DROP TRIGGER audit_no_mutation ON audit"))
