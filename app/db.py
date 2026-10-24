from datetime import datetime, timezone
from sqlalchemy import (create_engine, String, Integer, BigInteger, Boolean, DateTime,
                        ForeignKey, Index, Text, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from . import config

def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(config.DATABASE_URL, connect_args=_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)  # always stored lowercase
    pw_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10))  # admin | owner | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class SessionRow(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 of cookie token
    csrf: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(50))
    storage_key: Mapped[str] = mapped_column(String(32), unique=True)  # random, never user-supplied
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class Grant(Base):
    __tablename__ = "grants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doc_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    level: Mapped[str] = mapped_column(String(4))  # read | edit
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (
        # at most one ACTIVE grant per (doc,user); closes concurrent double-grant races
        Index("uq_active_grant", "doc_id", "user_id", unique=True,
              sqlite_where=text("revoked_at IS NULL"), postgresql_where=text("revoked_at IS NULL")),
    )

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer().with_variant(BigInteger, "postgresql"), primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(30))
    outcome: Mapped[str] = mapped_column(String(10))  # ok | denied | error
    target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(100), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

SQLITE_TRIGGERS = [
    "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END",
]
PG_TRIGGERS = [
    "CREATE OR REPLACE FUNCTION audit_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit is append-only'; END; $$ LANGUAGE plpgsql",
    "DROP TRIGGER IF EXISTS audit_no_mutation ON audit",
    "CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_immutable()",
    "DROP TRIGGER IF EXISTS audit_no_truncate ON audit",
    "CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable()",
]

def _fix(u: str) -> str:
    return u.replace("postgres://", "postgresql+psycopg://", 1).replace("postgresql://", "postgresql+psycopg://", 1)

def init_db():
    eng = create_engine(_fix(config.MIGRATE_DATABASE_URL)) if config.MIGRATE_DATABASE_URL else engine
    Base.metadata.create_all(eng)
    stmts = SQLITE_TRIGGERS if eng.dialect.name == "sqlite" else PG_TRIGGERS
    with eng.begin() as c:
        for s in stmts:
            c.execute(text(s))
