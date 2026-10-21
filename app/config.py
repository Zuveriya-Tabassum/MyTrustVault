import os
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./trustvault.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
STORAGE_DIR = os.environ.get("STORAGE_DIR", "./storage")
MAX_BYTES = int(os.environ.get("MAX_BYTES", 10 * 1024 * 1024))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
SESSION_HOURS = 8
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "0") == "1"
