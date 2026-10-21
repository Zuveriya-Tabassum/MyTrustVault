#!/usr/bin/env bash
# One-command local start (Linux/macOS). Creates a venv, installs deps, seeds demo users, serves on :8000.
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
export COOKIE_SECURE=0
python -m app.seed
echo "Open http://localhost:8000"
exec uvicorn app.main:app --host 127.0.0.1 --port 8000
