@echo off
cd /d "%~dp0"
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
set COOKIE_SECURE=0
python -m app.seed
echo Open http://localhost:8000
uvicorn app.main:app --host 127.0.0.1 --port 8000
