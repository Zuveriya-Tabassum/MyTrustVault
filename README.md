# TrustVault (2-day build)
FastAPI + SQLAlchemy. SQLite locally, PostgreSQL in production. No UI yet: JSON API only.

## Run
    pip install -r requirements.txt
    COOKIE_SECURE=0 python -m app.seed && COOKIE_SECURE=0 uvicorn app.main:app
    pytest -q                      # 39 tests
    python tools/mutation_check.py # removes auth checks; suite must fail (see mutation_output.txt)

Demo logins (password from `SEED_PASSWORD`, default in app/seed.py — **rotate after judging**):
admin@trustvault.test, owner@trustvault.test, owner2@trustvault.test, viewer@trustvault.test, viewer2@trustvault.test

## Permission model
Per-document grants only (read | edit). No folders/groups/inheritance: categories are labels, they never grant access.
Owner: full control of own docs, the only one who can share/revoke/delete. Admin: users, audit, document *metadata*; no content without a grant.
Viewer: only what was granted. Denied → 404 (403 only if you can already see the doc). Details in THREATS.md.

## API (who may call)
| Endpoint | Allowed |
|---|---|
| POST /auth/login, GET /healthz | public |
| POST /auth/logout, GET /me, GET /documents (search) | any signed-in user (results filtered to own/granted) |
| POST /documents | owner |
| GET /documents/{id}, GET .../download | owner, or grant read/edit |
| PATCH /documents/{id} | owner, or grant edit |
| DELETE /documents/{id}, GET/PUT/DELETE .../grants | document owner only |
| POST /admin/users, POST /admin/users/{id}/disable, GET /admin/documents, /admin/audit, /admin/audit/verify, /admin/flags | admin |

## Deliberately not built
Versions, trash/restore, external share links, previews/zip export, virus scan, encryption at rest, AI suggestions, UI.
