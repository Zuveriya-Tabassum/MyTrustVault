# TrustVault (2-day build)
FastAPI + SQLAlchemy, with a dependency-free browser UI served by the same app (no Node, no build step). SQLite locally, PostgreSQL in production.

## Run locally (needs Python 3.10+)
    unzip trustvault.zip && cd trustvault
    ./run.sh          # Windows: run.bat      -> open http://localhost:8000

Manual: `pip install -r requirements.txt; COOKIE_SECURE=0 python -m app.seed; COOKIE_SECURE=0 uvicorn app.main:app`

    pytest -q                      # 51 tests
    python tools/mutation_check.py # removes auth checks; suite must fail (see mutation_output.txt)

Demo logins (password from `SEED_PASSWORD`, default in app/seed.py — **rotate after judging**):
admin@trustvault.test, owner@trustvault.test, owner2@trustvault.test, viewer@trustvault.test, viewer2@trustvault.test
Default password: `ChangeMe-Demo-2026!`

Try it: sign in as owner → upload → click the document → grant `viewer@trustvault.test` → sign in as viewer in a private window and download → revoke as owner → viewer's next request is refused → sign in as admin → Audit trail shows each step, including the refusal, and "Verify audit chain".

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
| GET /documents/{id}/suggestions, POST .../suggestions/reject | document owner only (advice; can never create a grant) |
| GET /admin/users, POST /admin/users, POST /admin/users/{id}/disable, GET /admin/documents, /admin/audit, /admin/audit/verify, /admin/flags | admin |

## Deliberately not built
Versions, trash/restore, external share links, previews/zip export, virus scan, encryption at rest, content replacement (edit = rename/recategorise only), LLM-based suggestions (suggestions are a rule on metadata: who you shared same-category documents with before).

## AI / ML in this product (advisory only, never in the permission path)
| Feature | Technique | Guardrail |
|---|---|---|
| "Suggested people" when sharing | TF-IDF + cosine similarity over document **metadata** (name tokens, category) vs. your earlier shares (`app/ml.py`) | Never reads file contents; only your own history; owner must press Grant; suggestion, dismissal and `from_suggestion` are audited |
| Optional LLM re-ranking | Set `ANTHROPIC_API_KEY` (and optionally `ANTHROPIC_MODEL`). Re-orders the candidates above | Output is filtered to the server's own candidate list, so it can't introduce anyone new; failures fall back silently |
| Admin "worth noticing" | Robust outlier detection (median/MAD modified z-score) on hourly download counts, off-hours access, refused-attempt and after-revoke rules | Flags only; nothing is blocked automatically |

## UI
Plain HTML/CSS/JS served by the app: responsive (phone bottom-sheet, tablet, desktop), dark mode, animated cards/drawer/toasts,
SVG charts, `prefers-reduced-motion` respected. Strict CSP (no inline script/style, no external hosts), so every animation is CSS-class driven.
Optional UI smoke test (needs Node): `npm i jsdom` then `node tools/ui_smoke.js` against a running server seeded with demo data.
