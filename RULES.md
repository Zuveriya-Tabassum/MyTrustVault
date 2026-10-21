# Invariants (context file given to the AI tool on every session)
- Every document read/write goes through `load_document()` in app/authz.py. Never `select(Document)` / `db.get(Document)` anywhere else (a test enforces this).
- Authorization is decided server-side in `authorize()`; never trust client flags.
- Unauthorized => 404 if the caller cannot see the doc, 403 if they can see it but lack the action. Always write a denied audit row with the real reason.
- Never cache permission decisions. Grants and sessions are read from the DB on every request.
- Admin may list metadata and read audit; admin may NOT read file content without an explicit grant.
- Audit table is append-only: never UPDATE/DELETE it. Success audit is written in the same transaction as the action.
- Request bodies use pydantic models with extra="forbid" (no mass assignment).
- Every new endpoint needs a row in tests/test_authz_matrix.py; test_routes.py fails on unprotected routes.
