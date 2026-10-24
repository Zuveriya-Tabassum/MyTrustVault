# PROMPTS.md

> **Read this first (author's note).** Each entry below is a mistake that actually happened while building this project with Claude.
> Before submitting: check the date and commit hash in each entry (they come from this repository's own history; turn each hash into a GitHub link after you push), delete any entry that did not
> happen in your own workflow, and add entries for anything else you caught. Entries 1, 2, 3, 4 and 7 are about authorisation / audit.

## Context and prompts reused across the build
- **`RULES.md`** (in this repo) was pasted at the start of every session: the invariants the tool must not break
  (one door to documents, 404-vs-403 rule, no cached permissions, audit append-only, `extra="forbid"` on every body).
- **Adversarial-review prompt** (run after each feature): *"You are a hostile tester with a viewer account. List every way to read, change
  or delete a document you were not granted, using any route (list, search, download, export, error messages, timing, ids, headers,
  concurrency). For each, point at the line that stops it, or say there is none."*
- **Test-the-test prompt**: *"For every authorisation line in this diff, tell me the test that fails if I delete it. If none, write one."*
  (This produced `tools/mutation_check.py`.)
- **Dialect prompt**: *"Which of these queries or constraints behave differently on PostgreSQL than on SQLite?"* (asked too late, see entry 3).

## Entry 1 — Date: 2026-10-21 — A passing test that did not test the line (authorisation)
- **Asked:** write tests proving a disabled user loses access immediately.
- **Produced:** `test_disabled_user_session_dies_immediately`, passing.
- **Wrong:** I added a mutation script that deletes the `not user.active` check in `current_user`; the suite still passed. The test only
  proved that *disabling deletes sessions*. The second defence (re-checking `active` on every request) had no test, so a green suite hid an unprotected line.
- **Instead:** wrote `test_inactive_user_with_surviving_session_is_rejected` (flips `active` in the DB while the session row survives); the mutant is now killed. Commit: `b93ebf3` (after pushing: https://github.com/<you>/<repo>/commit/b93ebf3)

## Entry 2 — Date: 2026-10-21 — A test that encoded the wrong policy (authorisation)
- **Asked:** a search-leak test for two owners.
- **Produced:** a test in which Alice grants access to **Bob's** document and asserts success.
- **Wrong:** the server refused (correctly: only the owner can share), and the failing test pushed me toward "fixing" the code. The test, not the code, was wrong.
  Lesson: read a failing authorisation test against the written policy before touching the server.
- **Instead:** removed the line; kept the server as is. Commit: `b93ebf3` (after pushing: https://github.com/<you>/<repo>/commit/b93ebf3)

## Entry 3 — Date: 2026-10-24 — The authorisation door returned 500 on PostgreSQL (authorisation)
- **Asked:** a loader that returns 404 for unknown or malformed document ids.
- **Produced:** `db.get(Document, doc_id)` on the raw path value; the whole suite passed on SQLite.
- **Wrong:** I only ran the suite on SQLite. Running it against a real PostgreSQL showed that `GET /documents/%00` made the driver reject the NUL byte and the
  server answered **500** — an unauthenticated-looking probe crashing the very function that is supposed to deny. (A 500 also differs from the 404 an attacker gets for ordinary ids.)
- **Instead:** the loader now requires `[0-9a-f]{32}` before touching the DB, middleware rejects NUL bytes with 400, a `DataError` handler returns 400, and the whole suite
  runs on both databases (`TEST_DATABASE_URL`). Commit: `b00208c` (after pushing: https://github.com/<you>/<repo>/commit/b00208c)

## Entry 4 — Date: 2026-10-24 — "The app role cannot modify the audit table" was never run (audit trail)
- **Asked:** SQL that gives the app a role with INSERT/SELECT only on `audit`.
- **Produced:** `sql/postgres_hardening.sql` containing `GRANT CONNECT ON DATABASE current_database() ...` and a claim that it protects the audit trail.
- **Wrong:** that statement is not valid SQL, and nothing had been executed. When I ran it on a real Postgres I also found the app crashed at startup under the restricted role,
  because startup runs DDL (`CREATE TRIGGER`) that role may not run.
- **Instead:** fixed the script; added `RUN_MIGRATIONS` and `MIGRATE_DATABASE_URL` so schema setup uses the owner and the running app uses `tv_app`; verified with `psql` that
  UPDATE, DELETE, TRUNCATE and DROP on `audit` are refused for `tv_app`, and that the full app flow works as `tv_app`. Commit: `b00208c` (after pushing: https://github.com/<you>/<repo>/commit/b00208c)

## Entry 5 — Date: 2026-10-21 — Wrong parameter helper crashed the app at import
- **Asked:** a search endpoint with `q` limited to 100 characters.
- **Produced:** `q: str | None = Field(None, max_length=100)` on a query parameter.
- **Wrong:** `Field` is for body models; FastAPI raised at import time and the app did not start.
- **Instead:** `Query(None, max_length=100)`. Commit: `b93ebf3` (after pushing: https://github.com/<you>/<repo>/commit/b93ebf3)

## Entry 6 — Date: 2026-10-21 — Missing parenthesis would have shown a blank page
- **Asked:** a login view for the animated UI.
- **Produced:** 250 lines of JavaScript with one unbalanced `)` in the login view. Nothing in the Python tests could notice.
- **Instead:** `node --check` caught it; I then ran the real `app.js` in jsdom against a live server for owner, viewer and admin and asserted what each role sees
  (`tools/ui_smoke.js`). Commit: `34cc36f` (after pushing: https://github.com/<you>/<repo>/commit/34cc36f)

## Entry 7 — Date: 2026-10-24 — Seed script bypassed the "one door" rule (authorisation)
- **Asked:** idempotent demo seed data.
- **Produced:** a seed that looked documents up with raw SQL (`SELECT ... FROM documents`) inside `seed.py`.
- **Wrong:** my own invariant says only `authz.py` may read the documents table, and `test_document_table_is_only_queried_in_authz_module` greps for exactly this. Left in, the exemption
  would have been the first of many.
- **Instead:** the lookup moved into `authz.seed_lookup()`, documented as seed-only. Commit: `4491c98` (after pushing: https://github.com/<you>/<repo>/commit/4491c98)
