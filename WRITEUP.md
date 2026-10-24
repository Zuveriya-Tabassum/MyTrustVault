# TrustVault — write-up

## What I built
A document platform with three roles (admin, owner, viewer) where access is decided by the server on every request, every attempt (allowed or refused)
is written to a tamper-evident audit trail, and revoking access works on the very next request. FastAPI + SQLAlchemy, PostgreSQL in production (SQLite
locally), a dependency-free browser UI served by the same app, 55 automated tests that run on both databases, and a mutation script that proves the tests fail
when an authorisation check is removed.

## Permission model, in my own words
Access belongs to a **document**, never to a folder or group. The owner (the uploader) can do everything with their document and is the only one who can share, revoke or delete.
A grant is `read` (view + download) or `edit` (also rename/recategorise) for one named person. Categories are only labels for searching, they never grant anything,
because folder inheritance is exactly how "I shared one file and they can see forty" happens. **Admins manage users and read the audit trail, and see document metadata, but cannot open
a document's content unless they were granted it like anyone else.** A user who cannot see a document gets `404`, identical to a document that does not exist, so ids cannot be probed;
a user who can see it but lacks the action gets `403`.

The decision lives in one function, `authorize()` (`app/authz.py`), reached through one door, `load_document()`. No other module queries the documents table (a test enforces it).
Search is filtered inside the SQL query (own OR active grant), so unauthorised rows never leave the database.

## Immediate revocation
Sessions, the user's `active` flag and grants are read from the database on every request; nothing about permissions is cached or put in a token. Revoking a grant, deleting a document or disabling a user
therefore works on the next request, including for sessions that were already open. Cost: one or two extra queries per request, and no CDN/presigned URLs (they would stay valid after revocation).
**Accepted:** a download that has already started finishes.

## Audit trail
Append-only table. Each row stores the hash of the previous row plus its own fields (SHA-256 chain); `/admin/audit/verify` recomputes it. The application's DB role can only INSERT and SELECT
(verified on PostgreSQL), triggers reject UPDATE/DELETE/TRUNCATE, and refused attempts are logged with the reason. **What stops it being quietly altered?** The app cannot alter it; an attacker with database
superuser rights could, but editing or deleting a row breaks the chain and `verify` shows it (tests prove this). Rewriting the *whole* chain or truncating the tail is only caught if someone
recorded the head hash elsewhere, which is why `verify` returns it, and that anchoring is manual (not automated): an honest gap.

## What I deliberately did not build
Versions, trash/restore, external share links, previews/thumbnails/ZIP export (each is a second route to the bytes that would need its own authorisation), virus scanning, encryption at rest,
automatic audit anchoring, group permissions, content replacement (edit = rename/recategorise), password reset and MFA.

## How I used AI, and where it was wrong
Claude wrote most of the code; I directed it with `RULES.md` and adversarial-review prompts. Its mistakes that mattered (all in PROMPTS.md with fixes): a passing test that did not test the line it claimed to;
a test encoding the wrong policy; a document loader that returned 500 on PostgreSQL for a NUL byte; a "hardening" SQL file that was invalid and had never been run; a seed script that bypassed my own
one-door rule. The suggestion feature is advisory ML (TF-IDF similarity on metadata, optional LLM re-rank restricted to the server's own candidate list, anomaly flags by median/MAD), it never reads file
contents, never writes a grant, and both the suggestion and the owner's decision are audited.

## What is unfinished
Hosted DB-role hardening may not be possible on the free tier; audit anchoring is manual; rate limiting is in-memory per process; uploaded files are lost when a free host restarts; the build time was compressed
(see commit history) rather than spread over a week. See THREATS.md for every accepted risk.
