# Interview cheat-sheet (read the code, not this file, while answering)

**Q: Where is the authorisation decision made when someone downloads a file?**
`app/main.py: download()` → `load_document(db, user, doc_id, "download", request)` in `app/authz.py` → `authorize(db, user, doc, "download")`.
`authorize` checks: deleted? → no. user active? → no. owner? → yes. Otherwise it reads the **active** grant row for (doc, user) from the DB and checks that its level allows `download`. No grant → no.

**Q: What happens if I remove that line?**
The line is `if not decision.allowed:` in `load_document`. Without it, any signed-in user who knows a document id (32 random hex characters) can download it. Tests that fail: `test_never_granted_gets_nothing[vic|bob|admin]`,
`test_read_grant_allows_only_read_and_download`, and more. `python tools/mutation_check.py` does exactly this removal and shows the suite going red. If instead `authorize()` always returned True, the same tests fail.

**Q: Walk me through revocation.** `DELETE /documents/{id}/grants/{user}` sets `revoked_at`. `authorize()` only looks at grants where `revoked_at IS NULL`, queried fresh each request. No cache, no token claims. Test: `test_revoke_is_immediate_for_an_already_open_session`.

**Q: Why 404 and not 403?** So that ids cannot be probed. 403 is returned only to someone who can already see the document (they have a lesser grant).

**Q: Why can't an admin read content?** Least privilege: administrators run the system, they don't need the contents, and the audit trail then answers "who read it" without an admin exception. They can grant themselves access only by being granted by an owner.

**Q: Who can see the audit trail, and what stops edits?** Admins (read). The app DB role cannot update or delete it, triggers refuse it, and the hash chain exposes changes. A DBA with superuser rights could rewrite everything; only an off-system copy of the head hash would reveal that.

**Q: Why FastAPI + Postgres + a plain-JS UI?** Fewer moving parts and less attack surface (no SPA token storage, no CORS, same origin, strict CSP); I can change any line live.

**Q: What would you do with another week?** Automate hash anchoring, move rate limiting to the database, encrypt files at rest with per-document keys, add external expiring links (hashed tokens, revocable), versions with per-version grants, and a real concurrency test for grant/revoke races.

**Practice before the interview:** delete the check in `authorize()` for `edit` and find which test fails; add a new field to `DocPatch` and see why `extra="forbid"` matters; trace one refused download from the request to the audit row.
