# PROMPTS.md  — log entries as they happen. Each needs: date, prompt, output, what was wrong, fix commit.

## Reused context file
`RULES.md` (invariants) was given to the tool at the start of every session.

## Entry 1 — 2026-10-21 — authorisation tests (REAL, found by tools/mutation_check.py)
- Asked: write the core + tests for per-request revocation of disabled users.
- Produced: `test_disabled_user_session_dies_immediately`, which passed.
- Wrong: the mutation script removed the `not user.active` check in `current_user` and the suite STILL passed. The test only proved that *disabling deletes sessions*; the second defence (re-checking `active` per request) was untested, so a green suite hid an unprotected line.
- Fix: added `test_inactive_user_with_surviving_session_is_rejected`; mutant now killed. Commit: <fill in hash>

## Entry 2 — 2026-10-21 — audit/authz test (REAL)
- Asked: search-leak test.
- Produced: a test where Alice called `share` on Bob's document and asserted success.
- Wrong: the test asserted the opposite of the policy (a non-owner sharing someone else's doc). The server correctly refused; the test was wrong. Lesson: a failing authz test can mean the test, not the code, is wrong — read the failure against the policy before "fixing" code.
- Fix: removed the line. Commit: <fill in hash>

## Entries 3–5+ — TO WRITE FROM YOUR OWN WORK
Do not invent these. Likely places to look: any list route that filters in Python, a PATCH schema that accepts extra fields,
a presigned/static file route, a cached permission check, `==` on tokens. At least two must be authz/audit.
