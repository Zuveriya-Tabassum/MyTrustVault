# Submission checklist (deadline: Sunday 25 Oct 2026, 6:00 PM — editing locks automatically)

## Before you tick "I am done"
- [ ] Profile complete (name, phone, college, degree, branch, year, CGPA, backlogs, resume link set to "anyone with the link")
- [ ] Public GitHub repo, with history: commit your own further changes in small steps, do not squash. Do not backdate commits.
- [ ] Live URL opens for a stranger (open it once before judging: free hosts sleep). `/healthz` returns ok.
- [ ] README has: live URL, one working login per role, how to run from a clean clone, how to run tests
- [ ] THREATS.md rows each point to a real test name (open one test per row and confirm)
- [ ] PROMPTS.md: dates and commit links filled in; each entry true for YOU; 5+ entries, 2+ on authorisation/audit
- [ ] `pytest -q` green; `python tools/mutation_check.py` shows every mutant KILLED (output saved in mutation_output.txt)
- [ ] API.md (who may call each endpoint), WRITEUP.md, sql/schema_postgres.sql, DEPLOY.md present
- [ ] 5-minute demo video: (1) viewer refused → owner grants → viewer downloads → owner revokes → viewer refused on the next click,
      (2) admin audit trail shows each step incl. the refusal, (3) Verify audit chain, (4) one line: where the download check lives
- [ ] Rotate/remove demo passwords after judging

## Mapping to the marks
| Marks | Where the evidence is |
|---|---|
| 35 Security | live site; `authz.py`; `tests/test_authz_matrix.py`; strict CSP, CSRF, rate limit, upload validation |
| 15 Threats | THREATS.md (40 rows, each with test or accepted reason) + mutation_output.txt |
| 15 Functionality | README "Try it"; roles, grants, revoke, search, audit, admin view, suggestions |
| 15 AI use | PROMPTS.md + RULES.md + reusable prompts |
| 10 Engineering | small modules, one authorisation door, errors handled, tests on SQLite and PostgreSQL |
| 10 Docs/deploy/demo | README, DEPLOY.md, API.md, WRITEUP.md, video |

## The six form questions
I don't know the exact wording of your six boxes. Answer each from WRITEUP.md in your own words (they are likely: what you built; what you chose not to build; your permission model;
how you protect the audit trail; how you used AI and where it was wrong; what is unfinished). Short, specific and honest beats long.
