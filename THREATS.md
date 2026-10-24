# THREATS.md  (status: closed = mitigated + test; accepted = known, reasoned; open = not done)

| # | Threat | Mitigation | Test | Status |
|---|---|---|---|---|
| 1 | IDOR / forced browsing by doc id | Single door `load_document()` → `authorize()`; DB lookup every call | test_never_granted_gets_nothing | closed |
| 2 | Existence leak (404 vs 403, timing) | 404 unless caller already has read; unknown/malformed ids identical | test_unknown_and_malformed_ids_look_the_same | closed (timing not measured) |
| 3 | Admin reads content | Admin has no implicit access; metadata-only listing | test_admin_sees_metadata_not_content | closed |
| 4 | Grantee escalates read→edit, re-shares, deletes | `share`/`delete` owner-only; level→action map | test_read_grant_allows_only_read_and_download, test_edit_grant_can_edit_but_not_share_or_delete | closed |
| 5 | Mass assignment (owner_id, role) | pydantic `extra="forbid"` on all bodies | test_mass_assignment_rejected | closed |
| 6 | Revoked user keeps access via open session | Grants + session + `active` read from DB each request, no cache | test_revoke_is_immediate_for_an_already_open_session, test_inactive_user_with_surviving_session_is_rejected | closed |
| 7 | Disabled user's sessions/grants survive | Disable deletes sessions, closes grants | test_disabled_user_session_dies_immediately | closed |
| 8 | Search leaks titles/owners/categories | Filter inside SQL (ownership OR active grant) | test_search_never_leaks_other_users_documents, test_search_wildcards_are_literal | closed |
| 9 | Deleted doc reachable / grants resurrect | Soft delete closes all grants; `deleted` denies every action | test_deleted_doc_unreachable_even_for_owner_and_grants_closed | closed (no restore feature exists) |
| 10 | Role bypass on admin routes | `require_role` dependency; denial audited | test_viewer_cannot_upload_or_use_admin | closed |
| 11 | Forgotten route is unprotected | Meta-test walks all routes; public allowlist is explicit | test_every_route_is_authenticated_or_explicitly_public | closed |
| 12 | New code bypasses the loader | Test greps for direct Document queries outside authz.py | test_document_table_is_only_queried_in_authz_module | closed (grep-level, not a proof) |
| 13 | Someone removes the auth check | Mutation script proves suite fails without it | tools/mutation_check.py (mutation_output.txt) | closed |
| 14 | Audit edited/deleted | Append-only triggers; hash chain; verify endpoint; prod DB role w/o UPDATE/DELETE | test_audit_is_append_only_at_db_level, test_tampering_is_detected_even_if_triggers_are_bypassed, test_deleting_a_middle_row_is_detected | closed vs app compromise; **accepted** vs DB superuser (see 15) |
| 15 | DB superuser rewrites whole chain / truncates tail | `verify` returns head hash for external anchoring | — | **open**: anchoring not automated; operator must record `head` off-system |
| 16 | Denied attempts not recorded | Every denial audited with reason, actor, ip | test_denials_are_audited_with_reason | closed |
| 17 | Log forging (newline injection) | Control chars stripped, fields bounded | test_log_forging_is_neutralised | closed |
| 18 | CSRF | SameSite=Strict + per-session token in header, constant-time compare | test_csrf_required | closed (login CSRF accepted: low impact) |
| 19 | Brute force / user enumeration at login | Per-email and per-IP limits; identical error; dummy hash to equalise work | test_login_is_uniform_and_rate_limited | closed; limiter is in-memory, per-process → **accepted** |
| 20 | Malicious upload (type spoof, SVG/HTML XSS, oversize, path traversal) | Extension allowlist + magic bytes, size cap while streaming, random storage key, sanitised name, attachment + nosniff + CSP | test_upload_validation, test_filename_is_sanitised_and_storage_key_is_random, test_oversize_rejected, test_download_headers | closed; no AV scan, no zip inspection (docx accepted by magic only) → **accepted** |
| 21 | Concurrent double grant | Partial unique index on active grants | (index; no concurrent test) | closed by DB constraint, untested |
| 22 | Download in flight when access revoked | Bytes already sent cannot be recalled | — | **accepted**: streaming completes; revoke affects next request |
| 23 | Grantee downloads then leaks copy | Out of technical scope | — | **accepted**; audit proves who downloaded |
| 24 | Owner can probe which emails exist (grant by email) | Owners are internal staff | — | **accepted** |
| 25 | Client IP wrong behind proxy | `request.client.host` only; X-Forwarded-For never trusted (spoofable) | — | **accepted**: logs proxy IP on some hosts |
| 26 | Backups/storage dir contain plaintext files | — | — | **open**: no at-rest encryption |
| 27 | Suggestion widens access / injection via file content | Suggestions use metadata only (never file bytes), are advice-only routes, owner must confirm via a separate grant call; suggestion, rejection and `from_suggestion` all audited | test_suggestions_are_advice_only_and_never_create_a_grant, test_suggestion_and_decision_are_both_audited, test_suggestions_only_use_metadata_from_own_documents | closed |
| 29 | Stored XSS in UI via names/emails | UI uses textContent only; CSP `script-src 'self'`, no inline script | test_ui_is_served_with_strict_csp_and_no_inline_script | closed |
| 30 | Static route exposes DB/storage | Static dir contains only UI files; traversal returns 404 | test_static_mount_cannot_reach_storage_or_db | closed |
| 28 | Postgres role/trigger setup | sql/postgres_hardening.sql | — | **open**: not yet run against live Postgres |
| 31 | Prompt injection into the LLM re-ranker (a document name is attacker-influenced: an edit-grantee can rename) | Text marked as data; model output is filtered to the server's candidate set, so it cannot add people; still only advice that the owner confirms | test_llm_output_can_never_add_people_outside_the_candidates | closed (worst case: candidates reordered) |
| 32 | Anomaly detector false positives/negatives | Advisory flags only; thresholds documented (count>=5 and robust z>3.5) | test_burst_detector_flags_outlier_but_not_normal_use, test_admin_flags_endpoint_reports_burst_end_to_end | **accepted**: a slow exfiltration below threshold is not flagged |
| 33 | Suggestion leaks another owner's sharing habits | History query restricted to the caller's own documents | test_suggestions_only_use_metadata_from_own_documents | closed |
| 34 | Malformed / NUL-byte ids crash the authorisation door (500 on PostgreSQL) | Strict id regex before any query; NUL rejected in URL (400); `DataError` → 400 | test_unknown_and_malformed_ids_look_the_same, test_nul_bytes_in_json_do_not_cause_server_errors (run on SQLite **and** PostgreSQL) | closed |
| 35 | A grantee reads the access log of a document (learns who else tried) | `/activity` needs the owner-only `share` action | matrix row + test_owner_sees_who_accessed_including_refused_attempts | closed |
| 36 | Wiped disk (ephemeral hosting) → 500 or silent failure on download | Clean 404 "File unavailable", audited as `error/file_missing`; demo files re-created at boot | test_seed_is_idempotent_and_recreates_wiped_files | closed; **accepted**: real user uploads are lost on the free plan |
| 37 | App process compromised, tries to rewrite the audit table | DB role `tv_app` with INSERT/SELECT only on `audit` + triggers + hash chain | verified by hand on PostgreSQL 16 (UPDATE/DELETE/TRUNCATE/DROP all refused); tamper tests | closed locally; **open** on the hosted DB if the host does not allow creating roles |
| 38 | Demo accounts (incl. an admin) are public | One shared password from an env var; admin has no content access; documented rotation | test_admin_sees_metadata_not_content | **accepted** until judging ends, then rotate |
| 39 | Spoofed `X-Forwarded-For` poisons audit IPs / defeats the per-IP limit | Forwarded headers are **not** trusted; audit shows the proxy address on hosted deployments; per-email limit still applies | — | **accepted** (less precise IPs) |
| 40 | Reflected/stored XSS via the owner access log or audit table | Everything rendered with textContent; CSP without inline script | test_ui_is_served_with_strict_csp_and_no_inline_script, tools/ui_smoke.js | closed |
