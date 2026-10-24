# API reference — who may call what
Auth: session cookie `tv_session` (HttpOnly, SameSite=Strict, Secure on HTTPS). Every non-GET request must also send `X-CSRF-Token`
(returned by `POST /auth/login` and `GET /me`). Errors: `401` not signed in · `403` signed in but not allowed (or you can see the
document but lack that action) · `404` the document does not exist **or you may not know it exists** · `409` conflict · `413/415/422` validation · `429` rate limited.
"Owner of doc" = the user who uploaded it. A *grant* is `read` or `edit` and is per document, per named person.

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /healthz` | anyone | liveness |
| `GET /` , `GET /static/*` | anyone | UI files only; no documents are ever served here |
| `POST /auth/login` | anyone | uniform error; rate limited per email and per IP; audited |
| `POST /auth/logout` | signed-in | deletes the session |
| `GET /me` | signed-in | identity, role, csrf token |
| `POST /documents` | role **owner** | multipart `file` + `category`; extension allowlist + content check + 10 MB cap |
| `GET /documents` | signed-in | search `q, owner, category, date_from, date_to`; **only own + granted docs, filtered in SQL** |
| `GET /documents/{id}` | doc owner, or grant read/edit | metadata |
| `GET /documents/{id}/download` | doc owner, or grant read/edit | streams through the app after the check; audited before bytes are sent |
| `PATCH /documents/{id}` | doc owner, or grant **edit** | `name`, `category` only; unknown fields rejected |
| `DELETE /documents/{id}` | doc owner only | soft delete; closes every grant |
| `GET /documents/{id}/grants` | doc owner only | |
| `PUT /documents/{id}/grants` | doc owner only | `{email, level, from_suggestion}`; create or change |
| `DELETE /documents/{id}/grants/{user_id}` | doc owner only | takes effect on the very next request |
| `GET /documents/{id}/suggestions` | doc owner only | advice only (similarity on metadata, optional LLM re-rank); cannot create grants |
| `POST /documents/{id}/suggestions/reject` | doc owner only | records the dismissal |
| `GET /documents/{id}/activity` | doc owner only | who touched this document, including refused attempts |
| `GET /admin/users` , `POST /admin/users` , `POST /admin/users/{id}/disable` | role **admin** | disable kills sessions and grants at once |
| `GET /admin/documents` | role **admin** | metadata only; **admins cannot open content without a grant** |
| `GET /admin/audit` | role **admin** | filters `action, outcome, limit` |
| `GET /admin/audit/verify` | role **admin** | recomputes the hash chain; returns head hash to anchor off-system |
| `GET /admin/flags` , `GET /admin/stats` | role **admin** | anomaly flags and dashboard numbers |
