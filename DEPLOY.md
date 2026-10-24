# Deploying (free, no credit card) — about 15 minutes

## A. Push to GitHub
    git init   # (already done if you cloned) 
    git remote add origin https://github.com/<you>/trustvault.git
    git push -u origin main          # repo must be PUBLIC

## B. Render (recommended: Docker + free Postgres)
1. render.com → sign in with GitHub → **New → Blueprint** → select the repo. It reads `render.yaml`.
2. When asked, set **SEED_PASSWORD** (12+ chars; this is the password of all five demo accounts). 
3. Wait for the build. Open `https://<name>.onrender.com/healthz` → `{"ok":true}`, then `/` for the app.
4. Put the URL and the demo credentials in README.md. Test as each role (README "Try it").
5. Free-plan notes: the service sleeps after inactivity (first request is slow, so open it before judging), and the
   disk is ephemeral: uploaded files vanish on restart (database rows stay; downloading then returns a clean
   "File unavailable" and is audited). Demo documents are re-created at every boot. Say this in your write-up.

## C. Other hosts
Anything that runs a Dockerfile works (Fly.io, Railway). Required env: `DATABASE_URL` (Postgres), `SEED_PASSWORD`,
`COOKIE_SECURE=1` (HTTPS only), `STORAGE_DIR`. Without `DATABASE_URL` it falls back to SQLite (fine locally, not for production).

## D. Optional hardening: a DB role that can never modify the audit table (tested on PostgreSQL 16)
    psql "$OWNER_URL" -v app_pw="'long-random'" -f sql/postgres_hardening.sql
    # then run the app with DATABASE_URL=<tv_app url>, RUN_MIGRATIONS=0, MIGRATE_DATABASE_URL=<owner url>
Render's managed Postgres may not allow creating roles on the free plan: if so, say in THREATS.md that DB-role
hardening was verified locally but not on the hosted database.

## E. After judging
Change SEED_PASSWORD, or delete the demo users from the admin console, and redeploy.
