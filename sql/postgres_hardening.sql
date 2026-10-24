-- Run ONCE as the table owner, AFTER the schema exists (python -m app.seed with the owner URL).
--   psql "$OWNER_URL" -v app_pw="'choose-a-long-random-password'" -f sql/postgres_hardening.sql
-- Then run the app with DATABASE_URL = the tv_app URL and RUN_MIGRATIONS=0 (MIGRATE_DATABASE_URL = owner URL for seeding).
-- Effect: even a fully compromised app process cannot UPDATE/DELETE/TRUNCATE the audit table;
-- the append-only triggers (app/db.py) are the second layer, the hash chain (/admin/audit/verify) the third.
CREATE ROLE tv_app LOGIN PASSWORD :app_pw;
GRANT USAGE ON SCHEMA public TO tv_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, grants TO tv_app;
GRANT SELECT, INSERT ON audit TO tv_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tv_app;
