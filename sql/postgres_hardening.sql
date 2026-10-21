-- Run ONCE as the DB owner after the app has created tables (python -m app.seed).
-- The app connects as tv_app, which can never UPDATE/DELETE/TRUNCATE the audit table.
-- (UNTESTED on a live Postgres in the 2-day build; the triggers in app/db.py are the second layer.)
CREATE ROLE tv_app LOGIN PASSWORD 'CHANGE_ME';
GRANT CONNECT ON DATABASE current_database() TO tv_app;  -- replace with your DB name if this errors
GRANT USAGE ON SCHEMA public TO tv_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, grants TO tv_app;
GRANT SELECT, INSERT ON audit TO tv_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tv_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit FROM tv_app;
