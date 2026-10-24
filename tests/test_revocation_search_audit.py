import pytest
from sqlalchemy import text
from app import audit
from app.db import SessionLocal, engine
from .conftest import uid, Client, PW, drop_audit_triggers

def share(who, doc, to="vic@t.test", level="read"):
    assert who["alice"].req("PUT", f"/documents/{doc}/grants", json={"email": to, "level": level}).status_code == 200

def test_revoke_is_immediate_for_an_already_open_session(who):
    doc = who["alice"].upload().json()["id"]; share(who, doc)
    assert who["vic"].req("GET", f"/documents/{doc}/download").status_code == 200
    assert who["alice"].req("DELETE", f"/documents/{doc}/grants/{uid('vic@t.test')}").status_code == 200
    assert who["vic"].req("GET", f"/documents/{doc}/download").status_code == 404   # same session, next request
    assert who["vic"].req("GET", f"/documents/{doc}").status_code == 404
    assert who["vic"].req("GET", "/documents").json() == []

def test_regrant_after_revoke_works_and_old_state_does_not_linger(who):
    doc = who["alice"].upload().json()["id"]; share(who, doc, level="edit")
    who["alice"].req("DELETE", f"/documents/{doc}/grants/{uid('vic@t.test')}")
    share(who, doc, level="read")
    assert who["vic"].req("PATCH", f"/documents/{doc}", json={"name": "a.pdf"}).status_code == 403  # not edit anymore

def test_disabled_user_session_dies_immediately(who):
    doc = who["alice"].upload().json()["id"]; share(who, doc)
    assert who["admin"].req("POST", f"/admin/users/{uid('vic@t.test')}/disable").status_code == 200
    assert who["vic"].req("GET", f"/documents/{doc}/download").status_code == 401
    r = Client.__new__(Client)
    from fastapi.testclient import TestClient
    from app import main
    assert TestClient(main.app).post("/auth/login", json={"email": "vic@t.test", "password": PW}).status_code == 401

def test_search_never_leaks_other_users_documents(who):
    who["alice"].upload(name="alice-salary.pdf", category="hr")
    b = who["bob"].upload(name="bob-contract.pdf", category="legal").json()["id"]
    assert [d["name"] for d in who["bob"].req("GET", "/documents", params={"q": "salary"}).json()] == []
    assert who["vic"].req("GET", "/documents", params={"q": "contract"}).json() == []
    assert who["vic"].req("GET", "/documents", params={"owner": "alice@t.test"}).json() == []
    assert who["vic"].req("GET", "/documents", params={"category": "hr"}).json() == []
    assert who["bob"].req("PUT", f"/documents/{b}/grants", json={"email": "vic@t.test", "level": "read"}).status_code == 200
    assert [d["name"] for d in who["vic"].req("GET", "/documents", params={"q": "contract"}).json()] == ["bob-contract.pdf"]

def test_search_wildcards_are_literal(who):
    who["alice"].upload(name="a.pdf")
    assert who["alice"].req("GET", "/documents", params={"q": "%"}).json() == []

def test_viewer_cannot_upload_or_use_admin(who):
    assert who["vic"].upload().status_code == 403
    assert who["admin"].upload().status_code == 403
    for u in ("/admin/documents", "/admin/audit", "/admin/audit/verify", "/admin/flags"):
        assert who["alice"].req("GET", u).status_code == 403
        assert who["vic"].req("GET", u).status_code == 403
    assert who["alice"].req("POST", "/admin/users", json={"email": "x@t.test", "password": "x" * 14, "role": "admin"}).status_code == 403

def test_mass_assignment_rejected(who):
    doc = who["alice"].upload().json()["id"]
    r = who["alice"].req("PATCH", f"/documents/{doc}", json={"owner_id": uid("eve@t.test")})
    assert r.status_code == 422
    assert who["bob"].req("PATCH", f"/documents/{doc}", json={"name": "z.pdf"}).status_code == 404

def test_csrf_required(who):
    doc = who["alice"].upload().json()["id"]
    assert who["alice"].c.delete(f"/documents/{doc}").status_code == 403  # no header
    assert who["alice"].c.delete(f"/documents/{doc}", headers={"X-CSRF-Token": "wrong"}).status_code == 403

@pytest.mark.parametrize("name,body,code", [
    ("evil.exe", b"MZ....", 415), ("fake.pdf", b"<html>x</html>", 415), ("empty.pdf", b"", 415),
    ("noext", b"%PDF-1", 415), ("x.svg", b"<svg onload=alert(1)>", 415), ("ok.txt", b"hello", 201),
    ("bin.txt", b"a\x00b", 415)])
def test_upload_validation(who, name, body, code):
    assert who["alice"].upload(name=name, body=body).status_code == code

def test_filename_is_sanitised_and_storage_key_is_random(who):
    r = who["alice"].upload(name="../../etc/pass\r\nwd.txt", body=b"hi").json()
    assert "/" not in r["name"] and "\n" not in r["name"] and ".." not in r["name"].split(".")[0]

def test_oversize_rejected(who, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "MAX_BYTES", 100)
    assert who["alice"].upload(name="big.txt", body=b"a" * 500).status_code == 413

def test_download_headers(who):
    doc = who["alice"].upload().json()["id"]
    r = who["alice"].req("GET", f"/documents/{doc}/download")
    assert r.headers["content-disposition"].startswith("attachment") and r.headers["x-content-type-options"] == "nosniff"

def test_login_is_uniform_and_rate_limited(who):
    from fastapi.testclient import TestClient
    from app import main
    c = TestClient(main.app)
    a = c.post("/auth/login", json={"email": "nobody@t.test", "password": "x"})
    b = c.post("/auth/login", json={"email": "vic@t.test", "password": "wrong"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    for _ in range(6):
        r = c.post("/auth/login", json={"email": "vic@t.test", "password": "wrong"})
    assert r.status_code == 429

def test_denials_are_audited_with_reason(who):
    doc = who["alice"].upload().json()["id"]
    who["vic"].req("GET", f"/documents/{doc}/download")
    rows = who["admin"].req("GET", "/admin/audit", params={"outcome": "denied"}).json()
    assert any(r["actor_id"] == uid("vic@t.test") and r["target"] == doc and r["reason"] == "no_grant" for r in rows)

def test_audit_records_every_event_type_and_chain_verifies(who):
    doc = who["alice"].upload().json()["id"]; share(who, doc)
    who["vic"].req("GET", f"/documents/{doc}/download")
    who["alice"].req("PATCH", f"/documents/{doc}", json={"name": "n.pdf"})
    who["alice"].req("DELETE", f"/documents/{doc}/grants/{uid('vic@t.test')}")
    who["alice"].req("DELETE", f"/documents/{doc}")
    acts = {r["action"] for r in who["admin"].req("GET", "/admin/audit").json() if r["outcome"] == "ok"}
    assert {"upload", "download", "update", "grant", "revoke", "delete", "login"} <= acts
    assert who["admin"].req("GET", "/admin/audit/verify").json()["ok"] is True

def test_audit_is_append_only_at_db_level(who):
    who["alice"].upload()
    for sql in ("UPDATE audit SET actor_id=999", "DELETE FROM audit"):
        with pytest.raises(Exception, match="append-only"):
            with engine.begin() as c:
                c.execute(text(sql))

def test_tampering_is_detected_even_if_triggers_are_bypassed(who):
    who["alice"].upload(); who["vic"].req("GET", "/documents")
    with engine.begin() as c:   # simulate an attacker with DB superuser: drop trigger, edit a row
        drop_audit_triggers(c)
        c.execute(text("UPDATE audit SET actor_id=42 WHERE id=2"))
    v = who["admin"].req("GET", "/admin/audit/verify").json()
    assert v["ok"] is False and v["first_bad_id"] == 2

def test_deleting_a_middle_row_is_detected(who):
    who["alice"].upload(); who["alice"].upload()
    with engine.begin() as c:
        drop_audit_triggers(c); c.execute(text("DELETE FROM audit WHERE id=3"))
    assert who["admin"].req("GET", "/admin/audit/verify").json()["ok"] is False

def test_log_forging_is_neutralised(who):
    from fastapi.testclient import TestClient
    from app import main
    TestClient(main.app).post("/auth/login", json={"email": "x@t.test\n2099 FAKE admin login ok", "password": "x"})
    rows = who["admin"].req("GET", "/admin/audit", params={"action": "login"}).json()
    assert all("\n" not in r["detail"] for r in rows)

def test_flags_show_attempts_after_revoke(who):
    doc = who["alice"].upload().json()["id"]; share(who, doc)
    who["alice"].req("DELETE", f"/documents/{doc}/grants/{uid('vic@t.test')}")
    who["vic"].req("GET", f"/documents/{doc}/download")
    assert any(f["type"] == "access_attempt_after_revoke" for f in who["admin"].req("GET", "/admin/flags").json())

def test_inactive_user_with_surviving_session_is_rejected(who):
    """Defence in depth: even if a session row survives, active=False must block the next request."""
    from sqlalchemy import update
    from app.db import User
    with SessionLocal() as db:
        db.execute(update(User).where(User.email == "vic@t.test").values(active=False)); db.commit()
    assert who["vic"].req("GET", "/documents").status_code == 401
