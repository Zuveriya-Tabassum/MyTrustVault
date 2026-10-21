from sqlalchemy import select
from app.db import SessionLocal, Grant
from .conftest import uid

def give(who, doc, email, **kw):
    return who["alice"].req("PUT", f"/documents/{doc}/grants", json={"email": email, "level": "read", **kw})

def test_suggestions_are_advice_only_and_never_create_a_grant(who):
    d1 = who["alice"].upload(category="hr").json()["id"]; give(who, d1, "vic@t.test")
    d2 = who["alice"].upload(category="hr").json()["id"]
    s = who["alice"].req("GET", f"/documents/{d2}/suggestions").json()
    assert [x["email"] for x in s] == ["vic@t.test"]
    with SessionLocal() as db:   # asking for / rejecting a suggestion changed nothing
        assert db.scalars(select(Grant).where(Grant.doc_id == d2)).all() == []
    who["alice"].req("POST", f"/documents/{d2}/suggestions/reject", json={"email": "vic@t.test"})
    assert who["vic"].req("GET", f"/documents/{d2}").status_code == 404

def test_suggestion_and_decision_are_both_audited(who):
    d1 = who["alice"].upload(category="hr").json()["id"]; give(who, d1, "vic@t.test")
    d2 = who["alice"].upload(category="hr").json()["id"]
    who["alice"].req("GET", f"/documents/{d2}/suggestions")
    assert give(who, d2, "vic@t.test", from_suggestion=True).status_code == 200
    who["alice"].req("POST", f"/documents/{d2}/suggestions/reject", json={"email": "eve@t.test"})
    rows = who["admin"].req("GET", "/admin/audit").json()
    acts = [r["action"] for r in rows]
    assert "ai_suggest" in acts and "ai_reject" in acts
    assert any(r["action"] == "grant" and '"from_suggestion":true' in r["detail"] for r in rows)

def test_suggestions_only_use_metadata_from_own_documents(who):
    b = who["bob"].upload(category="hr").json()["id"]
    who["bob"].req("PUT", f"/documents/{b}/grants", json={"email": "eve@t.test", "level": "read"})
    d = who["alice"].upload(category="hr").json()["id"]
    assert who["alice"].req("GET", f"/documents/{d}/suggestions").json() == []   # Bob's sharing habits don't leak

def test_ui_is_served_with_strict_csp_and_no_inline_script(who):
    from fastapi.testclient import TestClient
    from app import main
    c = TestClient(main.app)
    r = c.get("/")
    assert r.status_code == 200 and "<script>" not in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert c.get("/static/app.js").status_code == 200
    assert "innerHTML" not in c.get("/static/app.js").text.replace("never innerHTML", "")

def test_static_mount_cannot_reach_storage_or_db(who):
    from fastapi.testclient import TestClient
    from app import main
    c = TestClient(main.app)
    for p in ("/static/../trustvault.db", "/static/..%2f..%2fapp/main.py", "/storage/x"):
        assert c.get(p).status_code == 404

def test_me_returns_csrf_for_session_resume(who):
    assert who["vic"].c.get("/me").json()["csrf"] == who["vic"].csrf
