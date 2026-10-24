"""One user must never reach another user's documents, through ANY document route."""
import pytest
from .conftest import uid

SECRET = b"TOPSECRET-CONTENT"

def setup_doc(who):
    d = who["alice"].upload().json()["id"]
    return d

def calls(doc):  # every route that takes a document id: (method, url, kwargs, needed action)
    return [("GET", f"/documents/{doc}", {}, "read"),
            ("GET", f"/documents/{doc}/download", {}, "download"),
            ("PATCH", f"/documents/{doc}", {"json": {"name": "x.pdf"}}, "edit"),
            ("DELETE", f"/documents/{doc}", {}, "delete"),
            ("GET", f"/documents/{doc}/grants", {}, "share"),
            ("PUT", f"/documents/{doc}/grants", {"json": {"email": "eve@t.test", "level": "edit"}}, "share"),
            ("DELETE", f"/documents/{doc}/grants/{uid('vic@t.test')}", {}, "share"),
            ("GET", f"/documents/{doc}/suggestions", {}, "share"),
            ("GET", f"/documents/{doc}/activity", {}, "share"),
            ("POST", f"/documents/{doc}/suggestions/reject", {"json": {"email": "eve@t.test"}}, "share")]

@pytest.mark.parametrize("actor", ["vic", "bob", "admin"])  # never granted (admin included!)
def test_never_granted_gets_nothing(who, actor):
    doc = setup_doc(who)
    for m, u, kw, _ in calls(doc):
        r = who[actor].req(m, u, **kw)
        assert r.status_code == 404, (actor, m, u, r.status_code)
        assert SECRET not in r.content
    assert who["alice"].req("GET", f"/documents/{doc}").status_code == 200  # nothing was altered/deleted

def test_read_grant_allows_only_read_and_download(who):
    doc = setup_doc(who)
    assert who["alice"].req("PUT", f"/documents/{doc}/grants", json={"email": "vic@t.test", "level": "read"}).status_code == 200
    allowed = {"read", "download"}
    for m, u, kw, need in calls(doc)[:5]:
        r = who["vic"].req(m, u, **kw)
        if need in allowed:
            assert r.status_code == 200, (m, u)
        else:
            assert r.status_code == 403, (m, u, r.status_code)
    assert who["vic"].req("GET", f"/documents/{doc}/download").content.startswith(b"%PDF")

def test_edit_grant_can_edit_but_not_share_or_delete(who):
    doc = setup_doc(who)
    who["alice"].req("PUT", f"/documents/{doc}/grants", json={"email": "vic@t.test", "level": "edit"})
    assert who["vic"].req("PATCH", f"/documents/{doc}", json={"name": "renamed.pdf"}).status_code == 200
    assert who["vic"].req("DELETE", f"/documents/{doc}").status_code == 403
    assert who["vic"].req("PUT", f"/documents/{doc}/grants", json={"email": "eve@t.test", "level": "read"}).status_code == 403
    assert who["eve"].req("GET", f"/documents/{doc}").status_code == 404

def test_admin_sees_metadata_not_content(who):
    doc = setup_doc(who)
    r = who["admin"].req("GET", "/admin/documents")
    assert r.status_code == 200 and any(d["id"] == doc for d in r.json())
    assert who["admin"].req("GET", f"/documents/{doc}/download").status_code == 404
    assert who["admin"].req("GET", "/documents").json() == []  # not in the admin's own search either

def test_deleted_doc_unreachable_even_for_owner_and_grants_closed(who):
    doc = setup_doc(who)
    who["alice"].req("PUT", f"/documents/{doc}/grants", json={"email": "vic@t.test", "level": "read"})
    assert who["alice"].req("DELETE", f"/documents/{doc}").status_code == 200
    for actor in ("alice", "vic"):
        assert who[actor].req("GET", f"/documents/{doc}/download").status_code == 404
    assert who["alice"].req("GET", "/documents").json() == []

def test_unknown_and_malformed_ids_look_the_same(who):
    for bad in ("nope", "0" * 32, "../../etc/passwd", "ABCDEF" * 6):
        assert who["vic"].req("GET", f"/documents/{bad}").status_code == 404
    # NUL bytes: rejected cleanly (400), never a 500 (PostgreSQL would crash on them without validation)
    assert who["vic"].req("GET", "/documents/%00").status_code == 400
    assert who["vic"].req("GET", "/documents", params={"q": "a%00b"}).status_code in (200, 400)

def test_nul_bytes_in_json_do_not_cause_server_errors(who):
    from fastapi.testclient import TestClient
    from app import main
    r = TestClient(main.app).post("/auth/login", json={"email": "a\u0000b@t.test", "password": "x"})
    assert r.status_code in (400, 401)

def test_unauthenticated_gets_nothing(who):
    from fastapi.testclient import TestClient
    from app import main
    doc = setup_doc(who)
    anon = TestClient(main.app)
    for m, u, kw, _ in calls(doc):
        assert anon.request(m, u, **kw).status_code == 401
