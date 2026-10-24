"""Meta-tests: a route nobody thought about must not silently exist, and Document queries live in one module."""
import pathlib, re
from fastapi.routing import APIRoute
from app import main

PUBLIC = {("POST", "/auth/login"), ("GET", "/healthz"), ("GET", "/")}

def _deps(dep):
    for d in dep.dependencies:
        yield d.call
        yield from _deps(d)

def test_every_route_is_authenticated_or_explicitly_public():
    for r in main.app.routes:
        if not isinstance(r, APIRoute):
            continue
        for m in r.methods - {"HEAD", "OPTIONS"}:
            if (m, r.path) in PUBLIC:
                continue
            assert main.current_user in set(_deps(r.dependant)) or any(
                getattr(c, "__qualname__", "").startswith("require_role") for c in _deps(r.dependant)), (m, r.path)

def test_document_table_is_only_queried_in_authz_module():
    pat = re.compile(r"select\(\s*Document|db\.get\(\s*Document|\.query\(\s*Document|FROM documents", re.I)
    for f in pathlib.Path("app").glob("*.py"):
        if f.name in ("authz.py", "db.py"):
            continue
        assert not pat.search(f.read_text()), f"{f} queries Document directly; use app/authz.py"

def test_no_debug_docs_exposed_by_default(who=None):
    assert main.app.docs_url is None and main.app.openapi_url is None

def test_api_md_documents_every_route():
    """If a route is added without being documented (and its audience stated), this fails."""
    doc = pathlib.Path("API.md").read_text()
    for r in main.app.routes:
        if isinstance(r, APIRoute):
            norm = re.sub(r"\{[^}]+\}", "{", r.path)
            assert any(norm == re.sub(r"\{[^}]+\}", "{", p) for p in re.findall(r"`(?:GET |POST |PUT |PATCH |DELETE )?(/[^` ]*)`", doc)), f"{r.path} missing from API.md"
