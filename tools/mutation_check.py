"""Proves the tests test something: removes the authorisation check, expects the suite to FAIL.
Usage: python tools/mutation_check.py"""
import pathlib, subprocess, sys

MUTATIONS = [
    ("app/authz.py", "if not decision.allowed:  # AUTHZ-CHECK", "if False and not decision.allowed:  # AUTHZ-CHECK"),
    ("app/authz.py", "Document.deleted_at.is_(None), or_(Document.owner_id == user.id, has_grant)",
                     "Document.deleted_at.is_(None)"),                       # search no longer filtered
    ("app/authz.py", "Grant.revoked_at.is_(None)))\n    if g is None:", "True))\n    if g is None:"),  # revoked grants still count
    ("app/main.py", "if user is None or not user.active:  # re-checked on EVERY request", "if user is None:"),
]

def run():
    return subprocess.run([sys.executable, "-m", "pytest", "-x", "-q"], capture_output=True, text=True).returncode

def main():
    if run() != 0:
        sys.exit("baseline suite must pass first")
    bad = 0
    for path, old, new in MUTATIONS:
        f = pathlib.Path(path); src = f.read_text()
        if old not in src:
            print(f"SKIP (pattern not found): {old[:50]}"); bad += 1; continue
        f.write_text(src.replace(old, new, 1))
        try:
            killed = run() != 0
        finally:
            f.write_text(src)
        print(("KILLED  " if killed else "SURVIVED"), "-", path, "::", old[:60].replace("\n", " "))
        bad += 0 if killed else 1
    sys.exit(1 if bad else 0)

main()
