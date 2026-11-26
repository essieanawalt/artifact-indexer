# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Row-level authorization policy for projects, artifacts and manuscript downloads (CWE-862) (~100%)
# Human Modifications: None yet
# Verification: tests/test_authz.py; tests/test_auth.py::test_another_users_valid_token_is_accepted_but_refused_this_users_records
# Confidence: High
"""Row-level authorization, checked against the stored project record on every request.

404 / 403 rule: a record the caller may not act on raises NotAccessible (404, the same body as a
missing record). A caller whose role is not allowed an action at all gets 403 (see security.py).
"""
from fastapi import HTTPException

from app.directory import faculty_units
from app.security import Principal

NOT_FOUND = {"project": "Project not found", "artifact": "Artifact not found", "file": "File not found"}


class NotAccessible(HTTPException):
    """Raised when the record exists but the caller may not access it. Indistinguishable from not found."""

    def __init__(self, what: str = "project"):
        super().__init__(404, NOT_FOUND[what])


def is_member(principal: Principal, project) -> bool:
    return any(isinstance(m, dict) and m.get("id") == principal.sub for m in project.members or [])


def can_read(principal: Principal, project) -> bool:
    return True   # any authenticated caller with a known role may read profiles and artifact metadata


def can_modify(principal: Principal, project) -> bool:
    """Update or delete the project; add, update or delete its artifacts and manuscript files."""
    return principal.is_admin or is_member(principal, project)


def can_download(principal: Principal, project) -> bool:
    """Download manuscript files: members, faculty of the project's course or lab (mock directory), admin."""
    if principal.is_admin or is_member(principal, project):
        return True
    if "faculty_instructor" not in principal.roles:
        return False
    project_units = {(u.get("type"), u.get("id")) for u in project.units or [] if isinstance(u, dict)}
    taught = {unit for unit in faculty_units(principal.sub) if unit[0] in ("course", "lab")}
    return bool(project_units & taught)


def ensure(allowed: bool, what: str = "project") -> None:
    if not allowed:
        raise NotAccessible(what)
