# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Row-level authorization and role refusal tests (CWE-862) (~100%)
# Human Modifications: None yet
# Verification: This file; runs in-process and against the Compose stack
# Confidence: High
import pytest

from tests.conftest import if_match

PDF = b"%PDF-1.4 confidential draft"


@pytest.fixture
def manuscript(client, project, auth):
    base = f"/api/v1/projects/{project['id']}/artifacts/manuscripts"
    m = client.post(base + "/", json={"title": "Draft"}, headers=auth("alice")).json()
    r = client.post(f"{base}/{m['id']}/file", files={"file": ("draft.pdf", PDF, "application/pdf")},
                    headers=auth("alice", **if_match(m)))
    assert r.status_code == 200, r.text
    return r.json()


def project_body(project, **changes):
    return {**{k: project[k] for k in ("title", "description", "members", "units")}, **changes}


# --- reads are open to any authenticated caller -------------------------------------------------

@pytest.mark.parametrize("user", ["alice", "bob", "prof-other", "root"])
def test_any_authenticated_role_reads_profiles_metadata_and_search(client, project, manuscript, auth, user):
    pid = project["id"]
    assert client.get(f"/api/v1/projects/{pid}", headers=auth(user)).status_code == 200
    assert client.get(f"/api/v1/projects/{pid}/artifacts", headers=auth(user)).status_code == 200
    assert client.get(f"/api/v1/projects/{pid}/artifacts/manuscripts/{manuscript['id']}", headers=auth(user)).status_code == 200
    assert pid in {p["id"] for p in client.get("/api/v1/projects", headers=auth(user)).json()}


# --- writes: members or admin only; others get 404 ---------------------------------------------

def test_non_member_cannot_update_or_delete_project(client, project, auth):
    url = f"/api/v1/projects/{project['id']}"
    for user in ("bob", "prof-course", "prof-other"):
        assert client.put(url, json=project_body(project, title="hijack"), headers=auth(user, **if_match(project))).status_code == 404
        assert client.delete(url, headers=auth(user)).status_code == 404
    assert client.get(url, headers=auth("alice")).json()["title"] == project["title"]


def test_listed_member_with_any_role_may_update(client, project, auth):
    url = f"/api/v1/projects/{project['id']}"
    r = client.put(url, json=project_body(project, title="By prof-one"), headers=auth("prof-one", **if_match(project)))
    assert r.status_code == 200, r.text


def test_admin_may_update_and_delete_any_project(client, project, auth):
    url = f"/api/v1/projects/{project['id']}"
    r = client.put(url, json=project_body(project, title="By admin"), headers=auth("root", **if_match(project)))
    assert r.status_code == 200
    assert client.delete(url, headers=auth("root")).status_code == 204


def test_non_member_cannot_add_update_or_delete_artifacts(client, project, manuscript, auth):
    base = f"/api/v1/projects/{project['id']}/artifacts"
    assert client.post(base + "/videos/", json={"video_url": "https://example.org/v"}, headers=auth("bob")).status_code == 404
    mid = manuscript["id"]
    assert client.put(f"{base}/manuscripts/{mid}", json={"title": "x"}, headers=auth("bob", **if_match(manuscript))).status_code == 404
    assert client.post(f"{base}/manuscripts/{mid}/file", files={"file": ("x.pdf", b"x", "application/pdf")},
                       headers=auth("bob", **if_match(manuscript))).status_code == 404
    assert client.delete(f"{base}/manuscripts/{mid}/file", headers=auth("bob")).status_code == 404
    assert client.delete(f"{base}/manuscripts/{mid}", headers=auth("bob")).status_code == 404
    # nothing changed
    assert client.get(f"{base}/manuscripts/{mid}/file", headers=auth("alice")).content == PDF


def test_removed_member_loses_write_access(client, project, auth):
    url = f"/api/v1/projects/{project['id']}"
    body = project_body(project, members=[{"id": "alice", "role": "student"}])
    updated = client.put(url, json=body, headers=auth("alice", **if_match(project))).json()
    assert client.put(url, json=project_body(updated, title="x"), headers=auth("prof-one", **if_match(updated))).status_code == 404


# --- manuscript downloads -------------------------------------------------------------------

@pytest.mark.parametrize("user", ["alice", "prof-one", "prof-course", "prof-lab", "root"])
def test_download_allowed_for_members_unit_faculty_and_admin(client, project, manuscript, auth, user):
    base = f"/api/v1/projects/{project['id']}/artifacts/manuscripts"
    assert client.get(f"{base}/{manuscript['id']}/file", headers=auth(user)).content == PDF
    assert client.get(f"{base}/download", headers=auth(user)).status_code == 200


@pytest.mark.parametrize("user,roles", [
    ("bob", None),                         # student, not a member
    ("prof-other", None),                  # faculty of another course and lab
    ("prof-course", ["student"]),          # in the mock directory but without the faculty role
])
def test_download_refused_with_404(client, project, manuscript, auth, user, roles):
    base = f"/api/v1/projects/{project['id']}/artifacts/manuscripts"
    assert client.get(f"{base}/{manuscript['id']}/file", headers=auth(user, roles)).status_code == 404
    assert client.get(f"{base}/download", headers=auth(user, roles)).status_code == 404


def test_faculty_association_only_via_course_or_lab_not_department(client, payload, auth):
    body = {**payload, "units": [{"type": "department", "id": "dept-cs"}]}
    p = client.post("/api/v1/projects", json=body, headers=auth("alice")).json()
    base = f"/api/v1/projects/{p['id']}/artifacts/manuscripts"
    m = client.post(base + "/", json={"title": "x"}, headers=auth("alice")).json()
    client.post(f"{base}/{m['id']}/file", files={"file": ("a.pdf", b"abc", "application/pdf")}, headers=auth("alice", **if_match(m)))
    assert client.get(f"{base}/{m['id']}/file", headers=auth("prof-course")).status_code == 404
    client.delete(f"/api/v1/projects/{p['id']}", headers=auth("alice"))


def test_refused_and_missing_records_look_the_same(client, project, manuscript, auth):
    base = f"/api/v1/projects/{project['id']}/artifacts/manuscripts"
    refused = client.get(f"{base}/{manuscript['id']}/file", headers=auth("bob"))
    missing = client.get(f"{base}/00000000-0000-4000-8000-000000000000/file", headers=auth("bob"))
    assert refused.status_code == missing.status_code == 404
    assert refused.json() == missing.json()
    put_refused = client.put(f"/api/v1/projects/{project['id']}", json=project_body(project), headers=auth("bob", **if_match(project)))
    put_missing = client.put("/api/v1/projects/00000000-0000-4000-8000-000000000000", json=project_body(project),
                             headers=auth("bob", **if_match(project)))
    assert put_refused.status_code == put_missing.status_code == 404
    assert put_refused.json() == put_missing.json()


# --- role refusals: 403 -------------------------------------------------------------------

@pytest.mark.parametrize("user", ["norole", "guest"])
def test_token_without_a_known_role_gets_403(client, project, auth, payload, user):
    assert client.get("/api/v1/projects", headers=auth(user)).status_code == 403
    assert client.get(f"/api/v1/projects/{project['id']}", headers=auth(user)).status_code == 403
    assert client.post("/api/v1/projects", json=payload, headers=auth(user)).status_code == 403


@pytest.mark.parametrize("user", ["alice", "prof-one"])
def test_audit_log_is_admin_only(client, auth, user):
    assert client.get("/api/v1/audit-events", headers=auth(user)).status_code == 403
    assert client.get("/api/v1/audit-events", headers=auth("root")).status_code == 200


def test_member_listed_in_body_cannot_smuggle_admin_role(client, payload, auth):
    body = {**payload, "members": [{"id": "bob", "role": "admin"}]}
    p = client.post("/api/v1/projects", json=body, headers=auth("alice")).json()
    assert client.get("/api/v1/audit-events", headers=auth("bob")).status_code == 403
    client.delete(f"/api/v1/projects/{p['id']}", headers=auth("alice"))
