# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Original PA2 functional tests (OpenAI Codex) updated to authenticate with tokens and send If-Match (~40%)
# Human Modifications: None yet
# Verification: This file; runs in-process and against the Compose stack
# Confidence: High
import hashlib
import io
from uuid import UUID
import zipfile

import pytest

from tests.conftest import if_match


def test_health(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_project_lifecycle(client, project, payload, auth):
    pid = project["id"]
    assert str(UUID(pid)) == pid
    assert project["revision"] == 1
    assert project["members"] == payload["members"]   # creator alice is already listed
    assert project["units"] == payload["units"]
    assert project["created_at"] and project["updated_at"]
    assert client.get(f"/api/v1/projects/{pid}", headers=auth("alice")).json() == project
    updated = {**payload, "title": "Revised project"}
    response = client.put(f"/api/v1/projects/{pid}", json=updated, headers=auth("alice", **if_match(project)))
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 2
    assert response.json()["title"] == "Revised project"
    assert response.headers["etag"] == '"2"'
    assert client.delete(f"/api/v1/projects/{pid}", headers=auth("alice")).status_code == 204
    assert client.get(f"/api/v1/projects/{pid}", headers=auth("alice")).status_code == 404


def test_creator_added_as_member(client, payload, auth):
    body = {**payload, "members": [{"id": "carol", "role": "student"}]}
    created = client.post("/api/v1/projects", json=body, headers=auth("bob")).json()
    assert created["members"] == [{"id": "carol", "role": "student"}, {"id": "bob", "role": "creator"}]
    client.delete(f"/api/v1/projects/{created['id']}", headers=auth("bob"))


@pytest.mark.parametrize("kind,metadata", [
    ("repositories", {"repo_url": "https://example.org/lab/robot", "target_branch": "main", "primary_tech_stack": "Python", "total_commit_count": 17, "latest_commit_timestamp": "2026-11-01T00:00:00Z"}),
    ("videos", {"video_url": "https://example.org/video", "thumbnail_url": "https://example.org/image.png", "duration": 120, "description": "Demo"}),
    ("manuscripts", {"title": "A paper", "abstract": "A robot", "authors": ["Alice"], "keywords": ["robotics"], "year": 2026, "publisher": "Local demo"}),
])
def test_artifact_lifecycle(client, project, kind, metadata, auth):
    prefix = f"/api/v1/projects/{project['id']}/artifacts/{kind}"
    response = client.post(prefix + "/", json=metadata, headers=auth("alice"))
    assert response.status_code == 201, response.text
    a = response.json()
    UUID(a["id"])
    assert a["metadata"] == metadata
    assert a["revision"] == 1
    assert client.get(prefix + "/", headers=auth("bob")).json() == [a]
    assert a in client.get(f"/api/v1/projects/{project['id']}/artifacts", headers=auth("bob")).json()
    assert client.get(prefix + "/" + a["id"], headers=auth("bob")).json() == a
    revised = {**metadata, "description": "Updated metadata"}
    response = client.put(prefix + "/" + a["id"], json=revised, headers=auth("alice", **if_match(a)))
    assert response.status_code == 200, response.text
    assert response.json()["metadata"] == revised
    assert response.json()["revision"] == 2
    assert client.delete(prefix + "/" + a["id"], headers=auth("alice")).status_code == 204
    assert client.get(prefix + "/" + a["id"], headers=auth("alice")).status_code == 404


def test_manuscript_upload_download_hash_zip_delete(client, project, auth):
    base = f"/api/v1/projects/{project['id']}/artifacts/manuscripts"
    ids = []
    for number in range(2):
        a = client.post(base + "/", json={"title": f"Manuscript {number}"}, headers=auth("alice")).json()
        ids.append(a["id"])
        content = f"%PDF-1.4 course fixture {number}".encode()
        response = client.post(f"{base}/{a['id']}/file", files={"file": ("paper.pdf", content, "application/pdf")},
                               headers=auth("alice", **if_match(a)))
        assert response.status_code == 200, response.text
        assert response.json()["file"]["sha256"] == hashlib.sha256(content).hexdigest()
        assert response.json()["file"]["size"] == len(content)
        assert client.get(f"{base}/{a['id']}/file", headers=auth("alice")).content == content
    archive = client.get(base + "/download", headers=auth("alice"))
    assert archive.status_code == 200
    with zipfile.ZipFile(io.BytesIO(archive.content)) as z:
        assert len(z.namelist()) == 2
        for number, aid in enumerate(ids):
            assert z.read(f"{aid}/paper.pdf") == f"%PDF-1.4 course fixture {number}".encode()
    assert client.delete(f"{base}/{ids[0]}/file", headers=auth("alice")).status_code == 204
    assert client.get(f"{base}/{ids[0]}/file", headers=auth("alice")).status_code == 404
    assert client.get(f"{base}/{ids[0]}", headers=auth("alice")).json()["file"] is None


@pytest.mark.parametrize("query", [
    {"keyword": "robotics"}, {"dept_id": "dept-cs", "lab_id": "lab-robotics", "course_id": "CS763"},
    {"created_after": "2020-01-01", "created_before": "2100-01-01"},
    {"keyword": "research", "artifact_type": "repositories", "course_id": "CS763"},
])
def test_search_filters(client, project, query, auth):
    client.post(f"/api/v1/projects/{project['id']}/artifacts/repositories/", json={"repo_url": "https://example.org/repo"},
                headers=auth("alice"))
    response = client.get("/api/v1/projects", params=query, headers=auth("bob"))
    assert response.status_code == 200
    assert project["id"] in {p["id"] for p in response.json()}
    other = client.get("/api/v1/projects", params={"lab_id": "nonexistent"}, headers=auth("bob")).json()
    assert project["id"] not in {p["id"] for p in other}


def test_project_delete_removes_artifacts(client, project, auth):
    pid = project["id"]
    a = client.post(f"/api/v1/projects/{pid}/artifacts/videos/", json={"video_url": "https://example.org/demo"},
                    headers=auth("alice")).json()
    assert client.delete(f"/api/v1/projects/{pid}", headers=auth("alice")).status_code == 204
    assert client.get(f"/api/v1/projects/{pid}/artifacts/videos/{a['id']}", headers=auth("alice")).status_code == 404
