# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Tests for encryption at rest (CWE-312), input validation, PT1 stale updates, PT2 audit record, PT3 size limits (~100%)
# Human Modifications: None yet
# Verification: This file; local_only tests run in-process, the rest also against the Compose stack
# Confidence: High
import base64
import hashlib
import io
import os
import secrets
import zipfile

import pytest
from fastapi.testclient import TestClient

from tests.conftest import LIMITS, if_match, local_only

PDF = b"%PDF-1.4 TOP-SECRET-MANUSCRIPT-BODY"


def manuscripts(project):
    return f"/api/v1/projects/{project['id']}/artifacts/manuscripts"


def new_manuscript(client, project, auth, title="Draft"):
    r = client.post(manuscripts(project) + "/", json={"title": title}, headers=auth("alice"))
    assert r.status_code == 201, r.text
    return r.json()


def upload(client, project, auth, m, content=PDF, filename="paper.pdf", user="alice"):
    return client.post(f"{manuscripts(project)}/{m['id']}/file", files={"file": (filename, content, "application/pdf")},
                       headers=auth(user, **if_match(m)))


# --- CWE-312: encryption at rest and on return ----------------------------------------------------

def test_crypto_roundtrip_unique_nonce_and_tamper_detection():
    from app.crypto import DecryptionError, FieldCipher
    cipher = FieldCipher(secrets.token_bytes(32))
    a, b = cipher.encrypt(PDF, b"artifact-1"), cipher.encrypt(PDF, b"artifact-1")
    assert a != b and PDF not in a
    assert cipher.decrypt(a, b"artifact-1") == PDF
    with pytest.raises(DecryptionError):
        cipher.decrypt(a, b"artifact-2")       # ciphertext bound to its artifact
    tampered = bytearray(a)
    tampered[-1] ^= 1
    with pytest.raises(DecryptionError):
        cipher.decrypt(bytes(tampered), b"artifact-1")
    with pytest.raises(DecryptionError):
        FieldCipher(secrets.token_bytes(32)).decrypt(a, b"artifact-1")


@pytest.mark.parametrize("value", ["", "short", base64.b64encode(b"x" * 16).decode(), base64.b64encode(b"x" * 31).decode(),
                                   "replace-me", "!!!not base64!!!"])
def test_bad_encryption_keys_rejected(value):
    from app.crypto import parse_key
    with pytest.raises(ValueError):
        parse_key(value)


def test_encryption_key_parsing_accepts_base64_and_urlsafe():
    from app.crypto import parse_key
    raw = secrets.token_bytes(32)
    assert parse_key(base64.b64encode(raw).decode()) == raw
    assert parse_key(base64.urlsafe_b64encode(raw).decode()) == raw


@local_only
def test_service_refuses_to_start_without_encryption_key(app_factory, monkeypatch):
    monkeypatch.delenv("FIELD_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError):
        with TestClient(app_factory(encryption_key=None)):
            pass


@local_only
def test_manuscript_stored_encrypted_and_returned_decrypted(client, project, auth, tmp_path, encryption_key):
    from app.crypto import FieldCipher
    m = new_manuscript(client, project, auth)
    r = upload(client, project, auth, m)
    assert r.status_code == 200
    assert r.json()["file"]["sha256"] == hashlib.sha256(PDF).hexdigest()   # hash of plaintext
    stored_files = [p for p in (tmp_path / "files").rglob("*") if p.is_file()]
    assert len(stored_files) == 1
    blob = stored_files[0].read_bytes()
    assert PDF not in blob and b"TOP-SECRET" not in blob
    assert FieldCipher(encryption_key).decrypt(blob, m["id"].encode()) == PDF
    # The database holds no file bytes either.
    assert b"TOP-SECRET" not in (tmp_path / "test.db").read_bytes()
    assert client.get(f"{manuscripts(project)}/{m['id']}/file", headers=auth("alice")).content == PDF
    with zipfile.ZipFile(io.BytesIO(client.get(f"{manuscripts(project)}/download", headers=auth("alice")).content)) as z:
        assert z.read(f"{m['id']}/paper.pdf") == PDF


@local_only
def test_same_content_gets_different_ciphertext(client, project, auth, tmp_path):
    first, second = new_manuscript(client, project, auth), new_manuscript(client, project, auth)
    upload(client, project, auth, first)
    upload(client, project, auth, second)
    blobs = {p.read_bytes() for p in (tmp_path / "files").rglob("*") if p.is_file()}
    assert len(blobs) == 2


@local_only
def test_tampered_stored_file_is_not_served(client, project, auth, tmp_path):
    m = new_manuscript(client, project, auth)
    upload(client, project, auth, m)
    stored = next(p for p in (tmp_path / "files").rglob("*") if p.is_file())
    data = bytearray(stored.read_bytes())
    data[-5] ^= 0xFF
    stored.write_bytes(bytes(data))
    r = client.get(f"{manuscripts(project)}/{m['id']}/file", headers=auth("alice"))
    assert r.status_code == 500
    assert b"TOP-SECRET" not in r.content


@local_only
def test_legacy_plaintext_files_are_encrypted_at_startup(app_factory, tmp_path, auth, payload, encryption_key):
    from sqlalchemy import update
    from sqlalchemy.orm import Session
    from app.crypto import FieldCipher
    from app.models import Artifact
    app = app_factory()
    with TestClient(app) as c:
        p = c.post("/api/v1/projects", json=payload, headers=auth("alice")).json()
        m = c.post(manuscripts(p) + "/", json={"title": "Legacy"}, headers=auth("alice")).json()
        upload(c, p, auth, m)
    stored = next(p for p in (tmp_path / "files").rglob("*") if p.is_file())
    stored.write_bytes(PDF)  # simulate a file written by the pre-hardening service
    with Session(app.state.engine) as s:
        s.execute(update(Artifact).where(Artifact.id == m["id"]).values(file_encrypted=False))
        s.commit()
    with TestClient(app_factory()) as c:
        files = [p for p in (tmp_path / "files").rglob("*") if p.is_file()]
        assert len(files) == 1   # plaintext copy removed
        assert PDF not in files[0].read_bytes()
        assert FieldCipher(encryption_key).decrypt(files[0].read_bytes(), m["id"].encode()) == PDF
        assert c.get(f"{manuscripts(p)}/{m['id']}/file", headers=auth("alice")).content == PDF


# --- Input validation on every write endpoint ------------------------------------------------------

@pytest.mark.parametrize("change", [
    {"title": ""}, {"title": "x" * 301}, {"title": 5}, {"description": "x" * 10001}, {"members": []},
    {"members": [{"id": "bad id with spaces", "role": "student"}]}, {"members": [{"id": "ok"}]},
    {"members": [{"id": "ok", "role": "student", "admin": True}]}, {"members": "alice"},
    {"units": []}, {"units": [{"type": "planet", "id": "x"}]}, {"units": [{"type": "lab", "id": ""}]},
    {"unexpected": "field"},
])
def test_project_create_and_update_validate_input(client, project, payload, auth, change):
    assert client.post("/api/v1/projects", json={**payload, **change}, headers=auth("alice")).status_code == 422
    url = f"/api/v1/projects/{project['id']}"
    assert client.put(url, json={**payload, **change}, headers=auth("alice", **if_match(project))).status_code == 422


def test_non_json_bodies_rejected(client, project, auth):
    headers = auth("alice", **{"Content-Type": "application/json"})
    assert client.post("/api/v1/projects", content=b"{not json", headers=headers).status_code == 422
    assert client.post("/api/v1/projects", json=["a", "list"], headers=auth("alice")).status_code == 422


@pytest.mark.parametrize("kind,metadata", [
    ("repositories", {}), ("repositories", {"repo_url": "javascript:alert(1)"}), ("repositories", {"repo_url": "file:///etc/passwd"}),
    ("repositories", {"repo_url": "https://example.org/r", "total_commit_count": -1}),
    ("repositories", {"repo_url": "https://example.org/r", "total_commit_count": "many"}),
    ("repositories", {"repo_url": "https://example.org/r", "latest_commit_timestamp": "yesterday"}),
    ("repositories", {"repo_url": "https://example.org/r", "owner": "root"}),
    ("videos", {"video_url": "ftp://example.org/v"}), ("videos", {"video_url": "https://example.org/v", "duration": -5}),
    ("videos", {"video_url": "https://example.org/v", "thumbnail_url": "data:text/html,<script>"}),
    ("manuscripts", {}), ("manuscripts", {"title": ""}), ("manuscripts", {"title": "t", "year": 3000}),
    ("manuscripts", {"title": "t", "authors": "Alice"}), ("manuscripts", {"title": "t", "authors": [""]}),
    ("manuscripts", {"title": "x" * 501}),
])
def test_artifact_metadata_validated_on_create_and_update(client, project, auth, kind, metadata):
    base = f"/api/v1/projects/{project['id']}/artifacts/{kind}"
    assert client.post(base + "/", json=metadata, headers=auth("alice")).status_code == 422
    valid = {"repositories": {"repo_url": "https://example.org/r"}, "videos": {"video_url": "https://example.org/v"},
             "manuscripts": {"title": "ok"}}[kind]
    a = client.post(base + "/", json=valid, headers=auth("alice")).json()
    assert client.put(f"{base}/{a['id']}", json=metadata, headers=auth("alice", **if_match(a))).status_code == 422


def test_unknown_artifact_type_rejected(client, project, auth):
    r = client.post(f"/api/v1/projects/{project['id']}/artifacts/spreadsheets/", json={"title": "x"}, headers=auth("alice"))
    assert r.status_code == 422


def test_empty_upload_rejected(client, project, auth):
    m = new_manuscript(client, project, auth)
    assert upload(client, project, auth, m, content=b"").status_code == 422


@pytest.mark.parametrize("filename,expected", [("../../etc/passwd", "passwd"), ("..", "manuscript.bin"),
                                               ("my paper (v2).pdf", "my_paper__v2_.pdf"),
                                               ('evil"\r\nX-Injected: 1.pdf', None)])
def test_uploaded_filename_is_sanitised(client, project, auth, filename, expected):
    import re
    m = new_manuscript(client, project, auth)
    r = upload(client, project, auth, m, filename=filename)
    assert r.status_code == 200, r.text
    stored = r.json()["file"]["filename"]
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,255}", stored)
    if expected:
        assert stored == expected
    d = client.get(f"{manuscripts(project)}/{m['id']}/file", headers=auth("alice"))
    assert "x-injected" not in {k.lower() for k in d.headers}


@pytest.mark.parametrize("query", [{"keyword": "x" * 201}, {"created_after": "not-a-date"}, {"created_before": "2026-13-45"},
                                   {"artifact_type": "spreadsheets"}])
def test_search_parameters_validated(client, auth, query):
    assert client.get("/api/v1/projects", params=query, headers=auth("alice")).status_code == 422


def test_search_wildcards_are_literal(client, project, auth):
    found = client.get("/api/v1/projects", params={"keyword": "%"}, headers=auth("alice")).json()
    assert project["id"] not in {p["id"] for p in found}


# --- PT1: stale updates fail -----------------------------------------------------------------------

def test_project_update_requires_if_match(client, project, payload, auth):
    url = f"/api/v1/projects/{project['id']}"
    assert client.put(url, json=payload, headers=auth("alice")).status_code == 428
    assert client.put(url, json=payload, headers=auth("alice", **{"If-Match": "garbage"})).status_code == 412


def test_stale_project_update_fails_and_keeps_newer_change(client, project, payload, auth):
    url = f"/api/v1/projects/{project['id']}"
    first = client.put(url, json={**payload, "title": "Newer change"}, headers=auth("alice", **if_match(project)))
    assert first.status_code == 200
    stale = client.put(url, json={**payload, "title": "Stale overwrite"}, headers=auth("prof-one", **if_match(project)))
    assert stale.status_code == 412
    assert client.get(url, headers=auth("alice")).json()["title"] == "Newer change"


def test_read_returns_etag_matching_revision(client, project, auth):
    r = client.get(f"/api/v1/projects/{project['id']}", headers=auth("alice"))
    assert r.headers["etag"] == f'"{r.json()["revision"]}"'


def test_stale_artifact_update_fails(client, project, auth):
    base = f"/api/v1/projects/{project['id']}/artifacts/videos"
    a = client.post(base + "/", json={"video_url": "https://example.org/v"}, headers=auth("alice")).json()
    assert client.put(f"{base}/{a['id']}", json={"video_url": "https://example.org/v2"}, headers=auth("alice")).status_code == 428
    assert client.put(f"{base}/{a['id']}", json={"video_url": "https://example.org/v2"}, headers=auth("alice", **if_match(a))).status_code == 200
    stale = client.put(f"{base}/{a['id']}", json={"video_url": "https://example.org/v3"}, headers=auth("alice", **if_match(a)))
    assert stale.status_code == 412
    assert client.get(f"{base}/{a['id']}", headers=auth("alice")).json()["metadata"]["video_url"] == "https://example.org/v2"


def test_stale_manuscript_upload_fails(client, project, auth):
    m = new_manuscript(client, project, auth)
    assert upload(client, project, auth, m).status_code == 200
    assert upload(client, project, auth, m, content=b"older client").status_code == 412
    assert client.get(f"{manuscripts(project)}/{m['id']}/file", headers=auth("alice")).content == PDF


def test_stale_if_match_on_delete_fails(client, project, payload, auth):
    url = f"/api/v1/projects/{project['id']}"
    client.put(url, json=payload, headers=auth("alice", **if_match(project)))
    assert client.delete(url, headers=auth("alice", **if_match(project))).status_code == 412
    assert client.get(url, headers=auth("alice")).status_code == 200


@local_only
def test_concurrent_writers_cannot_both_commit(client, project):
    from sqlalchemy.orm import Session
    from sqlalchemy.orm.exc import StaleDataError
    from app.models import Project
    engine = client.app.state.engine
    with Session(engine) as one, Session(engine) as two:
        a, b = one.get(Project, project["id"]), two.get(Project, project["id"])
        a.title, b.title = "writer one", "writer two"
        one.commit()
        with pytest.raises(StaleDataError):
            two.commit()


# --- PT2: change and download record --------------------------------------------------------------

def events(client, auth, **params):
    r = client.get("/api/v1/audit-events", params=params, headers=auth("root"))
    assert r.status_code == 200, r.text
    return r.json()


def test_changes_deletes_and_downloads_are_recorded_and_survive_deletion(client, payload, auth):
    p = client.post("/api/v1/projects", json=payload, headers=auth("alice")).json()
    url = f"/api/v1/projects/{p['id']}"
    p = client.put(url, json={**payload, "title": "Changed"}, headers=auth("alice", **if_match(p))).json()
    m = new_manuscript(client, p, auth)
    m = upload(client, p, auth, m).json()
    client.get(f"{manuscripts(p)}/{m['id']}/file", headers=auth("prof-course"))
    client.get(f"{manuscripts(p)}/download", headers=auth("alice"))
    client.get(f"{manuscripts(p)}/{m['id']}/file", headers=auth("bob"))                     # refused
    client.put(url, json={**payload, "title": "stale"}, headers=auth("alice", **{"If-Match": '"1"'}))  # stale
    client.delete(f"{manuscripts(p)}/{m['id']}/file", headers=auth("alice"))
    client.delete(f"{manuscripts(p)}/{m['id']}", headers=auth("alice"))
    assert client.delete(url, headers=auth("alice")).status_code == 204

    recorded = events(client, auth, project_id=p["id"])
    summary = [(e["actor"], e["action"], e["outcome"]) for e in recorded]
    for expected in [("alice", "project.create", "success"), ("alice", "project.update", "success"),
                     ("alice", "artifact.create", "success"), ("alice", "manuscript.upload", "success"),
                     ("prof-course", "manuscript.download", "success"), ("alice", "manuscript.download_zip", "success"),
                     ("bob", "manuscript.download", "denied"), ("alice", "project.update", "conflict"),
                     ("alice", "manuscript.delete_file", "success"), ("alice", "artifact.delete", "success"),
                     ("alice", "project.delete", "success")]:
        assert expected in summary, (expected, summary)
    for event in recorded:
        assert event["at"] and event["project_id"] == p["id"]
    by_artifact = events(client, auth, artifact_id=m["id"])
    assert {e["action"] for e in by_artifact} >= {"manuscript.upload", "manuscript.download", "artifact.delete"}


def test_denied_change_attempts_are_recorded(client, project, payload, auth):
    client.put(f"/api/v1/projects/{project['id']}", json=payload, headers=auth("bob", **if_match(project)))
    client.delete(f"/api/v1/projects/{project['id']}", headers=auth("bob"))
    summary = {(e["actor"], e["action"], e["outcome"], e["status_code"]) for e in events(client, auth, project_id=project["id"])}
    assert ("bob", "project.update", "denied", 404) in summary
    assert ("bob", "project.delete", "denied", 404) in summary


def test_audit_query_is_validated(client, auth):
    assert client.get("/api/v1/audit-events", params={"limit": 0}, headers=auth("root")).status_code == 422
    assert client.get("/api/v1/audit-events", params={"limit": 100000}, headers=auth("root")).status_code == 422


# --- PT3: upload size and zip download limits ------------------------------------------------------

def test_upload_over_limit_rejected_and_not_stored(client, project, auth):
    m = new_manuscript(client, project, auth)
    too_big = os.urandom(LIMITS["max_upload_bytes"] + 1)
    assert upload(client, project, auth, m, content=too_big).status_code == 413
    assert client.get(f"{manuscripts(project)}/{m['id']}", headers=auth("alice")).json()["file"] is None


def test_upload_at_limit_accepted(client, project, auth):
    m = new_manuscript(client, project, auth)
    content = os.urandom(LIMITS["max_upload_bytes"])
    assert upload(client, project, auth, m, content=content).status_code == 200
    assert client.get(f"{manuscripts(project)}/{m['id']}/file", headers=auth("alice")).content == content


def test_oversized_json_body_rejected(client, auth, payload):
    body = {**payload, "description": "x" * (2 * 1024 * 1024)}
    assert client.post("/api/v1/projects", json=body, headers=auth("alice")).status_code == 413


@pytest.mark.parametrize("path_kind", ["json", "upload"])
def test_streamed_body_without_content_length_is_limited(client, project, auth, path_kind):
    if path_kind == "json":
        head, tail = b'{"title": "', b'"}'
        url, content_type = "/api/v1/projects", "application/json"
    else:
        head = (b'--xyz\r\nContent-Disposition: form-data; name="file"; filename="big.pdf"\r\n'
                b"Content-Type: application/pdf\r\n\r\n")
        tail = b"\r\n--xyz--\r\n"
        m = new_manuscript(client, project, auth)
        url, content_type = f"{manuscripts(project)}/{m['id']}/file", "multipart/form-data; boundary=xyz"

    def chunks():   # a generator body is sent chunked, with no Content-Length
        yield head
        for _ in range(40):
            yield b"x" * 65536
        yield tail
    r = client.post(url, content=chunks(), headers=auth("alice", **{"Content-Type": content_type, "If-Match": '"1"'}))
    assert r.status_code == 413


def test_zip_refused_when_too_many_files(client, project, auth):
    for i in range(LIMITS["max_zip_files"] + 1):
        upload(client, project, auth, new_manuscript(client, project, auth, f"m{i}"), content=b"small")
    r = client.get(f"{manuscripts(project)}/download", headers=auth("alice"))
    assert r.status_code == 422
    assert "individually" in r.json()["detail"]


def test_zip_refused_when_total_size_too_large(client, project, auth):
    per_file = LIMITS["max_upload_bytes"]
    count = LIMITS["max_zip_bytes"] // per_file + 1
    assert count <= LIMITS["max_zip_files"], "test limits must let the byte cap trigger first"
    for i in range(count):
        upload(client, project, auth, new_manuscript(client, project, auth, f"m{i}"), content=os.urandom(per_file))
    assert client.get(f"{manuscripts(project)}/download", headers=auth("alice")).status_code == 422


@local_only
def test_zip_concurrency_limited(client, project, auth):
    upload(client, project, auth, new_manuscript(client, project, auth), content=b"a")
    slots = client.app.state.zip_slots
    held = [slots.acquire(blocking=False) for _ in range(LIMITS["max_concurrent_zips"])]
    try:
        assert all(held)
        r = client.get(f"{manuscripts(project)}/download", headers=auth("alice"))
        assert r.status_code == 429
        assert "retry-after" in {k.lower() for k in r.headers}
    finally:
        for _ in held:
            slots.release()
    assert client.get(f"{manuscripts(project)}/download", headers=auth("alice")).status_code == 200
