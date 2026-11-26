# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Shared test fixtures: throwaway RSA key pair, test JWKS, token minting, in-process and Compose clients (~100%)
# Human Modifications: None yet
# Verification: Used by every test in tests/; full suite run in-process and against the Docker Compose stack
# Confidence: High
"""Shared fixtures.

Keys are generated in test code. When TEST_KEYS_DIR is set (Compose runs), the key pair is
written there once and reused so the container, which mounts that JWKS file read-only, and
pytest agree on the key. Run ``python -m tests.keys <dir>`` before ``docker compose up``.
"""
import os
import secrets
import time
from pathlib import Path

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from tests.keys import KID, load_or_create_keys

ISSUER = "http://localhost:9000"
AUDIENCE = "cs763-api"
BASE_URL = os.getenv("PA2_BASE_URL")
REMOTE = bool(BASE_URL)

# Limits shared with the service. In-process runs pass them to create_app; Compose runs must export
# the same variables to docker compose so service and tests agree.
LIMITS = {
    "max_upload_bytes": int(os.getenv("MAX_UPLOAD_BYTES", 64 * 1024)),
    "max_zip_files": int(os.getenv("MAX_ZIP_FILES", 5)),
    "max_zip_bytes": int(os.getenv("MAX_ZIP_BYTES", 128 * 1024)),
    "max_concurrent_zips": int(os.getenv("MAX_CONCURRENT_ZIPS", 2)),
}

USERS = {
    "alice": ["student"],          # creator and member of the sample project
    "bob": ["student"],            # authenticated, not a member
    "prof-one": ["faculty_instructor"],
    "prof-course": ["faculty_instructor"],   # mock directory: teaches CS763
    "prof-lab": ["faculty_instructor"],      # mock directory: runs lab-robotics
    "prof-other": ["faculty_instructor"],    # mock directory: unrelated course and lab
    "root": ["admin"],
    "norole": [],
    "guest": ["guest"],
}

local_only = pytest.mark.skipif(REMOTE, reason="needs in-process access to storage, database or app state")


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    directory = os.getenv("TEST_KEYS_DIR")
    return load_or_create_keys(Path(directory) if directory else tmp_path_factory.mktemp("jwks"))


def claims_for(subject, roles=None, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": subject,
              "roles": USERS.get(subject, []) if roles is None else roles,
              "iat": now, "exp": now + 300}
    for key, value in overrides.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims


@pytest.fixture(scope="session")
def mint(keys):
    def _mint(subject="alice", roles=None, *, kid=KID, algorithm="RS256", key=None, headers=None, **claims):
        return jwt.encode(claims_for(subject, roles, **claims), key or keys.private_key, algorithm=algorithm,
                          headers={"kid": kid, **(headers or {})})
    return _mint


@pytest.fixture(scope="session")
def auth(mint):
    def _auth(sub="alice", roles=None, **extra_headers):
        return {"Authorization": f"Bearer {mint(sub, roles)}", **extra_headers}
    return _auth


@pytest.fixture
def encryption_key():
    return secrets.token_bytes(32)


@pytest.fixture
def app_factory(tmp_path, keys, encryption_key):
    from app.main import create_app

    def _factory(**overrides):
        options = {"database_url": f"sqlite:///{tmp_path}/test.db", "storage_dir": tmp_path / "files",
                   "jwks_path": keys.jwks_path, "issuer": ISSUER, "audience": AUDIENCE,
                   "encryption_key": encryption_key, **LIMITS}
        options.update(overrides)
        return create_app(**options)
    return _factory


@pytest.fixture
def client(app_factory):
    if REMOTE:
        with httpx.Client(base_url=BASE_URL, follow_redirects=True, timeout=60) as c:
            yield c
    else:
        with TestClient(app_factory()) as c:
            yield c


@pytest.fixture
def payload():
    return {"title": "Research artifact catalog", "description": "Local robotics capstone",
            "members": [{"id": "alice", "role": "student"}, {"id": "prof-one", "role": "faculty"}],
            "units": [{"type": "lab", "id": "lab-robotics"}, {"type": "department", "id": "dept-cs"},
                      {"type": "course", "id": "CS763"}]}


@pytest.fixture
def project(client, payload, auth):
    response = client.post("/api/v1/projects", json=payload, headers=auth("alice"))
    assert response.status_code == 201, response.text
    p = response.json()
    yield p
    client.delete(f"/api/v1/projects/{p['id']}", headers=auth("root"))


def if_match(resource):
    return {"If-Match": f'"{resource["revision"]}"'}
