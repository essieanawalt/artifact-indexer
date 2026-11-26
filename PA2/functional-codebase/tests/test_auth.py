# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: JWT verification test cases (CWE-306) and identity-source tests (~100%)
# Human Modifications: None yet
# Verification: This file; runs in-process and against the Compose stack
# Confidence: High
import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest

from tests.conftest import AUDIENCE, claims_for, local_only
from tests.keys import KID, new_private_key

PROTECTED = "/api/v1/projects"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def segment(obj) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode())


def status_with(client, token):
    return client.get(PROTECTED, headers={"Authorization": f"Bearer {token}"}).status_code


def test_health_stays_public(client):
    assert client.get("/healthz").json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_no_other_public_endpoints(client, path):
    assert client.get(path).status_code == 404


def test_valid_token_accepted(client, mint):
    assert status_with(client, mint("alice")) == 200


def test_missing_token_is_401_with_challenge(client):
    response = client.get(PROTECTED)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/v1/projects"), ("GET", "/api/v1/projects/x"), ("PUT", "/api/v1/projects/x"),
    ("DELETE", "/api/v1/projects/x"), ("GET", "/api/v1/projects/x/artifacts"),
    ("GET", "/api/v1/projects/x/artifacts/manuscripts/download"), ("POST", "/api/v1/projects/x/artifacts/videos/"),
    ("GET", "/api/v1/projects/x/artifacts/videos/"), ("GET", "/api/v1/projects/x/artifacts/videos/y"),
    ("PUT", "/api/v1/projects/x/artifacts/videos/y"), ("DELETE", "/api/v1/projects/x/artifacts/videos/y"),
    ("POST", "/api/v1/projects/x/artifacts/manuscripts/y/file"), ("GET", "/api/v1/projects/x/artifacts/manuscripts/y/file"),
    ("DELETE", "/api/v1/projects/x/artifacts/manuscripts/y/file"), ("GET", "/api/v1/audit-events"),
])
def test_every_api_endpoint_requires_a_token(client, method, path):
    assert client.request(method, path).status_code == 401


def test_expired_token_rejected(client, mint):
    now = int(time.time())
    assert status_with(client, mint("alice", iat=now - 7200, exp=now - 3600)) == 401


def test_expired_by_two_minutes_rejected(client, mint):
    assert status_with(client, mint("alice", exp=int(time.time()) - 120)) == 401


def test_expired_within_clock_skew_accepted(client, mint):
    assert status_with(client, mint("alice", exp=int(time.time()) - 30)) == 200


def test_not_yet_valid_rejected(client, mint):
    assert status_with(client, mint("alice", nbf=int(time.time()) + 300)) == 401


def test_nbf_within_clock_skew_accepted(client, mint):
    assert status_with(client, mint("alice", nbf=int(time.time()) + 30)) == 200


def test_missing_exp_rejected(client, mint):
    assert status_with(client, mint("alice", exp=None)) == 401


def test_missing_sub_rejected(client, mint):
    assert status_with(client, mint("alice", sub=None)) == 401


@pytest.mark.parametrize("roles", ["admin", {"admin": True}, [1, 2]])
def test_roles_claim_must_be_array_of_strings(client, mint, roles):
    assert status_with(client, mint("alice", roles=roles)) == 401


def test_wrong_issuer_rejected(client, mint):
    assert status_with(client, mint("alice", iss="http://evil.example:9000")) == 401


def test_missing_issuer_rejected(client, mint):
    assert status_with(client, mint("alice", iss=None)) == 401


def test_wrong_audience_rejected(client, mint):
    assert status_with(client, mint("alice", aud="some-other-api")) == 401


def test_missing_audience_rejected(client, mint):
    assert status_with(client, mint("alice", aud=None)) == 401


def test_audience_array_including_ours_accepted(client, mint):
    assert status_with(client, mint("alice", aud=["other-api", AUDIENCE])) == 200


def test_audience_array_without_ours_rejected(client, mint):
    assert status_with(client, mint("alice", aud=["other-api", "third-api"])) == 401


@pytest.mark.parametrize("alg", ["none", "None", "NONE"])
def test_alg_none_rejected(client, alg):
    token = f"{segment({'alg': alg, 'typ': 'JWT', 'kid': KID})}.{segment(claims_for('root'))}."
    assert status_with(client, token) == 401


def test_hs256_signed_with_public_key_rejected(client, keys):
    signing_input = f"{segment({'alg': 'HS256', 'typ': 'JWT', 'kid': KID})}.{segment(claims_for('root'))}"
    signature = hmac.new(keys.public_pem, signing_input.encode(), hashlib.sha256).digest()
    assert status_with(client, f"{signing_input}.{b64url(signature)}") == 401


@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256"])
def test_algorithm_not_on_allowlist_rejected(client, mint, alg):
    assert status_with(client, mint("alice", algorithm=alg)) == 401


def test_bad_signature_rejected(client, mint):
    assert status_with(client, mint("alice", key=new_private_key())) == 401


def test_payload_changed_after_signing_rejected(client, mint):
    header, _, signature = mint("bob").split(".")
    forged = segment(claims_for("root"))
    assert status_with(client, f"{header}.{forged}.{signature}") == 401


def test_signature_stripped_rejected(client, mint):
    header, payload, _ = mint("alice").split(".")
    assert status_with(client, f"{header}.{payload}.") == 401


def test_unknown_kid_rejected(client, mint):
    assert status_with(client, mint("alice", kid="not-in-jwks")) == 401


def test_missing_kid_rejected(client, keys):
    token = jwt.encode(claims_for("alice"), keys.private_key, algorithm="RS256")
    assert status_with(client, token) == 401


def test_jku_header_pointing_elsewhere_rejected(client, mint):
    attacker = new_private_key()
    for kid in ("attacker-key", KID):
        token = mint("root", kid=kid, key=attacker, headers={"jku": "http://127.0.0.1:9/attacker-jwks.json"})
        assert status_with(client, token) == 401


def test_embedded_jwk_and_x5u_headers_rejected(client, mint):
    from tests.keys import public_jwk
    attacker = new_private_key()
    token = mint("root", kid=KID, key=attacker, headers={"jwk": public_jwk(attacker, KID), "x5u": "http://127.0.0.1:9/cert"})
    assert status_with(client, token) == 401


def test_key_location_headers_are_ignored_not_trusted(client, mint):
    # Signed by the real key: verification uses only the JWKS file, so the foreign jku is irrelevant.
    token = mint("alice", headers={"jku": "http://127.0.0.1:9/attacker-jwks.json"})
    assert status_with(client, token) == 200


@pytest.mark.parametrize("token", ["garbage", "a.b.c", "a.b", "....", "eyJhbGciOiJSUzI1NiJ9.e30",
                                   f"{b64url(b'not json')}.{b64url(b'{}')}.{b64url(b'sig')}"])
def test_malformed_tokens_rejected(client, token):
    assert status_with(client, token) == 401


@pytest.mark.parametrize("value", ["Basic YWxpY2U6cGFzcw==", "Token abc", "Bearer", "bearer"])
def test_wrong_authorization_scheme_rejected(client, value):
    assert client.get(PROTECTED, headers={"Authorization": value}).status_code == 401


def test_another_users_valid_token_is_accepted_but_refused_this_users_records(client, auth, project):
    base = f"/api/v1/projects/{project['id']}"
    assert client.get(base, headers=auth("bob")).status_code == 200   # accepted: any caller may read profiles
    body = {k: project[k] for k in ("title", "description", "members", "units")}
    assert client.put(base, json=body, headers=auth("bob", **{"If-Match": '"1"'})).status_code == 404
    assert client.delete(base, headers=auth("bob")).status_code == 404
    m = client.post(base + "/artifacts/manuscripts/", json={"title": "Paper"}, headers=auth("alice")).json()
    up = client.post(f"{base}/artifacts/manuscripts/{m['id']}/file", files={"file": ("p.pdf", b"%PDF secret", "application/pdf")},
                     headers=auth("alice", **{"If-Match": f'"{m["revision"]}"'}))
    assert up.status_code == 200, up.text
    assert client.get(f"{base}/artifacts/manuscripts/{m['id']}/file", headers=auth("bob")).status_code == 404
    assert client.get(f"{base}/artifacts/manuscripts/download", headers=auth("bob")).status_code == 404


def test_identity_never_taken_from_query_body_or_other_headers(client, auth, payload):
    headers = auth("bob", **{"X-User": "root", "X-Forwarded-User": "root", "X-Roles": "admin", "X-Sub": "alice"})
    response = client.post("/api/v1/projects?sub=root&roles=admin", json=payload, headers=headers)
    assert response.status_code == 201
    created = response.json()
    assert {"id": "bob", "role": "creator"} in created["members"]
    # Still bob: cannot use admin-only endpoint despite every spoofing attempt.
    assert client.get("/api/v1/audit-events?sub=root&roles=admin", headers=headers).status_code == 403
    for field in ("owner", "created_by", "sub", "roles"):
        assert client.post("/api/v1/projects", json={**payload, field: "root"}, headers=auth("bob")).status_code == 422
    client.delete(f"/api/v1/projects/{created['id']}", headers=auth("bob"))


@local_only
def test_jwks_file_is_the_only_key_source(app_factory, tmp_path, mint):
    from fastapi.testclient import TestClient
    empty = tmp_path / "empty-jwks.json"
    empty.write_text(json.dumps({"keys": []}))
    with TestClient(app_factory(jwks_path=empty)) as c:
        assert status_with(c, mint("alice")) == 401
    missing = tmp_path / "does-not-exist.json"
    with TestClient(app_factory(jwks_path=missing)) as c:
        assert status_with(c, mint("alice")) == 401
        assert c.get("/healthz").status_code == 200
