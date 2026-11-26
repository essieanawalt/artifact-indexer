# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Local RS256 JWT verification against a JWKS file and the authentication dependency (CWE-306) (~100%)
# Human Modifications: None yet
# Verification: tests/test_auth.py (all token cases), and every authenticated test
# Confidence: High
"""Authentication: JSON Web Tokens verified locally against the JWKS file at JWT_JWKS_PATH.

No identity provider and no network calls. Only RS256 keys from that file are used; any key or
key location in the token header (jku, jwk, x5u, x5c) is ignored.
"""
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

import jwt
from fastapi import HTTPException, Request
from jwt.algorithms import RSAAlgorithm

ALLOWED_ALGORITHMS = ["RS256"]
CLOCK_SKEW_SECONDS = 60
MIN_RSA_BITS = 2048
KNOWN_ROLES = frozenset({"admin", "faculty_instructor", "student"})

log = logging.getLogger("indexer.auth")


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str]

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles


class InvalidToken(Exception):
    pass


class JwksKeyStore:
    """Public keys from the JWKS file, keyed by kid. Reloaded when the file changes (key rotation)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._stamp = None
        self._keys: dict[str, object] = {}

    def get(self, kid: str):
        with self._lock:
            try:
                stat = self.path.stat()
                stamp = (stat.st_mtime_ns, stat.st_size)
                if stamp != self._stamp:
                    self._keys = self._parse(json.loads(self.path.read_text()))
                    self._stamp = stamp
            except (OSError, ValueError) as exc:
                log.error("JWKS file %s unreadable: %s; rejecting all tokens", self.path, exc)
                self._keys, self._stamp = {}, None
            return self._keys.get(kid)

    @staticmethod
    def _parse(document) -> dict:
        keys, seen = {}, set()
        for jwk in document.get("keys", []) if isinstance(document, dict) else []:
            kid = jwk.get("kid") if isinstance(jwk, dict) else None
            if not isinstance(kid, str) or not kid:
                continue
            if kid in seen:          # ambiguous kid: refuse to choose between keys
                keys.pop(kid, None)
                continue
            seen.add(kid)
            if jwk.get("kty") != "RSA" or jwk.get("alg", "RS256") != "RS256" or jwk.get("use", "sig") != "sig":
                continue
            public = {k: jwk[k] for k in ("kty", "n", "e") if k in jwk}   # never load private parts
            try:
                key = RSAAlgorithm.from_jwk(public)
            except (jwt.InvalidKeyError, ValueError, TypeError, KeyError):
                continue
            if key.key_size >= MIN_RSA_BITS:
                keys[kid] = key
        return keys


def verify_token(token: str, keys: JwksKeyStore, issuer: str, audience: str) -> Principal:
    """Signature check, algorithm allowlist and claim validation. Raises InvalidToken on any failure."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise InvalidToken("malformed token") from exc
    # Choose the algorithm and key ourselves: header alg must be on the allowlist, key comes only from the JWKS file.
    if header.get("alg") not in ALLOWED_ALGORITHMS:
        raise InvalidToken("algorithm not allowed")
    kid = header.get("kid")
    key = keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        raise InvalidToken("unknown kid")
    try:
        claims = jwt.decode(
            token, key=key, algorithms=ALLOWED_ALGORITHMS, issuer=issuer, audience=audience, leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iss", "aud", "sub"], "verify_signature": True, "verify_exp": True,
                     "verify_nbf": True, "verify_iss": True, "verify_aud": True, "strict_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc
    sub, roles = claims.get("sub"), claims.get("roles", [])
    if not isinstance(sub, str) or not sub or len(sub) > 128:
        raise InvalidToken("invalid sub")
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise InvalidToken("roles must be a JSON array of strings")
    return Principal(sub=sub, roles=frozenset(roles))


def _unauthorized(detail="Not authenticated"):
    return HTTPException(401, detail, headers={"WWW-Authenticate": 'Bearer realm="cs763-api"'})


def current_principal(request: Request) -> Principal:
    """FastAPI dependency: identity comes only from a verified Bearer token, never from body, query or other headers."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized()
    state = request.app.state
    try:
        principal = verify_token(token.strip(), state.jwks, state.settings.issuer, state.settings.audience)
    except InvalidToken as exc:
        log.info("token rejected: %s", exc)
        raise _unauthorized("Invalid token") from None
    if not principal.roles & KNOWN_ROLES:
        raise HTTPException(403, "Role not permitted")
    return principal


def require_admin(principal: Principal) -> None:
    if not principal.is_admin:
        raise HTTPException(403, "Role not permitted")
