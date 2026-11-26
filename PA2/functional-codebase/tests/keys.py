# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Throwaway test RSA key pair and test JWKS writer (~100%)
# Human Modifications: None yet
# Verification: Exercised by tests/test_auth.py and every authenticated test; used to prepare the Compose test run
# Confidence: High
"""Create or load a throwaway RS256 key pair and its JWKS file for tests only.

Usage before a Compose test run:  python -m tests.keys /some/scratch/dir
Then start Compose with JWKS_HOST_PATH=/some/scratch/dir/jwks.json and run pytest with
TEST_KEYS_DIR=/some/scratch/dir. Never point this at real key material.
"""
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KID = "test-key-1"


@dataclass(frozen=True)
class TestKeys:
    __test__ = False  # not a pytest test class
    private_key: rsa.RSAPrivateKey
    jwks_path: Path

    @property
    def public_pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def new_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(private_key, kid=KID) -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    return {**jwk, "kid": kid, "alg": "RS256", "use": "sig"}


def load_or_create_keys(directory: Path) -> TestKeys:
    directory.mkdir(parents=True, exist_ok=True)
    pem_path, jwks_path = directory / "test-private.pem", directory / "jwks.json"
    if pem_path.exists() and jwks_path.exists():
        private_key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    else:
        private_key = new_private_key()
        pem_path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
        pem_path.chmod(0o600)
        jwks_path.write_text(json.dumps({"keys": [public_jwk(private_key)]}, indent=2))
        jwks_path.chmod(0o644)  # the container user must be able to read the mounted public JWKS
    return TestKeys(private_key, jwks_path)


if __name__ == "__main__":
    keys = load_or_create_keys(Path(sys.argv[1]))
    print(keys.jwks_path)
