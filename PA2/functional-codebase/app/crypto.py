# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: AES-256-GCM field encryption for manuscript bytes (CWE-312) (~100%)
# Human Modifications: None yet
# Verification: tests/test_security.py (crypto round trip, tamper, key parsing, at-rest and on-return checks)
# Confidence: High
"""Application-layer encryption for manuscript file content.

Stored format: MAGIC (4 bytes) | nonce (12 random bytes) | AES-256-GCM ciphertext + 16-byte tag.
The artifact id is passed as associated data, so a stored blob cannot be moved to another
artifact without failing authentication.
"""
import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PAE1"
NONCE_BYTES = 12


class DecryptionError(Exception):
    """Ciphertext is malformed, was tampered with, or belongs to another key or artifact."""


def parse_key(value: str | bytes) -> bytes:
    """Accept the raw 32-byte key or its standard / URL-safe base64 form."""
    if isinstance(value, bytes):
        key = value
    else:
        text = value.strip()
        try:
            key = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_" if ("-" in text or "_" in text) else None,
                                   validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("FIELD_ENCRYPTION_KEY must be base64 of exactly 32 random bytes") from exc
    if len(key) != 32:
        raise ValueError("FIELD_ENCRYPTION_KEY must be base64 of exactly 32 random bytes")
    return key


class FieldCipher:
    def __init__(self, key: bytes):
        self._aead = AESGCM(parse_key(key))

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)  # fresh random nonce for every stored value
        return MAGIC + nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, blob: bytes, associated_data: bytes) -> bytes:
        if len(blob) < len(MAGIC) + NONCE_BYTES + 16 or not blob.startswith(MAGIC):
            raise DecryptionError("not an encrypted manuscript blob")
        nonce = blob[len(MAGIC):len(MAGIC) + NONCE_BYTES]
        try:
            return self._aead.decrypt(nonce, blob[len(MAGIC) + NONCE_BYTES:], associated_data)
        except InvalidTag as exc:
            raise DecryptionError("authentication failed") from exc
