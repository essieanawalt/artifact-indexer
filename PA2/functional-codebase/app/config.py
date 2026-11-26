# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Environment-driven settings with fail-closed validation (~100%)
# Human Modifications: None yet
# Verification: tests/conftest.py app_factory; tests/test_security.py::test_service_refuses_to_start_without_encryption_key
# Confidence: High
import os
from dataclasses import dataclass
from pathlib import Path

from app.crypto import parse_key

MIB = 1024 * 1024


def _int(name: str, default: int) -> int:
    value = int(os.getenv(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass
class Settings:
    database_url: str
    storage_dir: Path
    jwks_path: Path | None
    issuer: str | None
    audience: str | None
    encryption_key: bytes | str | None
    max_upload_bytes: int
    max_json_bytes: int
    max_zip_files: int
    max_zip_bytes: int
    max_concurrent_zips: int

    @classmethod
    def load(cls, **overrides) -> "Settings":
        """Explicit arguments (tests) win over environment variables; None means "use the environment"."""
        env = {
            "database_url": os.getenv("DATABASE_URL", "sqlite:///./baseline.db"),
            "storage_dir": Path(os.getenv("STORAGE_DIR", "./data/manuscripts")),
            "jwks_path": Path(os.environ["JWT_JWKS_PATH"]) if os.getenv("JWT_JWKS_PATH") else None,
            "issuer": os.getenv("JWT_ISSUER"),
            "audience": os.getenv("JWT_AUDIENCE"),
            "encryption_key": os.getenv("FIELD_ENCRYPTION_KEY"),
            "max_upload_bytes": _int("MAX_UPLOAD_BYTES", 10 * MIB),
            "max_json_bytes": _int("MAX_JSON_BYTES", 1 * MIB),
            "max_zip_files": _int("MAX_ZIP_FILES", 50),
            "max_zip_bytes": _int("MAX_ZIP_BYTES", 100 * MIB),
            "max_concurrent_zips": _int("MAX_CONCURRENT_ZIPS", 2),
        }
        for key, value in overrides.items():
            if value is not None:
                env[key] = Path(value) if key in ("storage_dir", "jwks_path") else value
        return cls(**env)

    def validate(self) -> bytes:
        """Fail closed at startup: no service without token verification settings and an encryption key."""
        missing = [name for name, value in (("JWT_JWKS_PATH", self.jwks_path), ("JWT_ISSUER", self.issuer),
                                             ("JWT_AUDIENCE", self.audience), ("FIELD_ENCRYPTION_KEY", self.encryption_key))
                   if not value]
        if missing:
            raise RuntimeError(f"missing required configuration: {', '.join(missing)}")
        try:
            return parse_key(self.encryption_key)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
