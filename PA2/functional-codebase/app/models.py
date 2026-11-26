# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: ORM models moved from main.py (OpenAI Codex original) plus optimistic-lock versioning, encryption flag, audit table and startup migration (~70%)
# Human Modifications: None yet
# Verification: tests/test_security.py (PT1 concurrency, PT2 audit, legacy encryption migration); whole suite
# Confidence: High
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return datetime.now(timezone.utc).isoformat()


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    members: Mapped[list] = mapped_column(JSON)
    units: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    revision: Mapped[int] = mapped_column(Integer)
    # PT1: UPDATE/DELETE ... WHERE revision = <loaded revision>; a concurrent change raises StaleDataError.
    __mapper_args__ = {"version_id_col": revision}


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)   # SHA-256 of the plaintext
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)      # plaintext size
    file_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("FALSE"))
    revision: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    __mapper_args__ = {"version_id_col": revision}


class AuditEvent(Base):
    """PT2: append-only record of changes, deletions and downloads. No foreign keys, so it outlives the records."""
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[str] = mapped_column(String(40), index=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(40))
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(20))
    status_code: Mapped[int] = mapped_column(Integer)


def migrate(engine) -> None:
    """Create tables and add columns introduced by the hardening to databases created by the PA2 baseline."""
    Base.metadata.create_all(engine)
    columns = {c["name"] for c in inspect(engine).get_columns("artifacts")}
    with engine.begin() as connection:
        if "revision" not in columns:
            connection.execute(text("ALTER TABLE artifacts ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"))
        if "file_encrypted" not in columns:
            connection.execute(text("ALTER TABLE artifacts ADD COLUMN file_encrypted BOOLEAN NOT NULL DEFAULT FALSE"))
