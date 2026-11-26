# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Strict request schemas for projects and the three artifact kinds (~90%; ProjectInput shape from the OpenAI Codex original)
# Human Modifications: None yet
# Verification: tests/test_security.py input validation tests; tests/test_api.py functional payloads
# Confidence: High
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictInt

ArtifactType = Literal["manuscripts", "videos", "repositories"]

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")]
ShortText = Annotated[str, Field(min_length=1, max_length=300)]
LongText = Annotated[str, Field(max_length=10_000)]


def _http_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("must be an http or https URL")
    return value


def _timestamp(value: str) -> str:
    datetime.fromisoformat(value.replace("Z", "+00:00"))   # raises ValueError if not ISO 8601
    return value


HttpUrl = Annotated[str, Field(max_length=2048), AfterValidator(_http_url)]
Timestamp = Annotated[str, Field(max_length=40), AfterValidator(_timestamp)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Member(Strict):
    id: Identifier
    role: Annotated[str, Field(min_length=1, max_length=64)]


class Unit(Strict):
    type: Literal["lab", "department", "course"]
    id: Identifier


class ProjectInput(Strict):
    # No owner/creator/sub fields: ownership comes from the token only (extra fields are rejected).
    title: ShortText
    description: LongText = ""
    members: list[Member] = Field(min_length=1, max_length=100)
    units: list[Unit] = Field(min_length=1, max_length=20)


class RepositoryMetadata(Strict):
    repo_url: HttpUrl
    target_branch: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    primary_tech_stack: Annotated[str, Field(max_length=100)] | None = None
    total_commit_count: Annotated[StrictInt, Field(ge=0)] | None = None
    latest_commit_timestamp: Timestamp | None = None
    description: LongText | None = None


class VideoMetadata(Strict):
    video_url: HttpUrl
    thumbnail_url: HttpUrl | None = None
    duration: Annotated[StrictInt, Field(ge=0, le=7 * 24 * 3600)] | None = None
    description: LongText | None = None


class ManuscriptMetadata(Strict):
    title: Annotated[str, Field(min_length=1, max_length=500)]
    abstract: Annotated[str, Field(max_length=20_000)] | None = None
    authors: list[Annotated[str, Field(min_length=1, max_length=200)]] | None = Field(default=None, max_length=100)
    keywords: list[Annotated[str, Field(min_length=1, max_length=100)]] | None = Field(default=None, max_length=50)
    year: Annotated[StrictInt, Field(ge=1900, le=2100)] | None = None
    publisher: Annotated[str, Field(max_length=300)] | None = None
    description: LongText | None = None


METADATA_MODELS = {"repositories": RepositoryMetadata, "videos": VideoMetadata, "manuscripts": ManuscriptMetadata}


class SearchQuery(BaseModel):
    # Unknown query parameters are ignored (not an error); identity is never read from them.
    keyword: Annotated[str, Field(max_length=200)] | None = None
    dept_id: Identifier | None = None
    lab_id: Identifier | None = None
    course_id: Identifier | None = None
    created_after: Timestamp | None = None
    created_before: Timestamp | None = None
    artifact_type: ArtifactType | None = None

