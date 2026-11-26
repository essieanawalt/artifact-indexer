# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: PT2 audit recorder for changes, deletions and downloads, including refused and failed attempts (~100%)
# Human Modifications: None yet
# Verification: tests/test_security.py PT2 tests (record contents, denied attempts, survival after deletion)
# Confidence: High
import logging
from contextlib import contextmanager

from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.authz import NotAccessible
from app.models import AuditEvent, now
from app.security import Principal

log = logging.getLogger("indexer.audit")


def outcome_for(exc: HTTPException) -> str:
    if isinstance(exc, NotAccessible) or exc.status_code == 403:
        return "denied"
    if exc.status_code == 404:
        return "not_found"
    if exc.status_code in (409, 412, 428):
        return "conflict"
    if exc.status_code >= 500:
        return "error"
    return "rejected"


class Auditor:
    """Writes each event in its own transaction, so the record survives a rolled-back change and later deletion."""

    def __init__(self, engine):
        self.engine = engine

    def record(self, actor: str, action: str, project_id: str | None, artifact_id: str | None, outcome: str, status: int):
        with Session(self.engine) as session:
            session.add(AuditEvent(at=now(), actor=actor, action=action, project_id=project_id, artifact_id=artifact_id,
                                   outcome=outcome, status_code=status))
            session.commit()
        log.info("audit actor=%s action=%s project=%s artifact=%s outcome=%s status=%s",
                 actor, action, project_id, artifact_id, outcome, status)

    @contextmanager
    def track(self, principal: Principal, action: str, project_id: str | None, artifact_id: str | None = None,
              success_status: int = 200):
        """Record the outcome of the wrapped operation. ``ids`` may be filled in by the block (e.g. new artifact id)."""
        ids = {"project_id": project_id, "artifact_id": artifact_id}
        try:
            yield ids
        except StaleDataError:
            self.record(principal.sub, action, ids["project_id"], ids["artifact_id"], "conflict", 412)
            raise HTTPException(412, "The record changed since you read it; reload and retry") from None
        except HTTPException as exc:
            self.record(principal.sub, action, ids["project_id"], ids["artifact_id"], outcome_for(exc), exc.status_code)
            raise
        except Exception:
            self.record(principal.sub, action, ids["project_id"], ids["artifact_id"], "error", 500)
            raise
        self.record(principal.sub, action, ids["project_id"], ids["artifact_id"], "success", success_status)
