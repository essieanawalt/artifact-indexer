# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: Routes from the OpenAI Codex PA2 original, rewritten to add authentication, row-level checks, encryption, If-Match, audit and limits (~75%)
# Human Modifications: None yet
# Verification: Full suite (tests/test_api.py, test_auth.py, test_authz.py, test_security.py) in-process and against Docker Compose
# Confidence: High
import hashlib
import logging
import os
import re
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import Annotated
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import Body, Depends, FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.audit import Auditor
from app.authz import can_download, can_modify, ensure
from app.config import Settings
from app.crypto import MAGIC, DecryptionError, FieldCipher
from app.limits import BodySizeLimit, read_limited
from app.models import Artifact, AuditEvent, Project, migrate, now
from app.schemas import METADATA_MODELS, ArtifactType, ProjectInput, SearchQuery
from app.security import Principal, current_principal, JwksKeyStore, require_admin

log = logging.getLogger("indexer")

Caller = Annotated[Principal, Depends(current_principal)]
IfMatch = Annotated[str | None, Header(alias="If-Match")]


# --- serialisation ---------------------------------------------------------------------------------

def project_json(p):
    return {k: getattr(p, k) for k in ("id", "title", "description", "members", "units", "created_at", "updated_at", "revision")}


def artifact_json(a):
    return {"id": a.id, "project_id": a.project_id, "artifact_type": a.kind, "revision": a.revision,
            "metadata": a.data, "created_at": a.created_at, "updated_at": a.updated_at,
            "file": {"filename": a.filename, "sha256": a.file_hash, "size": a.file_size} if a.file_path else None}


def with_etag(response: Response, record):
    response.headers["ETag"] = f'"{record.revision}"'


# --- lookups ------------------------------------------------------------------------------------

def get_session(request: Request):
    with Session(request.app.state.engine) as session:
        yield session


def get_project(session, project_id):
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    return project


def get_artifact(session, project_id, kind, artifact_id):
    project = get_project(session, project_id)
    artifact = session.get(Artifact, artifact_id)
    if artifact is None or artifact.project_id != project_id or artifact.kind != kind:
        raise HTTPException(404, "Artifact not found")
    return project, artifact


# --- PT1: optimistic concurrency via If-Match -------------------------------------------------------

def expected_revision(if_match: str | None, required: bool = True) -> int | None:
    if if_match is None:
        if required:
            raise HTTPException(428, 'If-Match header with the current revision (ETag) is required, e.g. If-Match: "3"')
        return None
    value = if_match.strip()
    value = value[2:] if value.startswith("W/") else value
    value = value.strip('"')
    if not value.isdigit():
        raise HTTPException(412, "If-Match does not match the current revision")
    return int(value)


def check_revision(record, expected: int | None):
    if expected is not None and record.revision != expected:
        raise HTTPException(412, "The record changed since you read it; reload and retry")


# --- validation helpers -------------------------------------------------------------------------

def validate_metadata(kind: str, metadata) -> dict:
    try:
        return METADATA_MODELS[kind].model_validate(metadata).model_dump(exclude_unset=True)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False, include_context=False)) from None


SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(name: str | None) -> str:
    cleaned = SAFE_FILENAME.sub("_", Path((name or "").replace("\\", "/")).name)[:255]
    return cleaned if cleaned.strip(".") else "manuscript.bin"


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# --- encrypted file storage (CWE-312) -----------------------------------------------------------------

def write_encrypted(app, artifact_id: str, plaintext: bytes) -> Path:
    blob = app.state.cipher.encrypt(plaintext, artifact_id.encode())
    target = app.state.settings.storage_dir / f"{artifact_id}-{uuid4().hex}"
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(blob)
    os.replace(temporary, target)
    return target


def read_decrypted(app, artifact) -> bytes:
    path = Path(artifact.file_path)
    if not path.is_file():
        raise HTTPException(404, "File not found")
    try:
        plaintext = app.state.cipher.decrypt(path.read_bytes(), artifact.id.encode())
    except DecryptionError:
        log.error("manuscript %s failed authenticated decryption", artifact.id)
        raise HTTPException(500, "Stored file failed its integrity check") from None
    if artifact.file_hash and hashlib.sha256(plaintext).hexdigest() != artifact.file_hash:
        raise HTTPException(500, "Stored file failed its integrity check")
    return plaintext


def unlink_quietly(path: str | None):
    if path:
        Path(path).unlink(missing_ok=True)


def encrypt_legacy_files(app):
    """Encrypt manuscript files stored in plain text by the pre-hardening service."""
    with Session(app.state.engine) as session:
        legacy = session.scalars(select(Artifact).where(Artifact.file_path.is_not(None), Artifact.file_encrypted.is_(False))).all()
        for artifact in legacy:
            path = Path(artifact.file_path)
            if not path.is_file():
                continue
            data = path.read_bytes()
            if data.startswith(MAGIC):
                try:   # already encrypted by an interrupted earlier run
                    app.state.cipher.decrypt(data, artifact.id.encode())
                    artifact.file_encrypted = True
                    continue
                except DecryptionError:
                    pass
            new_path = write_encrypted(app, artifact.id, data)
            artifact.file_path, artifact.file_encrypted = str(new_path), True
            artifact.file_hash = artifact.file_hash or hashlib.sha256(data).hexdigest()
            artifact.file_size = len(data)
            session.commit()
            path.unlink(missing_ok=True)
            log.info("encrypted legacy manuscript file for artifact %s", artifact.id)
        session.commit()


# --- application ----------------------------------------------------------------------------------

def create_app(database_url=None, storage_dir=None, *, jwks_path=None, issuer=None, audience=None, encryption_key=None,
               max_upload_bytes=None, max_json_bytes=None, max_zip_files=None, max_zip_bytes=None, max_concurrent_zips=None):
    settings = Settings.load(database_url=database_url, storage_dir=storage_dir, jwks_path=jwks_path, issuer=issuer,
                             audience=audience, encryption_key=encryption_key, max_upload_bytes=max_upload_bytes,
                             max_json_bytes=max_json_bytes, max_zip_files=max_zip_files, max_zip_bytes=max_zip_bytes,
                             max_concurrent_zips=max_concurrent_zips)
    url = settings.database_url
    engine = create_engine(url, **({"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}))
    storage = settings.storage_dir

    @asynccontextmanager
    async def lifespan(app):
        key = settings.validate()              # fail closed without JWKS path, issuer, audience or encryption key
        app.state.cipher = FieldCipher(key)
        app.state.jwks = JwksKeyStore(settings.jwks_path)
        storage.mkdir(parents=True, exist_ok=True)
        migrate(engine)
        encrypt_legacy_files(app)
        yield
        engine.dispose()

    # Interactive docs and the OpenAPI schema are disabled: only the health check is public.
    app = FastAPI(title="Project Artifact & Repository Indexer", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine = engine
    app.state.settings = settings
    app.state.audit = audit = Auditor(engine)
    app.state.zip_slots = threading.BoundedSemaphore(settings.max_concurrent_zips)
    app.add_middleware(BodySizeLimit, settings=settings)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    # --- projects ---------------------------------------------------------------------------------

    @app.post("/api/v1/projects", status_code=201)
    def create_project(body: ProjectInput, principal: Caller, response: Response, session: Session = Depends(get_session)):
        with audit.track(principal, "project.create", None, success_status=201) as ids:
            members = [m.model_dump() for m in body.members]
            if not any(m["id"] == principal.sub for m in members):
                members.append({"id": principal.sub, "role": "creator"})   # creator from the token, never the body
            stamp = now()
            project = Project(id=str(uuid4()), title=body.title, description=body.description, members=members,
                              units=[u.model_dump() for u in body.units], created_at=stamp, updated_at=stamp)
            ids["project_id"] = project.id
            session.add(project)
            session.commit()
        with_etag(response, project)
        return project_json(project)

    @app.get("/api/v1/projects")
    def search(principal: Caller, query: Annotated[SearchQuery, Query()], session: Session = Depends(get_session)):
        # Any authenticated caller may read every project profile, so no row filter is needed here.
        statement = select(Project).order_by(Project.created_at, Project.id)
        if query.keyword:
            pattern = f"%{escape_like(query.keyword)}%"
            statement = statement.where(Project.title.ilike(pattern, escape="\\") | Project.description.ilike(pattern, escape="\\"))
        if query.created_after:
            statement = statement.where(Project.created_at >= query.created_after)
        if query.created_before:
            statement = statement.where(Project.created_at <= query.created_before)
        projects = session.scalars(statement).all()
        for kind, unit_id in (("department", query.dept_id), ("lab", query.lab_id), ("course", query.course_id)):
            if unit_id:
                projects = [p for p in projects if any(u.get("type") == kind and u.get("id") == unit_id for u in p.units)]
        if query.artifact_type:
            kinds = set(session.scalars(select(Artifact.project_id).where(Artifact.kind == query.artifact_type)))
            projects = [p for p in projects if p.id in kinds]
        return [project_json(p) for p in projects]

    @app.get("/api/v1/projects/{project_id}")
    def read_project(project_id: str, principal: Caller, response: Response, session: Session = Depends(get_session)):
        project = get_project(session, project_id)
        with_etag(response, project)
        return project_json(project)

    @app.put("/api/v1/projects/{project_id}")
    def update_project(project_id: str, body: ProjectInput, principal: Caller, response: Response, if_match: IfMatch = None,
                       session: Session = Depends(get_session)):
        with audit.track(principal, "project.update", project_id):
            project = get_project(session, project_id)
            ensure(can_modify(principal, project))
            check_revision(project, expected_revision(if_match))
            project.title, project.description = body.title, body.description
            project.members = [m.model_dump() for m in body.members]
            project.units = [u.model_dump() for u in body.units]
            project.updated_at = now()
            session.commit()
        with_etag(response, project)
        return project_json(project)

    @app.delete("/api/v1/projects/{project_id}", status_code=204)
    def delete_project(project_id: str, principal: Caller, if_match: IfMatch = None, session: Session = Depends(get_session)):
        with audit.track(principal, "project.delete", project_id, success_status=204):
            project = get_project(session, project_id)
            ensure(can_modify(principal, project))
            check_revision(project, expected_revision(if_match, required=False))
            files = []
            for artifact in session.scalars(select(Artifact).where(Artifact.project_id == project_id)).all():
                files.append(artifact.file_path)
                session.delete(artifact)
            session.flush()
            session.delete(project)
            session.commit()
            for path in files:
                unlink_quietly(path)
        return Response(status_code=204)

    # --- artifacts --------------------------------------------------------------------------------

    @app.get("/api/v1/projects/{project_id}/artifacts")
    def all_artifacts(project_id: str, principal: Caller, session: Session = Depends(get_session)):
        get_project(session, project_id)
        return [artifact_json(a) for a in session.scalars(select(Artifact).where(Artifact.project_id == project_id).order_by(Artifact.id))]

    # Register the fixed download route before routes containing artifact IDs.
    @app.get("/api/v1/projects/{project_id}/artifacts/manuscripts/download")
    def download_zip(project_id: str, principal: Caller, session: Session = Depends(get_session)):
        with audit.track(principal, "manuscript.download_zip", project_id):
            project = get_project(session, project_id)
            ensure(can_download(principal, project))
            artifacts = session.scalars(select(Artifact).where(Artifact.project_id == project_id, Artifact.kind == "manuscripts",
                                                               Artifact.file_path.is_not(None)).order_by(Artifact.id)).all()
            # PT3: bound the archive before doing any work.
            if len(artifacts) > settings.max_zip_files or sum(a.file_size or 0 for a in artifacts) > settings.max_zip_bytes:
                raise HTTPException(422, f"Archive would exceed {settings.max_zip_files} files or {settings.max_zip_bytes} bytes; "
                                         "download files individually")
            if not app.state.zip_slots.acquire(blocking=False):
                raise HTTPException(429, "Too many archive downloads in progress; retry shortly", headers={"Retry-After": "5"})
            spool = SpooledTemporaryFile(max_size=8 * 1024 * 1024)
            try:
                with ZipFile(spool, "w", ZIP_DEFLATED) as archive:
                    for artifact in artifacts:
                        archive.writestr(f"{artifact.id}/{safe_filename(artifact.filename)}", read_decrypted(app, artifact))
                spool.seek(0)
            except BaseException:
                spool.close()
                raise
            finally:
                app.state.zip_slots.release()

        def stream():
            with spool:
                while chunk := spool.read(64 * 1024):
                    yield chunk

        return StreamingResponse(stream(), media_type="application/zip",
                                 headers={"Content-Disposition": 'attachment; filename="manuscripts.zip"',
                                          "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.post("/api/v1/projects/{project_id}/artifacts/{artifact_type}/", status_code=201)
    def add_artifact(project_id: str, artifact_type: ArtifactType, principal: Caller, response: Response,
                     metadata: dict = Body(...), session: Session = Depends(get_session)):
        with audit.track(principal, "artifact.create", project_id, success_status=201) as ids:
            project = get_project(session, project_id)
            ensure(can_modify(principal, project))
            data = validate_metadata(artifact_type, metadata)
            stamp = now()
            artifact = Artifact(id=str(uuid4()), project_id=project_id, kind=artifact_type, data=data, created_at=stamp,
                                updated_at=stamp, file_encrypted=False)
            ids["artifact_id"] = artifact.id
            session.add(artifact)
            session.commit()
        with_etag(response, artifact)
        return artifact_json(artifact)

    @app.get("/api/v1/projects/{project_id}/artifacts/{artifact_type}/")
    def list_artifacts(project_id: str, artifact_type: ArtifactType, principal: Caller, session: Session = Depends(get_session)):
        get_project(session, project_id)
        return [artifact_json(a) for a in session.scalars(select(Artifact).where(Artifact.project_id == project_id,
                                                                                 Artifact.kind == artifact_type).order_by(Artifact.id))]

    @app.get("/api/v1/projects/{project_id}/artifacts/{artifact_type}/{artifact_id}")
    def read_artifact(project_id: str, artifact_type: ArtifactType, artifact_id: str, principal: Caller, response: Response,
                      session: Session = Depends(get_session)):
        _, artifact = get_artifact(session, project_id, artifact_type, artifact_id)
        with_etag(response, artifact)
        return artifact_json(artifact)

    @app.put("/api/v1/projects/{project_id}/artifacts/{artifact_type}/{artifact_id}")
    def update_artifact(project_id: str, artifact_type: ArtifactType, artifact_id: str, principal: Caller, response: Response,
                        metadata: dict = Body(...), if_match: IfMatch = None, session: Session = Depends(get_session)):
        with audit.track(principal, "artifact.update", project_id, artifact_id):
            project, artifact = get_artifact(session, project_id, artifact_type, artifact_id)
            ensure(can_modify(principal, project), "artifact")
            data = validate_metadata(artifact_type, metadata)
            check_revision(artifact, expected_revision(if_match))
            artifact.data = data
            artifact.updated_at = now()
            session.commit()
        with_etag(response, artifact)
        return artifact_json(artifact)

    @app.delete("/api/v1/projects/{project_id}/artifacts/{artifact_type}/{artifact_id}", status_code=204)
    def delete_artifact(project_id: str, artifact_type: ArtifactType, artifact_id: str, principal: Caller,
                        if_match: IfMatch = None, session: Session = Depends(get_session)):
        with audit.track(principal, "artifact.delete", project_id, artifact_id, success_status=204):
            project, artifact = get_artifact(session, project_id, artifact_type, artifact_id)
            ensure(can_modify(principal, project), "artifact")
            check_revision(artifact, expected_revision(if_match, required=False))
            path = artifact.file_path
            session.delete(artifact)
            session.commit()
            unlink_quietly(path)
        return Response(status_code=204)

    # --- manuscript files -------------------------------------------------------------------------

    @app.post("/api/v1/projects/{project_id}/artifacts/manuscripts/{artifact_id}/file")
    def upload(project_id: str, artifact_id: str, principal: Caller, response: Response, file: UploadFile = File(...),
               if_match: IfMatch = None, session: Session = Depends(get_session)):
        with audit.track(principal, "manuscript.upload", project_id, artifact_id):
            project, artifact = get_artifact(session, project_id, "manuscripts", artifact_id)
            ensure(can_modify(principal, project), "artifact")
            check_revision(artifact, expected_revision(if_match))
            content = read_limited(file.file, settings.max_upload_bytes)           # PT3
            if not content:
                raise HTTPException(422, "Manuscript file is empty")
            new_path = write_encrypted(app, artifact.id, content)                    # CWE-312: encrypt before storing
            old_path = artifact.file_path
            artifact.file_path, artifact.file_encrypted = str(new_path), True
            artifact.filename = safe_filename(file.filename)
            artifact.file_hash = hashlib.sha256(content).hexdigest()               # hash of the plaintext
            artifact.file_size = len(content)
            artifact.updated_at = now()
            try:
                session.commit()
            except BaseException:
                unlink_quietly(str(new_path))
                raise
            if old_path != str(new_path):
                unlink_quietly(old_path)
        with_etag(response, artifact)
        return artifact_json(artifact)

    @app.get("/api/v1/projects/{project_id}/artifacts/manuscripts/{artifact_id}/file")
    def download(project_id: str, artifact_id: str, principal: Caller, session: Session = Depends(get_session)):
        with audit.track(principal, "manuscript.download", project_id, artifact_id):
            project, artifact = get_artifact(session, project_id, "manuscripts", artifact_id)
            ensure(can_download(principal, project), "artifact")
            if not artifact.file_path:
                raise HTTPException(404, "File not found")
            plaintext = read_decrypted(app, artifact)                               # decrypt only for allowed callers
        return Response(plaintext, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{safe_filename(artifact.filename)}"',
                                 "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.delete("/api/v1/projects/{project_id}/artifacts/manuscripts/{artifact_id}/file", status_code=204)
    def delete_file(project_id: str, artifact_id: str, principal: Caller, if_match: IfMatch = None,
                    session: Session = Depends(get_session)):
        with audit.track(principal, "manuscript.delete_file", project_id, artifact_id, success_status=204):
            project, artifact = get_artifact(session, project_id, "manuscripts", artifact_id)
            ensure(can_modify(principal, project), "artifact")
            check_revision(artifact, expected_revision(if_match, required=False))
            path = artifact.file_path
            artifact.file_path = artifact.filename = artifact.file_hash = artifact.file_size = None
            artifact.file_encrypted = False
            artifact.updated_at = now()
            session.commit()
            unlink_quietly(path)
        return Response(status_code=204)

    # --- PT2 record (admin only) ----------------------------------------------------------------------

    @app.get("/api/v1/audit-events")
    def audit_events(principal: Caller, project_id: Annotated[str | None, Query(max_length=64)] = None,
                     artifact_id: Annotated[str | None, Query(max_length=64)] = None,
                     actor: Annotated[str | None, Query(max_length=128)] = None,
                     limit: Annotated[int, Query(ge=1, le=1000)] = 500, session: Session = Depends(get_session)):
        require_admin(principal)
        statement = select(AuditEvent).order_by(AuditEvent.id)
        for column, value in ((AuditEvent.project_id, project_id), (AuditEvent.artifact_id, artifact_id), (AuditEvent.actor, actor)):
            if value:
                statement = statement.where(column == value)
        return [{"id": e.id, "at": e.at, "actor": e.actor, "action": e.action, "project_id": e.project_id,
                 "artifact_id": e.artifact_id, "outcome": e.outcome, "status_code": e.status_code}
                for e in session.scalars(statement.limit(limit))]

    return app


app = create_app()
