# Project Artifact & Repository Indexer (hardened)

FastAPI + PostgreSQL 17 service for projects and their artifacts (manuscripts with uploaded files, presentation videos, Git repositories). The PA3 hardening adds token authentication, row-level authorization, manuscript encryption, input validation, stale-update protection, an audit record and size limits. The functional routes are unchanged, except that updates now need `If-Match` (see below).

## Configure

Every variable is listed, with placeholders only, in [`.env.example`](.env.example). Copy it to `.env` (git-ignored) and fill it in:

| Variable | Meaning |
| --- | --- |
| `JWKS_HOST_PATH` | Host path of the **public** JWKS file. Compose mounts it read-only. |
| `JWT_JWKS_PATH` | Path inside the container where the service reads the JWKS file (default `/etc/indexer/jwks.json`). |
| `JWT_ISSUER` | Required `iss`: `http://localhost:9000` |
| `JWT_AUDIENCE` | Required `aud`: `cs763-api` |
| `FIELD_ENCRYPTION_KEY` | Base64 of exactly 32 random bytes (AES-256-GCM). Generate it with `python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`. Never commit it. |
| `MAX_UPLOAD_BYTES`, `MAX_JSON_BYTES`, `MAX_ZIP_FILES`, `MAX_ZIP_BYTES`, `MAX_CONCURRENT_ZIPS` | PT3 limits. Defaults: 10 MiB, 1 MiB, 50 files, 100 MiB, 2. |

If the JWKS path, issuer, audience or a valid encryption key is missing, the service refuses to start (fail closed).

## Run with Docker Compose

From `PA2/` (the Compose file is `../docker-compose.yml`):

```bash
docker compose --env-file functional-codebase/.env up --build -d --wait
```

Compose fills in its variables from the shell environment or from the `--env-file`. Compose looks for `.env` next to the Compose file by default, which is `PA2/.env`, so point it at this folder's `.env` with `--env-file`, or export the variables in your shell.

## Call the API with a token

All `/api/v1/*` routes need `Authorization: Bearer <JWT>`. Only `GET /healthz` is public, and `/docs`, `/redoc` and `/openapi.json` are turned off. A token must:

- be signed with **RS256**, with a `kid` that matches a key in the JWKS file. `none`, HS256 and every other algorithm are refused, and so are `jku`, `jwk`, `x5u` and `x5c` header values: the service never fetches keys.
- carry `exp`; `nbf` is checked when present. `iss` must equal `JWT_ISSUER`. `aud` must equal `JWT_AUDIENCE`, or be an array that contains it. Up to 60 s of clock skew is allowed.
- carry `sub` (the member id) and `roles` (a JSON array of `admin`, `faculty_instructor`, `student`).

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8002/api/v1/projects
```

**Updates need `If-Match` (PT1).** Every read and write returns `ETag: "<revision>"` and a `revision` field. `PUT` on a project or artifact, and `POST …/file` (upload), must send `If-Match: "<revision>"`. Without it you get **428**; with a stale revision you get **412**, and the newer change is kept. `DELETE` accepts an optional `If-Match`.

**Audit record (PT2).** `GET /api/v1/audit-events?project_id=…&artifact_id=…&actor=…&limit=…` is for `admin` only.

## Where the security code is

| Concern | Location |
| --- | --- |
| **Token signature verification** | [`app/security.py:90-116`](app/security.py) `verify_token`: algorithm allowlist, `kid` lookup, then `jwt.decode` with RS256 and the `iss`/`aud`/`exp`/`nbf` checks at lines 104-110. JWKS loading is at [`app/security.py:45-87`](app/security.py) `JwksKeyStore`: only RSA signing keys of at least 2048 bits, and an ambiguous `kid` is dropped. The request dependency is at [`app/security.py:123-136`](app/security.py) `current_principal`. |
| **Row-level authorization policy** | [`app/authz.py:28-54`](app/authz.py): `is_member`, `can_modify`, `can_download` (members, admin, and `faculty_instructor` of the project's course or lab from [`app/directory.py`](app/directory.py)), and `ensure`. |
| **Row-level checks in routes** | `app/main.py`, each loading the record before acting: update project 261, delete project 275, zip download 300, add artifact 335, update artifact 364, delete artifact 378, upload 393, file download 419, delete file 432. The admin-only audit query is at 449. |
| Encryption | [`app/crypto.py:49-60`](app/crypto.py) uses AES-256-GCM, a fresh 12-byte random nonce for each value, and the artifact id as associated data. Files are encrypted before writing in [`app/main.py:123-129`](app/main.py) `write_encrypted`, called from upload. They are decrypted, with the plaintext SHA-256 checked, only after the authorization check, in [`app/main.py:132-143`](app/main.py) `read_decrypted`, which serves both the single download and the zip. Plaintext files left by the pre-hardening service are encrypted at startup in [`app/main.py:151-174`](app/main.py). |
| Input validation | [`app/schemas.py`](app/schemas.py): strict models that reject unknown fields, with per-kind artifact metadata, http(s)-only URLs and length limits. Upload filenames are cleaned in `app/main.py` `safe_filename`. |
| PT1 stale updates | `version_id_col` in [`app/models.py`](app/models.py) makes the `UPDATE … WHERE revision = ?` atomic. `If-Match` is handled by `expected_revision` / `check_revision` in `app/main.py`. |
| PT2 audit record | [`app/audit.py`](app/audit.py) and the `audit_events` table in `app/models.py`. The table has no foreign keys, so events survive deletion. |
| PT3 limits | [`app/limits.py`](app/limits.py) caps the request body (it checks `Content-Length` and also counts streamed bytes) and bounds file reads. Zip caps and the concurrency gate are in `download_zip` in `app/main.py`. |

## The 404 / 403 rule

- **401**: missing, malformed or invalid token.
- **403**: the caller's role is not allowed the action at all. A token with no known role is refused on every API route, and the audit log is for `admin` only.
- **404**: the record does not exist, **or** it exists but the caller may not act on it. Examples: a non-member updating or deleting a project or its artifacts, or a non-member, non-admin, unassociated caller downloading a manuscript. The body is identical to a real "not found".
- Reads of project profiles, artifact metadata and search are open to every authenticated caller with a known role.

## Tests

The tests generate a throwaway RSA key pair and a test JWKS in test code (`tests/keys.py`), and sign their own tokens.

In-process (SQLite, temporary storage):

```bash
uv run pytest -q
```

Against the Compose stack:

```bash
uv run python -m tests.keys /tmp/pa3-keys
```

```bash
JWKS_HOST_PATH=/tmp/pa3-keys/jwks.json FIELD_ENCRYPTION_KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())") MAX_UPLOAD_BYTES=65536 MAX_ZIP_FILES=5 MAX_ZIP_BYTES=131072 docker compose -f ../docker-compose.yml up --build -d --wait
```

```bash
PA2_BASE_URL=http://127.0.0.1:8002 TEST_KEYS_DIR=/tmp/pa3-keys MAX_UPLOAD_BYTES=65536 MAX_ZIP_FILES=5 MAX_ZIP_BYTES=131072 uv run pytest -q
```

Tests that need direct access to storage, the database or app state are skipped in Compose mode.

---

## PA2 provenance (original metadata block)

- Authoring tool: OpenAI Codex desktop, local single-agent session, 2026-11-17 (IST).
- AI conceptual/prose contribution: 100% at initial creation; human refactoring: 0% at creation.
- Student verification and final contribution assessment: **pending**; review is not authorship.
- Prompts and output history: [../.ai_logs/prompt-history.md](../.ai_logs/prompt-history.md); [construction brief](../.ai_logs/functional-brief.md).
- PA3 hardening: Claude Code (Claude Opus 5.5), 2026-11-26. See the per-file headers and the task note.
