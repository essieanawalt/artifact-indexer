# Tool: Claude Code (Claude Opus 5.5)
# Language stack: Python / FastAPI / PostgreSQL 17 / uv
# Prompt Summary: "Harden the PA2 indexer: local RS256 JWT auth, row-level authz, AES-GCM manuscript encryption, input validation, PT1-PT3 mitigations"
# AI Contribution: PT3 request body size limits (ASGI middleware) and bounded file reading (~100%)
# Human Modifications: None yet
# Verification: tests/test_security.py PT3 tests (upload over/at limit, oversized JSON body)
# Confidence: High
import json

from fastapi import HTTPException

MULTIPART_OVERHEAD = 64 * 1024   # boundaries and part headers around the file itself
CHUNK = 64 * 1024


class BodyTooLarge(HTTPException):
    def __init__(self):
        super().__init__(413, "Request body too large")


class BodySizeLimit:
    """Reject request bodies above the limit before they are buffered or spooled to disk.

    Uses Content-Length when present and also counts streamed bytes, so chunked uploads cannot bypass it.
    """

    def __init__(self, app, settings):
        self.app = app
        self.settings = settings

    def limit_for(self, scope) -> int:
        if scope["method"] == "POST" and scope["path"].endswith("/file"):
            return self.settings.max_upload_bytes + MULTIPART_OVERHEAD
        return self.settings.max_json_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.limit_for(scope)
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            return await self._reject(send)
        received, started = 0, False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not started:
                await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = json.dumps({"detail": "Request body too large"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


def read_limited(stream, limit: int) -> bytes:
    """Read at most ``limit`` bytes from a file object; 413 if there is more."""
    chunks, total = [], 0
    while chunk := stream.read(CHUNK):
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, f"Manuscript file exceeds the {limit}-byte limit")
        chunks.append(chunk)
    return b"".join(chunks)
