"""An explicit two-route access gateway, designed to be read and tested."""

from contextlib import asynccontextmanager
import json
import logging
import os
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
import httpx
from pydantic import ValidationError

from .auth import InvalidIdentity, authenticate
from .config import Settings
from .upstream import ReportInput


MAX_BODY_BYTES = 16_384
MAX_UPSTREAM_BYTES = 1_048_576
AUDIT = logging.getLogger("policygate.audit")
AUDIT.setLevel(logging.INFO)
POLICY = {
    ("GET", "/reports"): frozenset({"reader", "admin"}),
    ("POST", "/reports"): frozenset({"admin"}),
}


def _failure(request: Request, status: int, reason: str, detail: str) -> JSONResponse:
    request.state.decision = "error" if status >= 500 else "deny"
    request.state.reason = reason
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse({"detail": detail}, status_code=status, headers=headers)


def create_app(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    # A single configured destination, no proxy environment variables, and no redirects.
    client = httpx.AsyncClient(
        transport=transport,
        timeout=settings.upstream_timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await client.aclose()

    app = FastAPI(
        title="PolicyGate", lifespan=lifespan,
        docs_url=None, redoc_url=None, openapi_url=None,
        redirect_slashes=False,
    )

    @app.middleware("http")
    async def audit_request(request: Request, call_next):
        request.state.request_id = str(uuid4())
        request.state.role = None
        request.state.decision = "deny"
        request.state.reason = "method_not_allowed"
        try:
            response = await call_next(request)
        except Exception:
            # Do not copy exceptions or credentials into an audit event or HTTP response.
            response = _failure(request, 500, "internal_error", "Internal gateway error.")
        response.headers["X-Request-ID"] = request.state.request_id
        known_path = request.url.path if request.url.path in {"/health", "/reports"} else "<unmatched>"
        AUDIT.info(json.dumps({
            "request_id": request.state.request_id,
            "method": request.method[:16],
            "path": known_path,
            "role": request.state.role,
            "decision": request.state.decision,
            "reason": request.state.reason,
            "status": response.status_code,
        }, separators=(",", ":")))
        return response

    @app.exception_handler(404)
    @app.exception_handler(405)
    async def deny_framework_fallback(request: Request, exc) -> JSONResponse:
        # Some malformed paths or custom methods do not match even a catch-all route.
        # Preserve the same default-deny behavior at that framework boundary.
        try:
            identity = authenticate(request.headers.get("authorization"), settings)
        except InvalidIdentity:
            return _failure(request, 401, "invalid_credentials", "A valid bearer token is required.")
        request.state.role = identity.role
        return _failure(request, 403, "policy_denied", "Access denied by policy.")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"])
    async def route_request(request: Request, path: str) -> Response:
        route = request.url.path
        if request.method == "GET" and route == "/health":
            request.state.decision = "allow"
            request.state.reason = "public_health"
            return JSONResponse({"status": "ok", "service": "policygate"})

        try:
            identity = authenticate(request.headers.get("authorization"), settings)
        except InvalidIdentity:
            return _failure(request, 401, "invalid_credentials", "A valid bearer token is required.")

        request.state.role = identity.role
        if identity.role not in POLICY.get((request.method, route), frozenset()):
            return _failure(request, 403, "policy_denied", "Access denied by policy.")

        payload = None
        if request.method == "POST":
            content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return _failure(request, 415, "unsupported_media_type", "Use application/json.")
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                    if declared_length < 0:
                        raise ValueError
                except ValueError:
                    return _failure(request, 400, "invalid_length", "Invalid Content-Length.")
                if declared_length > MAX_BODY_BYTES:
                    return _failure(request, 413, "body_too_large", "Request body exceeds 16 KiB.")
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY_BYTES:
                    return _failure(request, 413, "body_too_large", "Request body exceeds 16 KiB.")
                body.extend(chunk)
            try:
                decoded = json.loads(body)
            except (ValueError, UnicodeDecodeError, RecursionError):
                return _failure(request, 400, "invalid_json", "Malformed JSON body.")
            try:
                payload = ReportInput.model_validate(decoded).model_dump()
            except ValidationError:
                return _failure(request, 422, "invalid_report", "Provide only a nonblank title of at most 200 characters.")

        # Never use request paths, query parameters, or forwarded headers as destinations.
        # JSON serialization creates our Content-Type; client credentials are never copied.
        request_options = {"json": payload} if payload is not None else {}
        # Explicit Request bypasses the client's cookie jar, so an upstream Set-Cookie
        # cannot accidentally transfer state from one identity to another.
        outgoing = httpx.Request(request.method, settings.upstream_url + "/reports", **request_options)
        try:
            upstream = await client.send(outgoing, stream=True)
            try:
                if 300 <= upstream.status_code < 400:
                    return _failure(request, 502, "upstream_redirect", "Unexpected upstream redirect.")
                response_body = bytearray()
                async for chunk in upstream.aiter_bytes():
                    if len(response_body) + len(chunk) > MAX_UPSTREAM_BYTES:
                        return _failure(request, 502, "upstream_response_too_large", "Upstream response exceeds the demo limit.")
                    response_body.extend(chunk)
                response_status = upstream.status_code
            finally:
                await upstream.aclose()
        except httpx.TimeoutException:
            return _failure(request, 504, "upstream_timeout", "Upstream service timed out.")
        except httpx.RequestError:
            return _failure(request, 502, "upstream_unavailable", "Upstream service is unavailable.")

        request.state.decision = "allow"
        request.state.reason = "policy_allowed"
        return Response(content=bytes(response_body), status_code=response_status, media_type="application/json")

    return app


def app_from_env() -> FastAPI:
    """Uvicorn factory: refuse startup without an explicit sufficiently long secret."""
    settings = Settings(
        secret=os.environ.get("POLICYGATE_SECRET", ""),
        upstream_url=os.environ.get("POLICYGATE_UPSTREAM_URL", "http://127.0.0.1:8001"),
    )
    if not any(handler.get_name() == "policygate-json" for handler in AUDIT.handlers):
        handler = logging.StreamHandler()
        handler.set_name("policygate-json")
        handler.setFormatter(logging.Formatter("%(message)s"))
        AUDIT.addHandler(handler)
    AUDIT.propagate = False
    return create_app(settings)
