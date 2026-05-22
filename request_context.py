"""
request_context.py — per-request tracing via contextvars.

Provides a ContextVar that holds the current X-Request-ID, a logging filter
that injects it into every log record, and the ASGI middleware that sets it.

Usage in app.py:
    from request_context import request_tracing_middleware

    @app.middleware("http")
    async def _request_tracing(request, call_next):
        return await request_tracing_middleware(request, call_next)

The middleware must be registered AFTER the auth middleware so it becomes
the outermost layer (Starlette inserts middleware in LIFO order).
"""
from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar

from fastapi import Request
from fastapi.responses import Response

_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
_req_log = logging.getLogger("request")

_filter_installed = False
_old_log_record_factory = logging.getLogRecordFactory()


def _log_record_factory(*args, **kwargs) -> logging.LogRecord:
    record = _old_log_record_factory(*args, **kwargs)
    record.request_id = _request_id_var.get()  # type: ignore[attr-defined]
    return record


def get_request_id() -> str:
    """Return the request ID for the current async task, or '-' outside a request."""
    return _request_id_var.get()


def set_request_id(rid: str) -> None:
    """Set the request ID for the current async task."""
    _request_id_var.set(rid)


class RequestIdFilter(logging.Filter):
    """Injects ``request_id`` into every LogRecord so formatters can reference it."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get()  # type: ignore[attr-defined]
        return True


def install_filter() -> None:
    """Install request_id injection into every LogRecord via setLogRecordFactory (idempotent).

    Using a log-record factory rather than a logger filter ensures request_id
    is present on records emitted by any child logger — logger-level filters
    are not evaluated during propagation, so addFilter on the root logger alone
    does not cover child loggers.
    """
    global _filter_installed
    if _filter_installed:
        return
    logging.setLogRecordFactory(_log_record_factory)
    _filter_installed = True


async def request_tracing_middleware(request: Request, call_next) -> Response:
    """
    ASGI middleware that:
    - Reads X-Request-ID from the request header or generates a 16-char hex ID
    - Binds the ID to the current task via ContextVar (all log lines within
      this request automatically include it via RequestIdFilter)
    - Adds X-Request-ID to the response headers
    - Logs METHOD path → status (Xms) at INFO level after the response is sent
    """
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    set_request_id(rid)
    t0 = time.monotonic()
    response = await call_next(request)
    elapsed_ms = (time.monotonic() - t0) * 1000
    _req_log.info(
        "%s %s → %d (%.0fms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    response.headers["X-Request-ID"] = rid
    return response
