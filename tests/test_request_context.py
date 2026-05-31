"""
Tests for request_context — ContextVar, RequestIdFilter, and the tracing middleware.
"""
import logging

from fastapi import FastAPI
from fastapi.testclient import TestClient

from request_context import (
    RequestIdFilter,
    get_request_id,
    request_tracing_middleware,
    set_request_id,
)


# ---------------------------------------------------------------------------
# ContextVar helpers
# ---------------------------------------------------------------------------

def test_default_request_id_is_dash():
    assert get_request_id() == "-"


async def test_set_and_get_in_async_context():
    set_request_id("abc123")
    assert get_request_id() == "abc123"
    # Reset so this test doesn't bleed (context is per-task but reset for safety)
    set_request_id("-")


async def test_context_is_isolated_between_tasks():
    import asyncio

    results = []

    async def task(value: str):
        set_request_id(value)
        await asyncio.sleep(0)
        results.append(get_request_id())

    await asyncio.gather(task("task-A"), task("task-B"))
    assert set(results) == {"task-A", "task-B"}


# ---------------------------------------------------------------------------
# RequestIdFilter
# ---------------------------------------------------------------------------

def test_filter_injects_request_id_into_record():
    set_request_id("req-xyz")
    f = RequestIdFilter()
    record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
    assert f.filter(record) is True
    assert record.request_id == "req-xyz"  # type: ignore[attr-defined]
    set_request_id("-")


def test_filter_uses_default_when_no_request_active():
    set_request_id("-")
    f = RequestIdFilter()
    record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
    f.filter(record)
    assert record.request_id == "-"  # type: ignore[attr-defined]


def test_filter_always_returns_true():
    f = RequestIdFilter()
    record = logging.LogRecord("test", logging.WARNING, "", 0, "warn", (), None)
    assert f.filter(record) is True


# ---------------------------------------------------------------------------
# Middleware helpers
# ---------------------------------------------------------------------------

def _make_client() -> tuple[TestClient, FastAPI]:
    """Minimal app with the tracing middleware registered."""
    app = FastAPI()

    @app.middleware("http")
    async def _tracing(request, call_next):
        return await request_tracing_middleware(request, call_next)

    @app.get("/ping")
    async def ping():
        return {"id": get_request_id()}

    return TestClient(app, raise_server_exceptions=True), app


# ---------------------------------------------------------------------------
# Middleware — X-Request-ID header behaviour
# ---------------------------------------------------------------------------

def test_middleware_generates_request_id_when_absent():
    client, _ = _make_client()
    response = client.get("/ping")
    assert response.status_code == 200
    rid = response.headers.get("X-Request-ID")
    assert rid is not None
    assert len(rid) == 16
    assert rid.isalnum()  # uuid4().hex[:16] is lowercase hex


def test_middleware_echoes_provided_request_id():
    client, _ = _make_client()
    response = client.get("/ping", headers={"X-Request-ID": "my-trace-id"})
    assert response.headers["X-Request-ID"] == "my-trace-id"


def test_middleware_id_is_visible_inside_handler():
    client, _ = _make_client()
    response = client.get("/ping", headers={"X-Request-ID": "visible-id"})
    assert response.json()["id"] == "visible-id"


def test_middleware_generated_id_matches_header_and_handler():
    client, _ = _make_client()
    response = client.get("/ping")
    header_id = response.headers["X-Request-ID"]
    body_id = response.json()["id"]
    assert header_id == body_id


# ---------------------------------------------------------------------------
# Middleware — logging
# ---------------------------------------------------------------------------

def test_middleware_logs_request_line(caplog):
    client, _ = _make_client()
    with caplog.at_level(logging.INFO, logger="request"):
        client.get("/ping", headers={"X-Request-ID": "log-test-id"})

    request_logs = [r for r in caplog.records if r.name == "request"]
    assert len(request_logs) == 1
    msg = request_logs[0].getMessage()
    assert "GET" in msg
    assert "/ping" in msg
    assert "200" in msg


def test_middleware_log_includes_request_id(caplog):
    client, _ = _make_client()
    with caplog.at_level(logging.INFO, logger="request"):
        f = RequestIdFilter()
        logging.getLogger("request").addFilter(f)
        try:
            client.get("/ping", headers={"X-Request-ID": "filter-test-id"})
            request_logs = [r for r in caplog.records if r.name == "request"]
            assert len(request_logs) >= 1
            assert request_logs[-1].request_id == "filter-test-id"  # type: ignore[attr-defined]
        finally:
            logging.getLogger("request").removeFilter(f)
