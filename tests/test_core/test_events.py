import asyncio
import pytest
from plugin_system.core.events import Event, EventBus
from request_context import get_request_id, set_request_id


@pytest.fixture
def bus():
    return EventBus()


def test_subscribe_and_emit(bus):
    received = []
    bus.subscribe("test.event", lambda e: received.append(e))
    event = Event(name="test.event")
    bus.emit(event)
    assert len(received) == 1
    assert received[0] is event


def test_specific_handler_ignores_other_events(bus):
    received = []
    bus.subscribe("a.event", lambda e: received.append(e.name))
    bus.emit(Event("b.event"))
    assert received == []


def test_subscribe_all_receives_all_events(bus):
    received = []
    bus.subscribe_all(lambda e: received.append(e.name))
    bus.emit(Event("alpha"))
    bus.emit(Event("beta"))
    assert received == ["alpha", "beta"]


def test_unsubscribe_stops_delivery(bus):
    received = []
    handler = lambda e: received.append(e)
    bus.subscribe("x", handler)
    bus.unsubscribe("x", handler)
    bus.emit(Event("x"))
    assert received == []


def test_unsubscribe_unknown_handler_is_noop(bus):
    bus.subscribe("x", lambda e: None)
    bus.unsubscribe("x", lambda e: None)  # different object — should not raise


def test_emit_returns_sync_handler_results(bus):
    bus.subscribe("evt", lambda e: "hello")
    bus.subscribe("evt", lambda e: 42)
    results = bus.emit(Event("evt"))
    assert results == ["hello", 42]


def test_emit_excludes_failed_handlers_from_results(bus):
    def bad(e):
        raise RuntimeError("boom")
    bus.subscribe("evt", bad)
    bus.subscribe("evt", lambda e: "ok")
    results = bus.emit(Event("evt"))
    assert results == ["ok"]


def test_emit_async_handler_not_included_in_emit_results(bus):
    async def async_handler(e):
        return "async"
    bus.subscribe("evt", async_handler)
    results = bus.emit(Event("evt"))
    assert results == []


def test_emit_swallows_handler_exception(bus):
    def bad(e):
        raise RuntimeError("boom")

    bus.subscribe("oops", bad)
    bus.emit(Event("oops"))  # must not propagate


def test_multiple_subscribers_all_called(bus):
    results = []
    bus.subscribe("evt", lambda e: results.append(1))
    bus.subscribe("evt", lambda e: results.append(2))
    bus.emit(Event("evt"))
    assert results == [1, 2]


def test_service_injection_adds_services_key(bus):
    bus.plugin_services["my_plugin"] = ["dns", "dhcp"]
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload.get("services")))

    class FakePlugin:
        plugin_id = "my_plugin"
        def do_emit(self):
            bus.emit(Event("test"))

    FakePlugin().do_emit()
    assert received[0] == ["dns", "dhcp"]


def test_service_injection_does_not_override_existing(bus):
    bus.plugin_services["my_plugin"] = ["dns"]
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload.get("services")))

    class FakePlugin:
        plugin_id = "my_plugin"
        def do_emit(self):
            bus.emit(Event("test", payload={"services": ["custom"]}))

    FakePlugin().do_emit()
    assert received[0] == ["custom"]


def test_service_injection_skips_unknown_source(bus):
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload))
    bus.emit(Event("test"))
    assert "services" not in received[0]


@pytest.mark.asyncio
async def test_emit_async_awaits_async_handler(bus):
    received = []

    async def handler(e):
        received.append(e.name)

    bus.subscribe("async.evt", handler)
    await bus.emit_async(Event("async.evt"))
    assert received == ["async.evt"]


@pytest.mark.asyncio
async def test_emit_async_calls_sync_handler(bus):
    received = []
    bus.subscribe("sync.evt", lambda e: received.append(e.name))
    await bus.emit_async(Event("sync.evt"))
    assert received == ["sync.evt"]


@pytest.mark.asyncio
async def test_emit_async_returns_results(bus):
    bus.subscribe("evt", lambda e: "sync")

    async def async_h(e):
        return "async"
    bus.subscribe("evt", async_h)
    results = await bus.emit_async(Event("evt"))
    assert results == ["sync", "async"]


@pytest.mark.asyncio
async def test_emit_async_swallows_handler_exception(bus):
    async def bad(e):
        raise ValueError("async boom")

    bus.subscribe("err.evt", bad)
    await bus.emit_async(Event("err.evt"))  # must not propagate


def test_wildcard_receives_specific_event(bus):
    received = []
    bus.subscribe_all(lambda e: received.append(e.name))
    bus.emit(Event("specific.event"))
    assert "specific.event" in received


def test_wildcard_plus_specific_both_fire(bus):
    results = []
    bus.subscribe("named", lambda e: results.append("named"))
    bus.subscribe_all(lambda e: results.append("wildcard"))
    bus.emit(Event("named"))
    assert "named" in results
    assert "wildcard" in results


# ---------------------------------------------------------------------------
# Request ID injection
# ---------------------------------------------------------------------------

def test_emit_injects_request_id_into_payload(bus):
    set_request_id("test-req-1")
    received = []
    bus.subscribe("evt", lambda e: received.append(e.payload.get("request_id")))
    try:
        bus.emit(Event("evt"))
        assert received[0] == "test-req-1"
    finally:
        set_request_id("-")


def test_emit_uses_dash_when_no_request_active(bus):
    set_request_id("-")
    received = []
    bus.subscribe("evt", lambda e: received.append(e.payload.get("request_id")))
    bus.emit(Event("evt"))
    assert received[0] == "-"


def test_emit_does_not_override_explicit_request_id(bus):
    set_request_id("ctx-id")
    received = []
    bus.subscribe("evt", lambda e: received.append(e.payload.get("request_id")))
    try:
        bus.emit(Event("evt", payload={"request_id": "caller-set"}))
        assert received[0] == "caller-set"
    finally:
        set_request_id("-")


async def test_emit_async_injects_request_id(bus):
    set_request_id("async-req-1")
    received = []
    bus.subscribe("evt", lambda e: received.append(e.payload.get("request_id")))
    try:
        await bus.emit_async(Event("evt"))
        assert received[0] == "async-req-1"
    finally:
        set_request_id("-")
