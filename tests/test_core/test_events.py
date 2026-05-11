import asyncio
import pytest
from plugin_system.core.events import Event, EventBus


@pytest.fixture
def bus():
    return EventBus()


def test_subscribe_and_emit(bus):
    received = []
    bus.subscribe("test.event", lambda e: received.append(e))
    event = Event(name="test.event", source="test")
    bus.emit(event)
    assert len(received) == 1
    assert received[0] is event


def test_specific_handler_ignores_other_events(bus):
    received = []
    bus.subscribe("a.event", lambda e: received.append(e.name))
    bus.emit(Event("b.event", "src"))
    assert received == []


def test_subscribe_all_receives_all_events(bus):
    received = []
    bus.subscribe_all(lambda e: received.append(e.name))
    bus.emit(Event("alpha", "src"))
    bus.emit(Event("beta", "src"))
    assert received == ["alpha", "beta"]


def test_unsubscribe_stops_delivery(bus):
    received = []
    handler = lambda e: received.append(e)
    bus.subscribe("x", handler)
    bus.unsubscribe("x", handler)
    bus.emit(Event("x", "src"))
    assert received == []


def test_unsubscribe_unknown_handler_is_noop(bus):
    bus.subscribe("x", lambda e: None)
    bus.unsubscribe("x", lambda e: None)  # different object — should not raise


def test_emit_swallows_handler_exception(bus):
    def bad(e):
        raise RuntimeError("boom")

    bus.subscribe("oops", bad)
    bus.emit(Event("oops", "src"))  # must not propagate


def test_multiple_subscribers_all_called(bus):
    results = []
    bus.subscribe("evt", lambda e: results.append(1))
    bus.subscribe("evt", lambda e: results.append(2))
    bus.emit(Event("evt", "src"))
    assert results == [1, 2]


def test_service_injection_adds_services_key(bus):
    bus.plugin_services["my_plugin"] = ["dns", "dhcp"]
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload.get("services")))
    bus.emit(Event("test", source="my_plugin"))
    assert received[0] == ["dns", "dhcp"]


def test_service_injection_does_not_override_existing(bus):
    bus.plugin_services["my_plugin"] = ["dns"]
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload.get("services")))
    event = Event("test", source="my_plugin", payload={"services": ["custom"]})
    bus.emit(event)
    assert received[0] == ["custom"]


def test_service_injection_skips_unknown_source(bus):
    received = []
    bus.subscribe("test", lambda e: received.append(e.payload))
    bus.emit(Event("test", source="unknown_plugin"))
    assert "services" not in received[0]


@pytest.mark.asyncio
async def test_emit_async_awaits_async_handler(bus):
    received = []

    async def handler(e):
        received.append(e.name)

    bus.subscribe("async.evt", handler)
    await bus.emit_async(Event("async.evt", "src"))
    assert received == ["async.evt"]


@pytest.mark.asyncio
async def test_emit_async_calls_sync_handler(bus):
    received = []
    bus.subscribe("sync.evt", lambda e: received.append(e.name))
    await bus.emit_async(Event("sync.evt", "src"))
    assert received == ["sync.evt"]


@pytest.mark.asyncio
async def test_emit_async_swallows_handler_exception(bus):
    async def bad(e):
        raise ValueError("async boom")

    bus.subscribe("err.evt", bad)
    await bus.emit_async(Event("err.evt", "src"))  # must not propagate


def test_wildcard_receives_specific_event(bus):
    received = []
    bus.subscribe_all(lambda e: received.append(e.name))
    bus.emit(Event("specific.event", "src"))
    assert "specific.event" in received


def test_wildcard_plus_specific_both_fire(bus):
    results = []
    bus.subscribe("named", lambda e: results.append("named"))
    bus.subscribe_all(lambda e: results.append("wildcard"))
    bus.emit(Event("named", "src"))
    assert "named" in results
    assert "wildcard" in results
