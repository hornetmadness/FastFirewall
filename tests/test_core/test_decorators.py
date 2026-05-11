import pytest
from plugin_system.core.decorators import on, on_any, _HANDLER_EVENTS_ATTR, _WILDCARD_ATTR


def test_on_single_event_sets_attr():
    @on("user.login")
    def handler(event):
        pass

    assert getattr(handler, _HANDLER_EVENTS_ATTR) == ["user.login"]


def test_on_multiple_events_sets_all():
    @on("a", "b", "c")
    def handler(event):
        pass

    assert getattr(handler, _HANDLER_EVENTS_ATTR) == ["a", "b", "c"]


def test_on_stacked_decorators_accumulate():
    @on("x")
    @on("y")
    def handler(event):
        pass

    events = getattr(handler, _HANDLER_EVENTS_ATTR)
    assert "x" in events
    assert "y" in events


def test_on_preserves_function_identity():
    def handler(event):
        pass

    decorated = on("evt")(handler)
    assert decorated is handler


def test_on_empty_raises():
    with pytest.raises(ValueError):
        on()


def test_on_any_sets_wildcard_attr():
    @on_any
    def handler(event):
        pass

    assert getattr(handler, _WILDCARD_ATTR) is True


def test_on_any_does_not_set_events_attr():
    @on_any
    def handler(event):
        pass

    assert not hasattr(handler, _HANDLER_EVENTS_ATTR)


def test_on_any_preserves_function_identity():
    def handler(event):
        pass

    decorated = on_any(handler)
    assert decorated is handler


def test_on_and_on_any_can_coexist():
    @on_any
    @on("specific")
    def handler(event):
        pass

    assert getattr(handler, _WILDCARD_ATTR) is True
    assert "specific" in getattr(handler, _HANDLER_EVENTS_ATTR)
