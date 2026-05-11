"""
Decorators for plugin authors
─────────────────────────────
Usage inside a plugin module:

    from plugin_system.core.decorators import on, on_any

    @on("user.login")
    def greet(event):
        print(f"Hello {event.payload['username']}")

    @on("order.placed", "order.updated")   # multiple events
    async def handle_order(event):
        ...

    @on_any
    def log_everything(event):
        ...
"""
from __future__ import annotations

from typing import Callable

# Sentinel attribute name we attach to functions so the loader can find them
_HANDLER_EVENTS_ATTR = "_plugin_events"
_WILDCARD_ATTR = "_plugin_wildcard"


def on(*event_names: str) -> Callable:
    """
    Mark a function as a handler for one or more named events.

    @on("user.login")
    def handle(event): ...

    @on("order.placed", "order.updated")
    async def handle(event): ...
    """
    if not event_names:
        raise ValueError("@on() requires at least one event name")

    def decorator(fn: Callable) -> Callable:
        existing: list[str] = getattr(fn, _HANDLER_EVENTS_ATTR, [])
        fn._plugin_events = existing + list(event_names)  # type: ignore[attr-defined]
        return fn

    return decorator


def on_any(fn: Callable) -> Callable:
    """
    Mark a function as a wildcard handler (receives every event).

    @on_any
    def log_all(event): ...
    """
    fn._plugin_wildcard = True  # type: ignore[attr-defined]
    return fn
