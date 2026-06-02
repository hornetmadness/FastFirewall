"""Pub/sub event bus for the plugin system.

The module-level ``bus`` singleton is the shared channel; import it directly:

    from plugin_system.core.events import bus, Event

Plugins subscribe via ``bus.subscribe`` / ``bus.unsubscribe`` or the decorator
helpers in ``plugin_system.core.decorators`` (``@on``, ``@on_any``).

Emitting
--------
Construct an ``Event`` with just a name and optional payload, then hand it to
the bus::

    bus.emit(Event("firewall.rule.added", payload={"rule_id": rule.id}))
    await bus.emit_async(event)   # awaits async handlers; prefer in async contexts

``source`` and ``timestamp`` are set automatically — do not pass them.

Automatic fields
----------------
``emit`` / ``emit_async`` populate two fields on every event before dispatching:

- ``event.source`` — set to ``"<plugin_id>.<function_name>"`` by walking the
  call stack to the nearest frame whose ``self`` carries a ``plugin_id``
  (e.g. ``"firewall._apply_rules"``).  Empty string if called outside a plugin.
- ``event.timestamp`` — UTC ``datetime`` captured at ``Event()`` construction
  time (not at emit time).

Service injection
-----------------
``emit`` / ``emit_async`` also inject into ``event.payload``:

- ``"services"`` — the emitting plugin's declared service list (from
  ``plugin_services``), added via ``setdefault`` so an existing key is kept.
- ``"request_id"`` — the active HTTP request ID from ``request_context``, or
  ``"-"`` when called outside a request.

Bound-method identity
---------------------
Python creates a new object each time a bound method is accessed via an
attribute lookup, so ``self.method is self.method`` is ``False``.
``unsubscribe`` uses ``is`` identity to remove handlers, so always store the
reference in ``setup()`` and reuse it in ``teardown()``::

    def setup(self):
        self._h = self._on_event          # stable reference
        bus.subscribe("some.event", self._h)

    def teardown(self):
        bus.unsubscribe("some.event", self._h)

Error isolation
---------------
Exceptions raised by handlers are caught and logged; they never propagate to
the emitter or abort remaining handlers.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from request_context import get_request_id

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """A single bus message.

    Only ``name`` and ``payload`` are constructor arguments.  ``source`` and
    ``timestamp`` are set automatically by the bus at emit time — do not pass
    them.

    Attributes:
        name:      Event type identifier subscribers listen on (e.g. ``"firewall.rule.added"``).
        payload:   Arbitrary event data dict.
        source:    ``"<plugin_id>.<function>"`` of the emitting call site; empty if
                   called outside a plugin.  Set by the bus — not a constructor arg.
        timestamp: UTC datetime captured at construction.  Set at object creation —
                   not a constructor arg.
    """
    name: str
    payload: dict[str, Any] = field(default_factory=dict)
    source: str = field(init=False, default="")
    timestamp: datetime = field(init=False, default_factory=lambda: datetime.now(timezone.utc))


# Sync or async callable that accepts an Event.
Handler = Callable[[Event], Any]


class EventBus:
    """Central event bus shared across all plugins.

    Do not instantiate directly — use the module-level ``bus`` singleton.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._wildcard: list[Handler] = []
        # plugin_id → list of service value strings; populated by PluginLoader
        self.plugin_services: dict[str, list[str]] = {}

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, event_name: str, handler: Handler) -> None:
        """Register *handler* for a specific event name."""
        self._subscribers[event_name].append(handler)
        logger.debug("Subscribed %s → %s", handler.__qualname__, event_name)

    def subscribe_all(self, handler: Handler) -> None:
        """Register *handler* for every event (wildcard). Prefer ``@on_any``."""
        self._wildcard.append(handler)

    def unsubscribe(self, event_name: str, handler: Handler) -> None:
        """Remove *handler* from the subscriber list for *event_name*. No-op if not registered."""
        self._subscribers[event_name] = [
            h for h in self._subscribers[event_name] if h is not handler
        ]

    # ------------------------------------------------------------------
    # Emission
    # ------------------------------------------------------------------

    def _inject_services(self, event: Event) -> None:
        # Attach the emitting plugin's declared services so handlers can inspect
        # capabilities without having to look up the plugin registry themselves.
        # setdefault preserves an explicit "services" key if the caller set one.
        frame = inspect.currentframe()
        # walk past _inject_services and emit/emit_async to the actual caller
        for _ in range(2):
            frame = frame.f_back if frame else None
        while frame:
            local_self = frame.f_locals.get("self")
            plugin_id = getattr(local_self, "plugin_id", None)
            if plugin_id:
                event.source = f"{plugin_id}.{frame.f_code.co_name}"
                break
            frame = frame.f_back
        source_plugin = event.source.split(".")[0]
        if source_plugin in self.plugin_services:
            event.payload.setdefault("services", self.plugin_services[source_plugin])
        event.payload.setdefault("request_id", get_request_id())

    def emit(self, event: Event) -> list[Any]:
        """Emit *event* to all matching subscribers.

        Sync handlers run inline and their return values are collected into the
        returned list.  Async handlers are fire-and-forget (no result collected).
        Prefer ``emit_async`` in async contexts when you need to await handler
        results.  Exceptions are caught and logged; failed handlers contribute
        nothing to the result list.
        """
        self._inject_services(event)
        handlers = list(self._subscribers.get(event.name, [])) + list(self._wildcard)
        results: list[Any] = []
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        # No running loop (e.g. called from a sync context outside asyncio).
                        asyncio.run(result)
                else:
                    results.append(result)
            except Exception:
                logger.exception("Handler %s raised on event %s", handler.__qualname__, event.name)
        return results

    async def emit_async(self, event: Event) -> list[Any]:
        """Emit *event*, await every handler, and return all results.

        Both sync and async handlers contribute their return value to the list.
        Exceptions are caught and logged; failed handlers contribute nothing.
        """
        self._inject_services(event)
        handlers = list(self._subscribers.get(event.name, [])) + list(self._wildcard)
        results: list[Any] = []
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    result = await result
                results.append(result)
            except Exception:
                logger.exception("Handler %s raised on event %s", handler.__qualname__, event.name)
        return results


# Module-level default bus – plugins import this directly
bus = EventBus()
