"""Pub/sub event bus for the plugin system.

The module-level ``bus`` singleton is the shared channel; import it directly:

    from plugin_system.core.events import bus, Event

Plugins subscribe via ``bus.subscribe`` / ``bus.unsubscribe`` or the decorator
helpers in ``plugin_system.core.decorators`` (``@on``, ``@on_any``).

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

Service injection
-----------------
``emit`` / ``emit_async`` automatically set ``event.payload["services"]`` to
the emitting plugin's declared service list (from ``plugin_services``) unless
the caller already set that key.

Error isolation
---------------
Exceptions raised by handlers are caught and logged; they never propagate to
the emitter or abort remaining handlers.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """A single bus message.

    ``name`` is the event type identifier subscribers listen on (e.g.
    ``"plugin.loaded"``).  ``source`` is the plugin_id or system component
    that emitted the event.  ``payload`` carries arbitrary event data.
    """
    name: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)


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
        if event.source in self.plugin_services:
            event.payload.setdefault("services", self.plugin_services[event.source])

    def emit(self, event: Event) -> None:
        """Emit *event* to all matching subscribers.

        Sync handlers run inline.  Async handlers are fire-and-forget: scheduled
        as tasks when a loop is already running, or driven to completion via
        ``asyncio.run`` otherwise.  Prefer ``emit_async`` in async contexts when
        you need to await handler results.
        """
        self._inject_services(event)
        handlers = list(self._subscribers.get(event.name, [])) + list(self._wildcard)
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
            except Exception:
                logger.exception("Handler %s raised on event %s", handler.__qualname__, event.name)

    async def emit_async(self, event: Event) -> None:
        """Emit *event* and await every handler before returning."""
        self._inject_services(event)
        handlers = list(self._subscribers.get(event.name, [])) + list(self._wildcard)
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Handler %s raised on event %s", handler.__qualname__, event.name)


# Module-level default bus – plugins import this directly
bus = EventBus()
