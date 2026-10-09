"""Minimal, explicit plugin hooks for gateway extensions.

Set SENTINEL_GATEWAY_PLUGINS to a comma-separated list of
``package.module:callable`` values.  Each callable receives ``(event, data)``
and may be synchronous or asynchronous.  Hooks are isolated: a plugin error
is logged but cannot take the gateway down.
"""

import importlib
import inspect
import logging
import os
from typing import Any, Callable, List

logger = logging.getLogger(__name__)


class GatewayPluginManager:
    def __init__(self):
        self.plugins: List[Callable[[str, dict[str, Any]], Any]] = []
        for target in filter(None, (item.strip() for item in os.getenv("SENTINEL_GATEWAY_PLUGINS", "").split(","))):
            try:
                module_name, callable_name = target.split(":", 1)
                plugin = getattr(importlib.import_module(module_name), callable_name)
                if not callable(plugin):
                    raise TypeError("plugin target is not callable")
                self.plugins.append(plugin)
                logger.info("Loaded gateway plugin: %s", target)
            except Exception as exc:
                logger.error("Unable to load gateway plugin %s: %s", target, exc)

    async def emit(self, event: str, data: dict[str, Any]):
        for plugin in self.plugins:
            try:
                result = plugin(event, data)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception("Gateway plugin failed during %s", event)
