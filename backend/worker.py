"""Dedicated Vercel Daemon entry point for Redis event consumers."""

import asyncio
import os
import signal

# The HTTP service disables these loops in production; this dedicated daemon
# owns them so they remain available when request-driven containers scale down.
os.environ["SENTINEL_RUN_EVENT_WORKERS"] = "true"

from backend.gateway import app, gateway_lifespan  # noqa: E402


async def main() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for stop_signal in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(stop_signal, stop.set)

    async with gateway_lifespan(app):
        await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
