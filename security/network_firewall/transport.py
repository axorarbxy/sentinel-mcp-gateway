"""HTTPX transport that connects only to a DNS address already checked by policy."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from typing import Any

import httpcore
import httpx


class _PinnedNetworkStream(httpcore.AsyncNetworkStream):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            operation = self._reader.read(max_bytes)
            return await asyncio.wait_for(operation, timeout) if timeout is not None else await operation
        except asyncio.TimeoutError as exc:
            raise httpcore.ReadTimeout("Pinned connection read timed out") from exc
        except OSError as exc:
            raise httpcore.ReadError("Pinned connection read failed") from exc

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        try:
            self._writer.write(buffer)
            operation = self._writer.drain()
            if timeout is not None:
                await asyncio.wait_for(operation, timeout)
            else:
                await operation
        except asyncio.TimeoutError as exc:
            raise httpcore.WriteTimeout("Pinned connection write timed out") from exc
        except OSError as exc:
            raise httpcore.WriteError("Pinned connection write failed") from exc

    async def aclose(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except OSError:
            pass

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> "_PinnedNetworkStream":
        try:
            operation = self._writer.start_tls(
                ssl_context,
                server_hostname=server_hostname,
                ssl_handshake_timeout=timeout,
            )
            if timeout is not None:
                await asyncio.wait_for(operation, timeout)
            else:
                await operation
        except asyncio.TimeoutError as exc:
            raise httpcore.ConnectTimeout("Pinned connection TLS handshake timed out") from exc
        except (OSError, ssl.SSLError) as exc:
            raise httpcore.ConnectError("Pinned connection TLS handshake failed") from exc
        return self

    def get_extra_info(self, info: str) -> Any:
        return self._writer.get_extra_info(info)


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, hostname: str, address: str) -> None:
        self._hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        self._address = str(ipaddress.ip_address(address))

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple] | None = None,
    ) -> _PinnedNetworkStream:
        normalized = host.decode("ascii").lower().rstrip(".") if isinstance(host, bytes) else str(host).lower().rstrip(".")
        if normalized != self._hostname:
            raise httpcore.ConnectError("Unvalidated outbound hostname")
        try:
            operation = asyncio.open_connection(
                host=self._address,
                port=port,
                local_addr=(local_address, 0) if local_address else None,
            )
            reader, writer = await (
                asyncio.wait_for(operation, timeout) if timeout is not None else operation
            )
        except asyncio.TimeoutError as exc:
            raise httpcore.ConnectTimeout("Pinned connection timed out") from exc
        except OSError as exc:
            raise httpcore.ConnectError("Pinned connection failed") from exc

        stream = _PinnedNetworkStream(reader, writer)
        try:
            raw_socket = writer.get_extra_info("socket")
            if raw_socket is not None and socket_options:
                for option in socket_options:
                    raw_socket.setsockopt(*option)
            return stream
        except OSError as exc:
            await stream.aclose()
            raise httpcore.ConnectError("Pinned connection socket configuration failed") from exc

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple] | None = None,
    ) -> _PinnedNetworkStream:
        del path, timeout, socket_options
        raise httpcore.ConnectError("Unix sockets are not allowed by the network firewall")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, response: httpcore.Response, request: httpx.Request) -> None:
        self._response = response
        self._request = request

    async def __aiter__(self):
        try:
            async for chunk in self._response.stream:
                yield chunk
        except (httpcore.NetworkError, httpcore.ProtocolError) as exc:
            raise httpx.TransportError("Pinned upstream connection failed", request=self._request) from exc

    async def aclose(self) -> None:
        await self._response.aclose()


class PinnedHTTPXTransport(httpx.AsyncBaseTransport):
    """Keep the original host for HTTP Host/TLS SNI while pinning the TCP peer IP."""

    def __init__(
        self, *, hostname: str, address: str, timeout_seconds: float, max_connections: int,
    ) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=max_connections,
            max_keepalive_connections=min(20, max_connections),
            network_backend=_PinnedNetworkBackend(hostname, address),
        )
        self._timeout_seconds = timeout_seconds

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        extensions = dict(request.extensions)
        configured = dict(extensions.get("timeout", {}))
        for key in ("connect", "pool"):
            configured[key] = min(configured.get(key) or self._timeout_seconds, self._timeout_seconds)
        extensions["timeout"] = configured
        try:
            core_request = httpcore.Request(
                method=request.method,
                url=str(request.url).encode("ascii"),
                headers=request.headers.raw,
                content=await request.aread(),
                extensions=extensions,
            )
            core_response = await self._pool.handle_async_request(core_request)
        except httpcore.ConnectTimeout as exc:
            raise httpx.ConnectTimeout("Pinned upstream connection timed out", request=request) from exc
        except httpcore.ReadTimeout as exc:
            raise httpx.ReadTimeout("Pinned upstream response timed out", request=request) from exc
        except httpcore.WriteTimeout as exc:
            raise httpx.WriteTimeout("Pinned upstream request timed out", request=request) from exc
        except httpcore.PoolTimeout as exc:
            raise httpx.PoolTimeout("Pinned upstream connection pool timed out", request=request) from exc
        except (httpcore.NetworkError, httpcore.ProtocolError) as exc:
            raise httpx.TransportError("Pinned upstream connection failed", request=request) from exc
        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_ResponseStream(core_response, request),
            extensions=core_response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
