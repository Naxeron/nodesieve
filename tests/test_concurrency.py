"""Tests for workspace async/concurrency rules: stream teardown, ephemeral ports, single-attempt cache."""

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from nodesieve.core.batch import CoreRunner, PortManager
from nodesieve.geo import GeolocationService
from nodesieve.logging import safe_close_writer


def test_safe_close_writer_live_socket_and_errors():
    async def run():
        await safe_close_writer(None)
        server_writer = None

        async def handle(r, w):
            nonlocal server_writer
            server_writer = w

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        await safe_close_writer(writer, timeout=0.2)
        await safe_close_writer(server_writer, timeout=0.2)
        server.close()
        await server.wait_closed()

        reset = MagicMock()

        async def raise_reset():
            raise ConnectionResetError("reset")

        reset.wait_closed = raise_reset
        await safe_close_writer(reset, timeout=0.2)
        reset.close.assert_called_once()

        broken = MagicMock()
        broken.close.side_effect = BrokenPipeError("broken")
        await safe_close_writer(broken, timeout=0.2)

    asyncio.run(run())


def test_safe_close_writer_50_concurrent_hanging_peers():
    async def run():
        writers = []
        for _ in range(50):
            w = MagicMock()

            async def hang():
                await asyncio.sleep(5.0)

            w.wait_closed = hang
            writers.append(w)
        started = time.monotonic()
        await asyncio.gather(*(safe_close_writer(w, timeout=0.2) for w in writers))
        assert time.monotonic() - started < 0.40
        assert all(w.close.call_count == 1 for w in writers)

    asyncio.run(run())


def test_ephemeral_port_stress_50_concurrent_allocations():
    async def run():
        ports, servers = [], []
        try:
            for _ in range(50):
                p = PortManager.get_free_port()
                assert p > 0 and p not in ports
                ports.append(p)
                servers.append(await asyncio.start_server(lambda r, w: None, "127.0.0.1", p))
            assert len(set(ports)) == 50
        finally:
            for srv in servers:
                srv.close()
                await srv.wait_closed()
            for p in ports:
                PortManager.release_port(p)

    asyncio.run(run())


def test_runner_cleanup_on_aenter_exception():
    async def run():
        before = set(PortManager._allocated_ports)
        runner = CoreRunner("vless://no-server-here#Invalid", config={})
        with pytest.raises(Exception):
            async with runner:
                pass
        assert PortManager._allocated_ports == before and runner.port is None

    asyncio.run(run())


def test_geolocation_service_single_attempt_lock_and_offline_fallback():
    async def run():
        GeolocationService._country_attempted = False
        with patch("aiohttp.ClientSession.get", side_effect=OSError("Network unreachable")) as fetch:
            names = await asyncio.gather(*(GeolocationService.get_country_name("US") for _ in range(50)))
        assert all(n == "United States" for n in names)
        assert fetch.call_count == 1 and GeolocationService._country_attempted
        assert await GeolocationService.get_country_name("TR") == "Türkiye"

    asyncio.run(run())
