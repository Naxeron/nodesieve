"""Subscription cache: a subscription that cannot be fetched falls back to its last good payload."""

import asyncio
import base64
import json
import os
import stat
import tempfile
import unittest

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestServer

from nodesieve.core.fetcher import NodeFetcher

URL = "https://sub.example.com/api/v1/client/subscribe?token=SECRET123"
NODE_A = "vless://uuid-a@1.1.1.1:443?type=tcp&security=tls#NodeA"
NODE_B = "trojan://secret-b@2.2.2.2:443?sni=b.example#NodeB"
NODE_C = "vless://uuid-c@3.3.3.3:8443?type=ws#NodeC"


def _payload(*nodes: str) -> bytes:
    return base64.b64encode("\n".join(nodes).encode())


class _Response:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    async def read(self) -> bytes:
        return self._body


class _Request:
    """Stands in for aiohttp's request context manager: failures surface on entry, as in aiohttp."""

    def __init__(self, outcome):
        self._outcome = outcome

    async def __aenter__(self):
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome

    async def __aexit__(self, *exc_info):
        return False


class _Session:
    def __init__(self, outcome):
        self._outcome = outcome

    def get(self, url, timeout=None):
        return _Request(self._outcome)


FAILURES = {
    "HTTP 503": _Response(503, b"maintenance"),
    "connection refused": aiohttp.ClientConnectionError("Connection refused"),
    "timeout": asyncio.TimeoutError(),
}


class TestSubscriptionCache(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = temporary.name
        self.cache_dir = os.path.join(self.root, "sub_cache")

    def fetch(self, outcome, url=URL, **config):
        fetcher = NodeFetcher({"use_mux": False, **config})
        fetcher.cache_dir = self.cache_dir
        return asyncio.run(fetcher._process_url(_Session(outcome), url))

    def cache_files(self):
        return sorted(os.listdir(self.cache_dir)) if os.path.isdir(self.cache_dir) else []

    def test_successful_fetch_is_cached_privately(self):
        self.assertEqual(self.fetch(_Response(200, _payload(NODE_A, NODE_B))), [NODE_A, NODE_B])

        files = self.cache_files()
        self.assertEqual(len(files), 1, files)
        self.assertNotIn("SECRET123", files[0])
        self.assertFalse(files[0].endswith(".tmp"))
        with open(os.path.join(self.cache_dir, files[0]), encoding="utf-8") as cache_file:
            entry = json.load(cache_file)
        self.assertEqual(entry["url"], URL)
        self.assertEqual(entry["content"], _payload(NODE_A, NODE_B).decode())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.cache_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.cache_dir, files[0])).st_mode), 0o600)

    def test_failed_fetch_uses_cached_nodes(self):
        self.fetch(_Response(200, _payload(NODE_A, NODE_B)))
        for name, failure in FAILURES.items():
            with self.subTest(name), self.assertLogs("nodesieve", "WARNING") as logs:
                self.assertEqual(self.fetch(failure), [NODE_A, NODE_B])
            self.assertTrue(any("Using 2 cached nodes" in line for line in logs.output), logs.output)

    def test_failed_fetch_without_cache_returns_nothing(self):
        for name, failure in FAILURES.items():
            with self.subTest(name):
                self.assertEqual(self.fetch(failure), [])
        self.assertEqual(self.cache_files(), [])

    def test_payload_without_usable_nodes_keeps_previous_cache(self):
        self.fetch(_Response(200, _payload(NODE_A)))
        for body in (b"", b"<html>Service unavailable</html>", b"vmess://unsupported"):
            with self.subTest(body=body):
                self.assertEqual(self.fetch(_Response(200, body)), [NODE_A])
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [NODE_A])

    def test_newer_fetch_replaces_cache(self):
        self.fetch(_Response(200, _payload(NODE_A)))
        self.fetch(_Response(200, _payload(NODE_B, NODE_C)))
        self.assertEqual(len(self.cache_files()), 1)
        self.assertEqual(self.fetch(FAILURES["timeout"]), [NODE_B, NODE_C])

    def test_each_subscription_has_its_own_cache(self):
        other = "https://other.example.org/sub"
        self.fetch(_Response(200, _payload(NODE_A)))
        self.fetch(_Response(200, _payload(NODE_B)), url=other)
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [NODE_A])
        self.assertEqual(self.fetch(FAILURES["HTTP 503"], url=other), [NODE_B])

    def test_unreadable_cache_is_ignored_and_replaced_by_next_good_fetch(self):
        self.fetch(_Response(200, _payload(NODE_A)))
        cache_path = os.path.join(self.cache_dir, self.cache_files()[0])
        for broken in ("not json", "[]", json.dumps({"url": "https://elsewhere/", "fetched_at": 1, "content": NODE_A}),
                       json.dumps({"url": URL, "fetched_at": "yesterday", "content": NODE_A}),
                       json.dumps({"url": URL, "fetched_at": 1, "content": None})):
            with self.subTest(broken=broken):
                with open(cache_path, "w", encoding="utf-8") as cache_file:
                    cache_file.write(broken)
                with self.assertLogs("nodesieve", "WARNING") as logs:
                    self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [])
                self.assertTrue(any("Ignoring unreadable cache" in line for line in logs.output), logs.output)

        self.fetch(_Response(200, _payload(NODE_B)))
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [NODE_B])

    def test_cache_write_failure_does_not_fail_the_fetch(self):
        blocker = os.path.join(self.root, "not-a-directory")
        with open(blocker, "w", encoding="utf-8") as blocker_file:
            blocker_file.write("")
        self.cache_dir = os.path.join(blocker, "sub_cache")
        with self.assertLogs("nodesieve", "WARNING") as logs:
            self.assertEqual(self.fetch(_Response(200, _payload(NODE_A))), [NODE_A])
        self.assertTrue(any("Could not cache subscription" in line for line in logs.output), logs.output)

    def test_cached_payload_is_parsed_with_current_settings(self):
        self.fetch(_Response(200, _payload(NODE_A)), use_mux=False)
        nodes = self.fetch(FAILURES["HTTP 503"], use_mux=True)
        self.assertEqual(nodes, [NODE_A.replace("?", "?smux=1&", 1)])


class TestFetchAllWithLocalServer(unittest.IsolatedAsyncioTestCase):
    """fetch_all against a real HTTP server: fresh, failing and unreachable subscriptions."""

    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cache_dir = os.path.join(temporary.name, "sub_cache")
        self.flaky_status = 200

        async def flaky(request):
            if self.flaky_status != 200:
                return web.Response(status=self.flaky_status, text="maintenance")
            return web.Response(body=_payload(NODE_A, NODE_B))

        async def steady(request):
            return web.Response(body=_payload(NODE_C))

        app = web.Application()
        app.router.add_get("/flaky", flaky)
        app.router.add_get("/steady", steady)
        self.server = TestServer(app)  # binds a free port from the kernel
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)
        self.flaky_url = str(self.server.make_url("/flaky"))
        self.steady_url = str(self.server.make_url("/steady"))

    async def fetch_all(self):
        fetcher = NodeFetcher({
            "subscriptions": [self.flaky_url, self.steady_url],
            "use_mux": False,
        })
        fetcher.cache_dir = self.cache_dir
        return await fetcher.fetch_all()

    async def test_failing_subscription_falls_back_while_others_stay_fresh(self):
        nodes, _ = await self.fetch_all()
        self.assertEqual(nodes, [NODE_A, NODE_B, NODE_C])

        self.flaky_status = 503
        nodes, source_map = await self.fetch_all()
        self.assertEqual(nodes, [NODE_A, NODE_B, NODE_C])
        self.assertEqual(source_map[NODE_A], self.flaky_url)
        self.assertEqual(source_map[NODE_C], self.steady_url)

        await self.server.close()
        nodes, _ = await self.fetch_all()
        self.assertEqual(nodes, [NODE_A, NODE_B, NODE_C])


if __name__ == "__main__":
    unittest.main()
