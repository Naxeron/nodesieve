"""Subscription cache: failed fetches fall back to the last good payload."""

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
NODE_SS = "ss://YWVzLTEyOC1nY206cHc=@4.4.4.4:8388#NodeSS"


def _payload(*nodes: str) -> bytes:
    return base64.b64encode("\n".join(nodes).encode())


class _Response:
    def __init__(self, status: int, body: bytes):
        self.status, self._body = status, body

    async def read(self) -> bytes:
        return self._body


class _Request:
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
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name
        self.cache_dir = os.path.join(self.root, "sub_cache")

    def fetch(self, outcome, url=URL, **config):
        fetcher = NodeFetcher(config)
        fetcher.cache_dir = self.cache_dir
        return asyncio.run(fetcher._process_url(_Session(outcome), url))

    def cache_files(self):
        return sorted(os.listdir(self.cache_dir)) if os.path.isdir(self.cache_dir) else []

    def test_successful_fetch_cached_privately_and_reused_on_failure(self):
        self.assertEqual(self.fetch(_Response(200, _payload(NODE_A, NODE_B))), [NODE_A, NODE_B])
        files = self.cache_files()
        self.assertEqual(len(files), 1)
        self.assertNotIn("SECRET123", files[0])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.cache_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.cache_dir, files[0])).st_mode), 0o600)

        for name, failure in FAILURES.items():
            with self.subTest(name), self.assertLogs("nodesieve", "WARNING") as logs:
                self.assertEqual(self.fetch(failure), [NODE_A, NODE_B])
            self.assertTrue(any("Using 2 cached nodes" in line for line in logs.output))

    def test_hysteria_and_empty_or_unusable_payloads_preserve_cache(self):
        nodes = ["hy2://pw@node.example/#One", "hysteria2://user:pw@[2001:db8::1]:443,8443/#Two"]
        self.assertEqual(self.fetch(_Response(200, _payload(*nodes))), nodes)
        for bad in (b"hy2://pw@node.example:65536", b"", b"<html>err</html>", b"vmess://unsupported"):
            self.assertEqual(self.fetch(_Response(200, bad)), nodes)
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), nodes)

    def test_failed_fetch_without_cache_returns_nothing(self):
        for failure in FAILURES.values():
            self.assertEqual(self.fetch(failure), [])
        self.assertEqual(self.cache_files(), [])

    def test_unchanged_payload_skips_write_and_newer_replaces_cache(self):
        self.fetch(_Response(200, _payload(NODE_A)))
        path = os.path.join(self.cache_dir, self.cache_files()[0])
        inode = os.stat(path).st_ino
        self.fetch(_Response(200, _payload(NODE_A)))
        self.assertEqual(os.stat(path).st_ino, inode)
        self.fetch(_Response(200, _payload(NODE_B, NODE_C)))
        self.assertEqual(self.fetch(FAILURES["timeout"]), [NODE_B, NODE_C])

    def test_per_subscription_isolation_and_reparse_with_current_settings(self):
        other = "https://other.example.org/sub"
        self.fetch(_Response(200, _payload(NODE_A, NODE_SS)))
        self.fetch(_Response(200, _payload(NODE_B)), url=other)
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [NODE_A])
        self.assertEqual(self.fetch(FAILURES["HTTP 503"], routing={"enabled": True}), [NODE_A, NODE_SS])
        self.assertEqual(self.fetch(FAILURES["HTTP 503"], url=other), [NODE_B])

    def test_unreadable_cache_ignored_and_write_failure_nonfatal(self):
        self.fetch(_Response(200, _payload(NODE_A)))
        path = os.path.join(self.cache_dir, self.cache_files()[0])
        for broken in ("not json", "[]", json.dumps({"url": "https://other/", "fetched_at": 1, "content": NODE_A}),
                       json.dumps({"url": URL, "fetched_at": "bad", "content": NODE_A}),
                       json.dumps({"url": URL, "fetched_at": 1, "content": None})):
            with open(path, "w", encoding="utf-8") as f:
                f.write(broken)
            with self.assertLogs("nodesieve", "WARNING"):
                self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [])
        self.fetch(_Response(200, _payload(NODE_B)))
        self.assertEqual(self.fetch(FAILURES["HTTP 503"]), [NODE_B])

        blocker = os.path.join(self.root, "file")
        open(blocker, "w").close()
        self.cache_dir = os.path.join(blocker, "sub_cache")
        with self.assertLogs("nodesieve", "WARNING"):
            self.assertEqual(self.fetch(_Response(200, _payload(NODE_A))), [NODE_A])


class TestFetchAllWithLocalServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache_dir = os.path.join(tmp.name, "sub_cache")
        self.flaky_status = 200

        async def flaky(request):
            return (web.Response(status=self.flaky_status, text="err") if self.flaky_status != 200
                    else web.Response(body=_payload(NODE_A, NODE_B)))

        async def steady(request):
            return web.Response(body=_payload(NODE_C))

        app = web.Application()
        app.router.add_get("/flaky", flaky)
        app.router.add_get("/steady", steady)
        self.server = TestServer(app)
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)

    async def test_failing_subscription_falls_back_while_others_stay_fresh(self):
        flaky_url, steady_url = str(self.server.make_url("/flaky")), str(self.server.make_url("/steady"))
        fetcher = NodeFetcher({"subscriptions": [flaky_url, steady_url]})
        fetcher.cache_dir = self.cache_dir
        nodes, _ = await fetcher.fetch_all()
        self.assertEqual(nodes, [NODE_A, NODE_B, NODE_C])
        self.flaky_status = 503
        nodes, src = await fetcher.fetch_all()
        self.assertEqual((nodes, src[NODE_A], src[NODE_C]), ([NODE_A, NODE_B, NODE_C], flaky_url, steady_url))
        await self.server.close()
        self.assertEqual((await fetcher.fetch_all())[0], [NODE_A, NODE_B, NODE_C])
