"""Fetching subscriptions: which URLs are asked, and how their payloads are decoded."""

import asyncio
import unittest
from unittest.mock import MagicMock

from nodesieve.core.fetcher import NodeFetcher


class TestFreshOnDemandFetcher(unittest.TestCase):
    """Fetching the configured subscriptions; their fallback cache is covered by test_sub_cache.py."""

    def test_fetch_all_queries_only_the_configured_subscriptions(self):
        config = {"subscriptions": ["https://example.com/custom_sub.txt"]}
        fetcher = NodeFetcher(config)

        queried_urls = []

        async def mock_process_url(session, url):
            queried_urls.append(url)
            return ["vless://uuid@1.1.1.1:443#Node1"]

        fetcher._process_url = mock_process_url

        nodes, source_map = asyncio.run(fetcher.fetch_all())
        self.assertEqual(queried_urls, ["https://example.com/custom_sub.txt"])
        self.assertEqual(len(nodes), 1)

    def test_fetcher_deduplicates_duplicate_remote_subscriptions(self):
        """Duplicate subscription URLs in config are requested only once."""
        config = {"subscriptions": ["https://example.com/sub1", "https://example.com/sub1"]}
        fetcher = NodeFetcher(config)
        queried = []

        async def mock_process(session, url):
            queried.append(url)
            return ["vless://uuid@1.1.1.1:443#Node1"]

        fetcher._process_url = mock_process
        nodes, _ = asyncio.run(fetcher.fetch_all())
        self.assertEqual(len(queried), 1)
        self.assertEqual(queried[0], "https://example.com/sub1")

    def test_fetcher_handles_multiline_and_urlsafe_base64_payload(self):
        """_process_url correctly decodes multiline and URL-safe base64 payloads."""
        import base64
        fetcher = NodeFetcher(config={"subscriptions": []})

        raw_nodes = "vless://uuid@1.1.1.1:443?type=tcp#NodeA\nvless://uuid@2.2.2.2:443?type=tcp#NodeB"
        encoded = base64.urlsafe_b64encode(raw_nodes.encode("utf-8")).decode("utf-8")
        # Introduce newlines within base64
        multiline_b64 = encoded[:15] + "\r\n" + encoded[15:]

        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200

        async def async_read():
            return multiline_b64.encode("utf-8")

        mock_resp.read = async_read

        class AsyncContextManager:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_session.get.return_value = AsyncContextManager()
        nodes = asyncio.run(fetcher._process_url(mock_session, "https://example.com/sub"))
        self.assertEqual(len(nodes), 2)


if __name__ == "__main__":
    unittest.main()
