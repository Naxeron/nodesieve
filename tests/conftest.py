"""Shared test setup."""

import pytest

from proxy_sites.core.fetcher import NodeFetcher


@pytest.fixture(autouse=True)
def _isolated_sub_cache(tmp_path_factory, monkeypatch):
    """Give every test an empty subscription cache outside the project directory."""
    monkeypatch.setattr(NodeFetcher, "cache_dir", str(tmp_path_factory.mktemp("sub_cache")))
