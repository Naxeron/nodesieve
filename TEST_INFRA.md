# Test Infrastructure

## Principles

- **Observable behaviour.** Tests check files and their permissions, return codes, outputs, and log messages.
- **Offline execution.** Tests use fixtures and loopback servers for providers and subscriptions. Real Xray integration tests run when `./xray` or `xray` on `PATH` is available. The suite rejects core downloads.
- **Workspace rules** (`.agents/AGENTS.md`): stream teardown bounded by a timeout, ports from the kernel (`bind(('127.0.0.1', 0))`), single-attempt caches.

## Layout

```
tests/
├── conftest.py          # Isolated temp project directory per test and download guard
├── test_android.py      # Android DNS resolution into Xray dns.hosts
├── test_cli.py          # CLI actions, overrides, validation, and refused options
├── test_concurrency.py  # Workspace async/port/cache rules under load
├── test_config.py       # Settings load, save, normalization, strict mode
├── test_dependencies.py # Memory detection and running without psutil/PyYAML
├── test_feed.py         # Feed output, permissions, speed cutoffs, and feed_command
├── test_fetcher.py      # Subscription querying and base64 decoding
├── test_hysteria2.py    # Hysteria 2 share links, Xray outbounds, QUIC scan prep
├── test_location.py     # 14-provider GeoIP consensus and proxy probing
├── test_parsers.py      # Shared URI parsing, host/port extraction, node naming
├── test_routing.py      # Location policy, pool ranking, redacted Steer report, pipeline
├── test_sub_cache.py    # Subscription fallback cache against failures and local HTTP server
├── test_tester.py       # NodeTester: TCP ping, Cloudflare trace, Phase 1 check, speedtest
└── test_xray_core.py    # Xray outbounds, binary SHA-256, CoreBatch, run_in_batches,
                         # ResourceLimits, and real-binary HTTP/SOCKS5/Hysteria 2 relay
```

## Running

```bash
python -m pytest
```

## Project Directory Isolation

`tests/conftest.py` points `PROJECT_ROOT` in every module listed in `_PROJECT_ROOT_USERS` at an empty temporary directory per test and fails the session if any file in the real project directory changed during the run.
