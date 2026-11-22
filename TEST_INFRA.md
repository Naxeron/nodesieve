# Test Infrastructure

## Principles

- **Observable behaviour.** Tests check files and their permissions, HTTP responses,
  return codes and log messages.
- **Offline execution.** Tests use fixtures and loopback servers for providers and
  subscriptions. Core integration tests run when a local `./mihomo`, `./xray` or
  `xray` on PATH is available. The suite rejects attempts to download a core.
- **Workspace rules** (`.agents/AGENTS.md`): stream teardown bounded by a timeout, ports
  from the kernel (`bind(('127.0.0.1', 0))`), single-attempt caches.

## Layout

```
tests/
├── conftest.py                 # An empty temporary project directory per test (see below)
├── test_android.py             # Android: node servers resolved through Android's resolver and handed
│                               # to Mihomo in its hosts section, also with the real binary
├── test_cli.py                 # Actions, options and the combinations that are refused
├── test_concurrency.py         # The workspace rules, also under load
├── test_config.py              # Settings: load, save, malformed values
├── test_dependencies.py        # Memory detection and CLI startup without psutil
├── test_feed.py                # The feed's files, the feed command, serve and its CLI
├── test_fetcher.py             # Which subscription URLs are asked, decoding their payloads
├── test_hysteria2.py           # Both Hysteria 2 URI schemes, core options, port ranges and QUIC scan preparation
├── test_location.py            # GeoIP consensus, the providers' requests and answers
├── test_main_routing.py        # Main-pool location policy and candidate selection
├── test_mihomo_batch.py        # One core instance per batch of nodes, through Mihomo: refused and
│                               # crashing nodes set aside, lost instances, scan limits; a stand-in for
│                               # Mihomo and the real binary
├── test_multiplexing.py        # use_mux: a node is checked without multiplexing and keeps it, up to
│                               # the feed's Clash profile, only if its server answers through it,
│                               # which only a scan through Mihomo asks
├── test_parsers.py             # Share links to Mihomo proxies, node names
├── test_routing_pipeline.py    # Steer scans write the local report and feed
├── test_routing_ui.py          # Routing menu and routing CLI options
├── test_steer_export.py        # Steer main pool ranking and its redacted report
├── test_sub_cache.py           # Subscription cache: fallback to the last good payload, also against a
│                               # local HTTP server that fails
├── test_tester.py              # NodeTester: TCP ping, IP resolution, the IP check, speedtest
└── test_xray_core.py           # Xray: links to outbounds, its configuration and log, the download and
                                # its SHA-256, batches through a stand-in and the real binary, and both cores
                                # relaying through a local Hysteria 2 server
```

## Running

```bash
python -m pytest
```

Tests that use psutil skip when it is unavailable.

## Project Directory Isolation

The checker writes its output into the project directory (`feed/`, `crashed_nodes.txt`,
`sub_cache/`). `tests/conftest.py` points `PROJECT_ROOT` in every module that builds such
paths at an empty temporary directory for each test, and fails the session, listing the
files, if any file in the real project directory changed during the run. A module that
starts building paths from `PROJECT_ROOT` belongs in `_PROJECT_ROOT_USERS` there.
