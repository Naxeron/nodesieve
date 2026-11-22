# Test Infrastructure

## Principles

- **Observable behaviour.** Tests check what a user or another module sees: files and
  their permissions, HTTP answers, return codes, log lines, commands sent to the router.
- **No network, no router.** Providers, subscriptions, the cores and the router's SSH side
  are stand-ins, except where a test says it uses the real `./mihomo` binary or a real
  Xray (`./xray`, or `xray` on PATH; skipped without one) and
  `TestStreamFileToRouterHardware`, which logs in to a router at `192.168.1.1` when one
  answers. A test that tries to download a core fails.
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
├── test_dependencies.py        # Running without psutil and Paramiko, as from requirements-termux.txt
├── test_feed.py                # The feed's files, the feed command, serve and its CLI
├── test_fetcher.py             # Which subscription URLs are asked, decoding their payloads
├── test_hysteria2.py           # Both Hysteria 2 URI schemes, core options, port ranges and QUIC scan preparation
├── test_install_router.py      # install-router: what is sent to the router, and its answers
├── test_location.py            # GeoIP consensus, the providers' requests and answers
├── test_main_routing.py        # Main-pool location policy and candidate selection
├── test_mihomo_batch.py        # One core instance per batch of nodes, through Mihomo: refused and
│                               # crashing nodes set aside, lost instances, scan limits; a stand-in for
│                               # Mihomo and the real binary
├── test_multiplexing.py        # use_mux: a node is checked without multiplexing and keeps it, up to
│                               # the feed's Clash profile, only if its server answers through it,
│                               # which only a scan through Mihomo asks
├── test_parsers.py             # Share links to Mihomo proxies, node names
├── test_router_adversarial.py  # Streaming files to the router over SSH: quoting, payloads; with a
│                               # live router in TestStreamFileToRouterHardware
├── test_router_client.py       # SSH commands and file streams, and Paramiko being optional
├── test_routing_pipeline.py    # Steer scans: the report, the feed, nothing sent to a router
├── test_routing_ui.py          # Routing menu and routing CLI options
├── test_steer_export.py        # Steer main pool ranking and its redacted report
├── test_sub_cache.py           # Subscription cache: fallback to the last good payload, also against a
│                               # local HTTP server that fails
├── test_tester.py              # NodeTester: TCP ping, IP resolution, the IP check, speedtest
└── test_xray_core.py           # Xray: links to outbounds, its configuration and log, the download and
                                # its SHA-256, batches through a stand-in and the real binary, and both cores
                                # relaying through a local Hysteria 2 server
```

The router installer's shell side, `nodesieve/router/openwrt_install.sh`, is checked with
`sh -n` here; it was also run against an OpenWrt 24.10.5 container (install, reinstall,
scans, uhttpd serving the feed, `--remove`).

## Running

```bash
python -m pytest
# Leave a router at 192.168.1.1 alone:
python -m pytest --deselect tests/test_router_adversarial.py::TestStreamFileToRouterHardware
```

The suite also runs with only `requirements-termux.txt` installed: the tests that need
psutil or Paramiko skip.

## Project Directory Isolation

The checker writes its output into the project directory (`feed/`, `crashed_nodes.txt`,
`sub_cache/`). `tests/conftest.py` points `PROJECT_ROOT` in every module that builds such
paths at an empty temporary directory for each test, and fails the session, listing the
files, if any file in the real project directory changed during the run. A module that
starts building paths from `PROJECT_ROOT` belongs in `_PROJECT_ROOT_USERS` there.
