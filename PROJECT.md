# nodesieve

## Architecture

`nodesieve` qualifies proxy nodes by their exit IP alone — no individual website is
probed — and publishes the working ones as a subscription feed. On OpenWrt the checks
run directly on the router through its own connection. The same pipeline runs locally
on a computer or in Termux on Android.

```
[Raw Subscriptions] (failed or empty download falls back to last good copy in sub_cache/)
       │
       ▼
[Phase 0: TCP Reachability Filter] (raw TCP connect, timeout 1.5s; Hysteria 2 skips to Phase 1 QUIC)
       │
       ▼
[Phase 1: IP Check] (local Xray instances, up to 32 nodes each, one mixed listener per node)
       ├── Exit IPv4/IPv6, country and latency via Cloudflare trace
       ├── Drop: no outbound connectivity, exit IP equal to host's real IP (leak)
       ├── Speed mode: reject RU/BY/CN/IR/KP/SY/CU exits, apply allowed_countries
       └── Location mode: GeoIP consensus of 14 providers per IP family (location.py) against routing.main
       │
       ├──────────────► Location mode: select_main_pool + write_routing_report -> every qualifying node,
       │                ranked by agreement, votes, latency; steer-output/routing-report.json (redacted)
       ▼ (Speed mode)
[Phase 2: Speedtest] (sequential through shared Xray batches; keep nodes >= min_speed_percent of fastest, top 30)
       │
       ▼
[Subscription Feed] (feed/: links.txt and links-base64.txt)
       ├── A scan without results leaves the existing feed untouched
       ├── Optional feed_command after server list/order changes (e.g. refresh Steer on OpenWrt)
       └── Served statically (e.g. OpenWrt uhttpd pointing at feed_dir)
```

## Interface Contracts

### `NodeTester` ↔ `dashboard.py`
- `async_check_tcp_node(node, timeout=1.5) -> Optional[str]`: Phase 0 TCP ping; valid Hysteria 2 links pass through to Phase 1 QUIC.
- `check_link(node) -> Optional[str]` / `speedtest_link(node) -> Optional[str]`: Link Xray should serve (normalizing VLESS `encryption=none`), or `None` when filtered out before Xray.
- `test_node_full(idx, node, endpoint=None) -> Optional[Tuple[str, float, str]]`: Phase 1 exit IP, leak, and country/GeoIP check through `endpoint` (shared Xray) or a single-node `CoreRunner`. Calls `ensure_alive()` before attributing failures to a node, raising `CoreInstanceLost(retry=True)` when a shared instance exited.
- `speedtest_node(idx, node, timeout, endpoint=None) -> Optional[Tuple[str, float]]`: Phase 2 sustained throughput check returning `(relabelled_node, bytes_per_second)`.
- `fetch_location(base_port, ipv4_ip, ipv6_ip) -> dict`: Runs `location.probe_location` through the node's listener (up to 6 nodes concurrently).

### `batch.py` / `xray.py` / `limits.py`
- `XrayCore` (`core/xray.py`): binary download with release SHA-256 verification, outbound conversion (`parsers.xray.node_url_to_xray_outbound`), batch config rendering (`render_xray_config` with per-listener routing rules, blackhole fallback, and Android `dns.hosts`), and failure log parsing (`refused`, `busy`, `detail`).
- `CoreBatch(nodes, config, temp_prefix)`: async context manager serving `BatchNode(link, idx, total)` on mixed `127.0.0.1` listeners. Waits for the ready proxy to relay, isolates refused/crashing nodes (by log tag or binary halving), retries busy ports twice, and logs crashes to `crashed_nodes.txt`.
- `CoreRunner` / `run_in_batches`: runs per-node checks through shared `CoreBatch` instances (`ResourceLimits.core_instances`), retrying jobs lost to a shared crash individually.
- `ResourceLimits` (`core/limits.py`): budgets `mem_per_worker` (8 MB) per node and `CORE_INSTANCE_MB` (24 MB) per instance above 500 MB reserve, capped at 256 workers (64 on Android).

### `location.py` & `routing.py`
- `probe_location(proxy, families, real_ip, timeout=60, client=None) -> dict`: discovers per-family exit IPs and queries 14 GeoIP providers (13 `LOOKUPS` + Cloudflare trace) through `proxy`.
- `normalize_routing`, `main_policy_failure`, `select_main_pool`, `write_routing_report`: validates `routing` policy, ranks qualifying nodes by agreement, report count, and latency, and writes a credential-redacted JSON report.

### `feed.py`
- `write_feed(nodes, config)`: atomically writes configured `feed_formats` (`links.txt`, `links-base64.txt`) when bytes or permissions changed (`0600`, or `0644` when directory is world-traversable for `uhttpd`).
- `feed_server_keys`, `run_feed_command`, `feed_status`: detects server list/order changes, runs `feed_command` when changed (unless `--dry-run`), and reports kept feed status.

## Code Layout

```
nodesieve/
├── __main__.py          # Entry point: python -m nodesieve
├── config.py            # Settings load/save/normalization (nodesieve_config.json)
├── constants.py         # Defaults, paths, geoblocked exit countries
├── feed.py              # Subscription feed (links.txt, links-base64.txt) and feed_command
├── files.py             # Atomic writes with explicit permissions
├── geo.py               # Country code to name lookup with offline fallback
├── location.py          # 14-provider GeoIP consensus through a node's proxy
├── logging.py           # Logging, progress bar, error tracking, free memory
├── routing.py           # Main-pool location policy, ranking, redacted Steer report
├── core/
│   ├── batch.py         # Local Xray batches, PortManager, CoreRunner, run_in_batches
│   ├── fetcher.py       # Subscription download, decoding, and fallback cache
│   ├── limits.py        # Memory and file-descriptor worker bounds
│   ├── tester.py        # TCP ping, exit IP/GeoIP check, and speedtest
│   └── xray.py          # Xray binary download, config rendering, and log parsing
├── parsers/
│   ├── base.py          # Shared URI parsing, validation, host/port, node naming
│   ├── hysteria2.py     # Hysteria 2 share links and port ranges
│   └── xray.py          # Share links to Xray outbounds (VLESS, Trojan, SS, Hysteria 2)
└── ui/
    ├── cli.py           # CLI actions: check, config
    └── dashboard.py     # Scan coordinator
tests/                   # Test suite
```

## Guidelines Adherence (.agents/AGENTS.md)
1. **Async Stream Teardown Safety**: Any network writer teardown must wrap `await writer.wait_closed()` in `asyncio.wait_for(..., timeout=0.2)` or `try/except`.
2. **Ephemeral Subprocess Port Binding**: Dynamic kernel allocation `s.bind(('127.0.0.1', 0))` must be used for any local test proxies or servers. Never use static port increments.
3. **Single-Attempt Cache Pattern**: No falsy collection checks under async locks; use explicit `_attempted = True` flags.
