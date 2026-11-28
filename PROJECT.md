# nodesieve

## Architecture

`nodesieve` qualifies proxy nodes by their exit IP alone — no individual website is
probed — and publishes the working ones as a subscription feed. On OpenWrt the checks
run directly on the router through its own connection. The same pipeline runs locally
on a computer or in Termux on Android.

```
[Raw Subscriptions] (a failed or empty download falls back to that subscription's last good copy in sub_cache/)
       │
       ▼
[Phase 0: TCP Reachability Filter] (raw TCP connect, timeout 1.5s, Hysteria 2 proceeds to Phase 1 over QUIC)
       │
       ▼
[Phase 1: IP Check] (local core instances, Xray or Mihomo, up to 32 nodes each, a listener per node)
       ├── Exit IPv4/IPv6, country and latency via Cloudflare trace
       ├── Drop: no outbound connectivity, exit IP equal to this host's IP (leak)
       ├── Mihomo target: reject RU/BY/CN/IR/KP/SY/CU exits, apply allowed_countries
       ├── Mihomo target, through Mihomo: a qualifying node keeps multiplexing (use_mux) only if it answers a
       │   request through it; through Xray, which has no sing-mux, no node keeps it
       └── Steer target: GeoIP consensus of 16 providers per IP family (location.py) against routing.main
       │
       ├──────────────► Steer target: select_main_pool: every qualifying node, ranked by agreement,
       │                reports, latency; steer-output/routing-report.json, without credentials
       ▼ (Mihomo target)
[Phase 2: Speedtest] (keep nodes reaching min_speed_percent of the fastest, then take up to 30 in rank order)
       │
       ▼
[Subscription Feed] (feed/: share links, the same in base64, a Clash/Mihomo profile)
       ├── A scan without results leaves the feed as it was
       ├── Optional feed_command after a feed update (e.g. refresh Steer's subscription on the router)
       └── Served by `python -m nodesieve serve`, or by uhttpd when configured to serve feed_dir
```

## Interface Contracts

### `NodeTester` ↔ `dashboard.py`
- `class NodeTester`:
  - `async def async_check_tcp_node(node, timeout=1.5) -> Optional[str]`: Phase 0 checks TCP reachability for TCP protocols and passes valid Hysteria 2 nodes to the core for their first network check.
  - `def check_links(node) -> Optional[Tuple[str, Optional[str]]]`: What the IP check needs the local core to serve for a node: the link it is checked with (without multiplexing where `use_mux` applies) and the same node with multiplexing for the probe, or `None` for no probe (Steer, a core other than Mihomo, or no multiplexing). `None` instead of the pair for a node turned away before any core is needed.
  - `async def test_node_full(idx, node, endpoint=None) -> Optional[Tuple[str, float, str]]`: Phase 1 IP check through `endpoint`, the node's listener on a shared core instance, or through an instance of its own when there is none. Returns `(relabelled_node, latency_ms, tested_node)` or `None`; the outcome, including a drop reason, is recorded in `node_metadata`. The node is checked without multiplexing; when `use_mux` applies to it and its server does not answer through sing-mux, or the core is not Mihomo and so can't ask, the relabelled link is marked `smux=0`, which `node_url_to_mihomo_dict` reads as "no multiplexing" for the speedtest and the feed's Clash profile. Before it puts a failure down to the node it calls `ensure_alive()`, which raises `CoreInstanceLost` with `retry` when a shared instance has exited; the node is then to be checked again alone.
  - `def speedtest_links(node)` / `async def speedtest_node(idx, node, timeout, endpoint=None) -> Optional[Tuple[str, float, float]]`: The same for the speedtest. Returns `(relabelled_node, bytes_per_second, location_score)`.
  - `async def fetch_location(base_port, ipv4_ip, ipv6_ip) -> dict`: `location.probe_location` through the node's listener, six nodes at once; the families the trace found must have a consensus.

### `batch.py` ↔ `tester.py` / `dashboard.py`
- `core_for(config) -> ProxyCore`: the core of the `core` setting, `"xray"` (default) or `"mihomo"`; `setup_core(config)` also puts its binary in place, downloading it when the project directory has none.
- `class CoreBatch(nodes: List[BatchNode], config, temp_prefix)`: async context manager; one instance of the core serving `BatchNode(link, mux_link=None, idx=0, total=0)` each through a mixed listener on 127.0.0.1 pinned to the node's proxy, with nothing else going anywhere (`ProxyCore.render`). On Android the servers' addresses from Android's resolver go into one `hosts` section. `endpoints[i]` is node i's `NodeEndpoint` (`port`, `proxy_url`, `error`, `exception`, `mux`, `shared`, `async ensure_alive()`).
  - Start: an extra listener, pinned to an HTTP proxy that leads back to nodesieve, tells when the core relays: Mihomo opens listeners before it relays and closes what arrives in between, and Xray and Mihomo 1.19 dial that proxy only once the probe sent a line, dropping what came with the answer to their CONNECT, so the token answers the line. The core's output goes to a log in the instance's directory, read on failure.
  - A proxy the core refuses (Mihomo: `Parse config error: proxy N: …`; Xray: `failed to build outbound config with tag node-N`) is set aside with that reason and recorded with `record_crash` (`crashed_nodes.txt`, and on screen for a numbered node); the rest start without it. An exit that names no proxy halves the batch until the node is found. A listener whose port was taken meanwhile gets new ports (twice). A core that runs but never relays fails the batch's nodes without halving. A link the core has no proxy for gets the error and starts nothing.
- `class CoreRunner(node, config, temp_prefix, node_idx, total_nodes, endpoint=None)`: A node's proxy for one check (`port`, `proxy_url`, `ensure_alive()`). With an endpoint it uses the batch's instance and leaves it running; without, it starts a one-node batch and stops it on exit.
- `async def run_in_batches(jobs, links, check, on_result, *, config, workers, total_nodes, temp_prefix, error_context, nodes_per_instance=None)`: Runs `check(idx, node, endpoint)` for each `(idx, node)` job, `workers` at once, through `CoreBatch`es of up to `NODES_PER_INSTANCE` consecutive jobs (or `nodes_per_instance` when given, e.g. sequential speedtests sharing one instance) and at most `ResourceLimits.core_instances(workers)` of them at once (one at a time when `nodes_per_instance > workers`). `links` is `check_links` or `speedtest_links`. `on_result(idx, node, result)` gets each job's result once, `None` if the check raised. Jobs whose check raised `CoreInstanceLost` with `retry` are checked again, each in a batch of its own.
- `ResourceLimits` (`core/limits.py`): `get_max_safe_workers(config)` budgets `mem_per_worker` (8 MB) per node and `CORE_INSTANCE_MB` (24) per instance, leaving 500 MB, at most 256 nodes (64 on Android); `core_instances(workers) -> (nodes_per_instance, instances_at_once)` is `(min(32, workers), ceil(workers / that) + 1)`. Free memory comes from `/proc/meminfo` on Linux and Android, from psutil elsewhere (`logging.get_free_memory_mb`).

### `base.ProxyCore` ↔ `batch.py`: `xray.XrayCore`, `mihomo.MihomoCore`
- `path`, `setup()`: the binary in the project directory, downloaded when absent (Xray: the latest release for the platform, the Android build on Android, checked against the release's SHA-256; Mihomo: the latest alpha); exits when it can't.
- `proxy(link, config)`: the core's proxy for a share link, `ValueError` for one it can't serve (`parsers.xray.node_url_to_xray_outbound`, every option a link gives, FinalMask included; `parsers.mihomo.node_url_to_mihomo_dict`, as for the feed). `named(proxy, name)`, `server(proxy)`, `ready_proxy(port)`.
- `render(served, hosts)`: the configuration serving each `(named proxy, port)` (Xray: a mixed inbound and a routing rule each, a blackhole for the rest, `dns.hosts` with `sockopt.domainStrategy: UseIP` where hosts name the server). `command(work_dir, config_path)`.
- `refused(lines, names)`, `busy(lines, listeners)`, `detail(lines)`: what the core's output says stopped it.

### `location.py` ↔ `tester.py` / `routing.py`
- `async def probe_location(proxy, families, real_ip, timeout=60, client=None) -> dict`: Finds the node's exit address per family with identity services, asks the 16 providers (`LOOKUPS`, MaxMind's and ip2location.com's token flows, Cloudflare's trace) through `proxy`, and returns `location_evidence(...)`: `source: "geoip"`, the consensus, per-family results, `tested_families`, `status`, `ip_leak`.

### `routing.py` ↔ `steer.py` / `dashboard.py`
- `normalize_routing(value) -> dict`: Validates `routing` (`enabled`, `target: "steer"`, `default_policy: "preserve"`, `main.excluded_countries`, `main.allowed_countries`, `main.min_agreement`, `main.min_votes`) and refuses anything else.
- `main_policy_failure(policy, evidence) -> Optional[str]`: Why GeoIP evidence does not satisfy the main policy, or `None`.
- `select_main_pool(candidates, metadata, routing) -> {"policy", "eligible", "excluded"}`: Every qualifying node, ranked.
- `steer.write_routing_report(route, config) -> {"ready", "report_path", "servers", "warnings", "errors"}`: Writes the redacted report; `servers` is the ranked list the Steer pipeline publishes to the feed, empty unless `ready`.

### `feed.py` ↔ `dashboard.py` / `cli.py`
- `write_feed(nodes, config) -> {"written", "count", "left_out", "directory"}`: Replaces the configured `feed_formats` (`links.txt`, `links-base64.txt` and `clash.yaml` by default; `clash.yaml` is skipped if `PyYAML` is absent) in the feed directory, each atomically and only when bytes or mode changed, with the nodes that have a share link supported by Xray or Mihomo (VLESS, Trojan, Shadowsocks, Hysteria 2), in order and without repeated servers. Files are mode 0600, or 0644 when others may enter the directory (uhttpd serves only world-readable files). With none, nothing is written and the previous feed stays. The profile enables multiplexing only for Mihomo-target scans, as `node_url_to_mihomo_dict` reads each link's `smux` marker; `links.txt` drops the marker.
- `feed_server_keys(config) -> list[str] | None`: Ordered `node_key`s currently in the feed, used by `dashboard.publish_feed` to skip `feed_command` when the servers and their order did not change.
- `run_feed_command(config) -> bool | None`: Runs the `feed_command` setting through the shell after `dashboard.publish_feed` changed the feed's server list or order, unless the scan is a dry run. A failure is logged and does not fail the scan.
- `feed_status(config) -> {"count", "written_at"} | None`: The feed apps get now.
- `build_app(config, token)` / `serve_feed(config, token, host, port)`: `GET`/`HEAD /<token>/<file>` for the three files with `profile-update-interval` and `profile-title` headers, 503 before the first feed, 404 for anything else. `cli.py` creates `feed_token` on the first `serve` and saves only that, refusing to save over a settings file it cannot read (`ConfigManager.load(strict=True)`).

## Code Layout

```
nodesieve/
├── __main__.py                      # Entry point: python -m nodesieve
├── config.py                        # Settings file (nodesieve_config.json)
├── constants.py                     # Defaults, paths, the excluded exit countries
├── feed.py                          # Subscription feed (links, base64, Clash profile) and its HTTP server
├── files.py                         # Atomic writes of files holding credentials
├── routing.py                       # Main-pool location policy and candidate selection
├── location.py                      # GeoIP consensus of 16 providers asked through a node's proxy
├── geo.py                           # Country name and IP country lookups
├── logging.py                       # Output, progress, error tracking, free memory
├── core/
│   ├── fetcher.py                   # Subscriptions and their fallback cache
│   ├── base.py                      # What nodesieve needs of a proxy core; release downloads
│   ├── batch.py                     # Local core instances: a batch of nodes each, a listener per node; run_in_batches
│   ├── limits.py                    # Nodes checked at once, core instances, file descriptor limit
│   ├── mihomo.py                    # Mihomo: its binary, configuration and log
│   ├── xray.py                      # Xray: its binary, configuration and log
│   └── tester.py                    # Node tester: TCP ping, IP check, speedtest
├── parsers/                         # Share links to Xray outbounds and Mihomo proxies, node names
├── router/
│   └── steer.py                     # Steer main-pool ranking and its report
└── ui/
    ├── cli.py                       # Command-line actions: check, serve, routing, config
    ├── dashboard.py                 # Scan coordinator
    └── routing.py                   # Steer routing menu
tests/                               # Test suite
```

## Guidelines Adherence (.agents/AGENTS.md)
1. **Async Stream Teardown Safety**: Any network writer teardown must wrap `await writer.wait_closed()` in `asyncio.wait_for(..., timeout=0.2)` or `try/except`.
2. **Ephemeral Subprocess Port Binding**: Dynamic kernel allocation `s.bind(('127.0.0.1', 0))` must be used for any local test proxies or servers. Never use static port increments.
3. **Single-Attempt Cache Pattern**: No falsy collection checks under async locks; use explicit `_attempted = True` flags.
