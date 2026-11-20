# nodesieve

## Architecture
`nodesieve` qualifies proxy nodes by their exit IP alone — no individual website is
probed — and publishes the working ones as a subscription feed. It runs where the nodes
are used, so the checks go through that device's own connection: a computer, Termux on
Android, or an OpenWrt router that `install-router` set up.

```
[Raw Subscriptions] (a failed or empty download falls back to that subscription's last good copy in sub_cache/)
       │
       ▼
[Phase 0: TCP Reachability Filter] (raw TCP connect, timeout 1.5s)
       │
       ▼
[Phase 1: IP Check] (local Mihomo instances, up to 32 nodes each, a listener per node)
       ├── Exit IPv4/IPv6, country and latency via Cloudflare trace
       ├── Drop: no outbound connectivity, exit IP equal to this host's IP (leak)
       ├── Mihomo target: reject RU/BY/CN/IR/KP/SY/CU exits, apply allowed_countries
       ├── Mihomo target: a qualifying node keeps multiplexing (use_mux) only if it answers a request through it
       └── Steer target: GeoIP consensus of 16 providers per IP family (location.py) against routing.main
       │
       ├──────────────► Steer target: select_main_pool: every qualifying node, ranked by agreement,
       │                reports, latency; steer-output/routing-report.json, without credentials
       ▼ (Mihomo target)
[Phase 2: Speedtest] (throughput of the working nodes; the 30 fastest are kept)
       │
       ▼
[Subscription Feed] (feed/: share links, the same in base64, a Clash/Mihomo profile)
       ├── A scan without results leaves the feed as it was
       ├── feed_command after a scan that updated it (on the router: Steer fetches its subscription)
       └── Served by `python -m nodesieve serve`, or by the router's uhttpd under /www/nodesieve/<token>/
```

## Interface Contracts

### `NodeTester` ↔ `dashboard.py`
- `class NodeTester`:
  - `async def async_check_tcp_node(node, timeout=1.5) -> Optional[str]`: Phase 0 TCP reachability.
  - `def check_links(node) -> Optional[Tuple[str, Optional[str]]]`: What the IP check needs a local Mihomo to serve for a node: the link it is checked with (without multiplexing where `use_mux` applies) and the same node with multiplexing for the probe, or `None` for no probe (Steer, or no multiplexing). `None` instead of the pair for a node turned away before any Mihomo is needed.
  - `async def test_node_full(idx, node, endpoint=None) -> Optional[Tuple[str, float, str]]`: Phase 1 IP check through `endpoint`, the node's listener on a shared Mihomo, or through a Mihomo of its own when there is none. Returns `(relabelled_node, latency_ms, tested_node)` or `None`; the outcome, including a drop reason, is recorded in `node_metadata`. The node is checked without multiplexing; when `use_mux` applies to it and its server does not answer through sing-mux, the relabelled link is marked `smux=0`, which `node_url_to_mihomo_dict` reads as "no multiplexing" for the speedtest and the feed's Clash profile. Before it puts a failure down to the node it calls `ensure_alive()`, which raises `MihomoInstanceLost` with `retry` when a shared Mihomo has exited; the node is then to be checked again alone.
  - `def speedtest_links(node)` / `async def speedtest_node(idx, node, timeout, endpoint=None) -> Optional[Tuple[str, float, float]]`: The same for the speedtest. Returns `(relabelled_node, bytes_per_second, location_score)`.
  - `async def fetch_location(base_port, ipv4_ip, ipv6_ip) -> dict`: `location.probe_location` through the node's listener, six nodes at once; the families the trace found must have a consensus.

### `mihomo.py` ↔ `tester.py` / `dashboard.py`
- `class MihomoBatch(nodes: List[BatchNode], config, temp_prefix)`: async context manager; one Mihomo serving `BatchNode(link, mux_link=None, idx=0, total=0)` each through a mixed listener on 127.0.0.1 pinned to the node's proxy, with `MATCH,REJECT` for anything else (`render_batch_config`). On Android the servers' addresses from Android's resolver go into one `hosts` section. `endpoints[i]` is node i's `NodeEndpoint` (`port`, `proxy_url`, `error`, `exception`, `mux`, `shared`, `async ensure_alive()`).
  - Start: an extra listener, pinned to an HTTP proxy that leads back to nodesieve, tells when Mihomo relays: it opens listeners before it relays and closes what arrives in between. Mihomo's output goes to a log in the instance's directory, read on failure.
  - A proxy Mihomo refuses (`Parse config error: proxy N: …`) is set aside with that reason and recorded with `record_crash` (`crashed_nodes.txt`, and on screen for a numbered node); the rest start without it. An exit that names no proxy halves the batch until the node is found. A listener whose port was taken meanwhile gets new ports (twice). A Mihomo that runs but never relays fails the batch's nodes without halving. A link without a Mihomo proxy gets the error and starts nothing.
- `class MihomoRunner(node, config, temp_prefix, node_idx, total_nodes, endpoint=None)`: A node's proxy for one check (`port`, `proxy_url`, `ensure_alive()`). With an endpoint it uses the batch's Mihomo and leaves it running; without, it starts a one-node batch and stops it on exit.
- `async def run_in_batches(jobs, links, check, on_result, *, config, workers, total_nodes, temp_prefix, error_context)`: Runs `check(idx, node, endpoint)` for each `(idx, node)` job, `workers` at once, through `MihomoBatch`es of up to `NODES_PER_INSTANCE` consecutive jobs and at most `ResourceLimits.mihomo_instances(workers)` of them at once. `links` is `check_links` or `speedtest_links`. `on_result(idx, node, result)` gets each job's result once, `None` if the check raised. Jobs whose check raised `MihomoInstanceLost` with `retry` are checked again, each in a batch of its own.
- `ResourceLimits` (`core/limits.py`): `get_max_safe_workers(config)` budgets `mem_per_worker` (8 MB) per node and `MIHOMO_INSTANCE_MB` (24) per instance, leaving 500 MB, at most 256 nodes (64 on Android); `mihomo_instances(workers) -> (nodes_per_instance, instances_at_once)` is `(min(32, workers), ceil(workers / that) + 1)`. Free memory comes from `/proc/meminfo` on Linux and Android, from psutil elsewhere (`logging.get_free_memory_mb`).

### `location.py` ↔ `tester.py` / `routing.py`
- `async def probe_location(proxy, families, real_ip, timeout=60, client=None) -> dict`: Finds the node's exit address per family with identity services, asks the 16 providers (`LOOKUPS`, MaxMind's and ip2location.com's token flows, Cloudflare's trace) through `proxy`, and returns `location_evidence(...)`: `source: "geoip"`, the consensus, per-family results, `tested_families`, `status`, `ip_leak`.

### `routing.py` ↔ `steer.py` / `dashboard.py`
- `normalize_routing(value) -> dict`: Validates `routing` (`enabled`, `target: "steer"`, `default_policy: "preserve"`, `main.excluded_countries`, `main.allowed_countries`, `main.min_agreement`, `main.min_votes`) and refuses anything else.
- `main_policy_failure(policy, evidence) -> Optional[str]`: Why GeoIP evidence does not satisfy the main policy, or `None`.
- `select_main_pool(candidates, metadata, routing) -> {"policy", "eligible", "excluded"}`: Every qualifying node, ranked.
- `steer.write_routing_report(route, config) -> {"ready", "report_path", "servers", "warnings", "errors"}`: Writes the redacted report; `servers` is the ranked list the Steer pipeline publishes to the feed, empty unless `ready`.

### `feed.py` ↔ `dashboard.py` / `cli.py`
- `write_feed(nodes, config) -> {"written", "count", "left_out", "directory"}`: Replaces `links.txt`, `links-base64.txt` and `clash.yaml` in the feed directory, each atomically, with the nodes that have a share link (VLESS, Trojan, Shadowsocks), in order and without repeated servers. Files are mode 0600, or 0644 when others may enter the directory (uhttpd serves only world-readable files). With none, nothing is written and the previous feed stays. The profile enables multiplexing only for Mihomo-target scans, as `node_url_to_mihomo_dict` reads each link's `smux` marker; `links.txt` drops the marker.
- `run_feed_command(config) -> bool | None`: Runs the `feed_command` setting through the shell after `dashboard.publish_feed` wrote a new feed, unless the scan is a dry run. A failure is logged and does not fail the scan.
- `feed_status(config) -> {"count", "written_at"} | None`: The feed apps get now.
- `build_app(config, token)` / `serve_feed(config, token, host, port)`: `GET`/`HEAD /<token>/<file>` for the three files with `profile-update-interval` and `profile-title` headers, 503 before the first feed, 404 for anything else. `cli.py` creates `feed_token` on the first `serve` and saves only that, refusing to save over a settings file it cannot read (`ConfigManager.load(strict=True)`).

### `router/install.py` ↔ `cli.py`, and the router
- `install_router(config, every, dry_run, remove) -> bool`: Looks at the router over SSH first (`RouterClient`, Paramiko imported only then; read-only `_PRECHECK`: OpenWrt release, package manager, free storage, an existing install, Zapret Manager, uhttpd's directory). Refuses anything but OpenWrt with opkg or apk and, for a new install, under 150 MB free. Then uploads `code_archive()` (the package and `THIRD_PARTY_NOTICES.md`; root-owned) to `/tmp/nodesieve-code.tgz` and streams `openwrt_install.sh` to `sh -s` with its `NS_*` values prepended, shell-quoted.
- `router_settings(config, web_dir, steer)`: This computer's settings without router credentials or local paths, with `workers: auto`, the feed in `<uhttpd home>/nodesieve/<token>`, and `feed_command` set to Steer's `steer_action sub_refresh x` when Zapret Manager is installed.
- `openwrt_install.sh` (BusyBox `sh`, one function): installs missing packages; replaces only the code in `/opt/nodesieve` (never `nodesieve_config.json`, `feed`, `sub_cache`, `steer-output`, `mihomo`); writes settings only when there are none; makes the feed's directories 711 with an empty, readable `index.html`; keeps one tagged `# nodesieve-scan` line in root's crontab (`flock -n` against overlap). `NS_MODE=remove` deletes `/opt/nodesieve`, the web directory and that line. Reports through `NS_INFO`, `NS_NOTE` and `NS_ERROR` lines and `NS_OK` at the end.

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
│   ├── limits.py                    # Nodes checked at once, Mihomo instances, file descriptor limit
│   ├── mihomo.py                    # Local Mihomo instances: a batch of nodes each, a listener per node; run_in_batches
│   └── tester.py                    # Node tester: TCP ping, IP check, speedtest
├── parsers/                         # Share links to Mihomo proxies, node names
├── router/
│   ├── client.py                    # SSH to the router (Paramiko), for install-router
│   ├── install.py                   # install-router: nodesieve on an OpenWrt router over SSH
│   ├── openwrt_install.sh           # Router side of install-router (packages, code, feed, cron)
│   └── steer.py                     # Steer main-pool ranking and its report
└── ui/
    ├── cli.py                       # Command-line actions: check, serve, routing, config, install-router
    ├── dashboard.py                 # Scan coordinator
    └── routing.py                   # Steer routing menu
tests/                               # Test suite
```

## Guidelines Adherence (.agents/AGENTS.md)
1. **Async Stream Teardown Safety**: Any network writer teardown must wrap `await writer.wait_closed()` in `asyncio.wait_for(..., timeout=0.2)` or `try/except`.
2. **Ephemeral Subprocess Port Binding**: Dynamic kernel allocation `s.bind(('127.0.0.1', 0))` must be used for any local test proxies or servers. Never use static port increments.
3. **Single-Attempt Cache Pattern**: No falsy collection checks under async locks; use explicit `_attempted = True` flags.
