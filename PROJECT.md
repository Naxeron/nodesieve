# Proxy Site Checker

## Architecture
`Proxy Site Checker` qualifies proxy nodes by their exit IP alone — no individual
website is probed — through a dual-stage, router-representative pipeline:

```
[Raw Subscriptions] (a failed or empty download falls back to that subscription's last good copy in sub_cache/)
       │
       ▼
[Phase 0: TCP Reachability Filter] (Local rapid pre-filter: raw TCP connect, timeout 1.5s)
       │
       ▼
[Stage 1: Local IP Check] (Local ephemeral Mihomo instance per node)
       ├── Exit IPv4/IPv6, country and latency via Cloudflare trace
       ├── Drop: no outbound connectivity, exit IP equal to this host's IP (leak)
       ├── Mihomo target: reject RU/BY/CN/IR/KP/SY/CU exits, apply allowed_countries
       └── Steer target: ipregion GeoIP consensus per IP family against routing.main
       │
       ├──────────────► Steer target: [Main Pool Export]
       │                   ├── select_main_pool: every qualifying node, ranked by agreement, reports, latency
       │                   ├── steer-output/: redacted report, ranked server list, guarded apply script
       │                   └── Deploy over SSH stdin: hand the list to the Zapret Manager panel backend
       │                       (steer_action sub_set), wait for its job, verify, restore the previous servers on failure
       ▼ (Mihomo target; candidate survivors: ~20-50 nodes)
[Stage 2: Router-Representative Verification]
       ├── RouterClient (Mihomo REST API :9090 + Paramiko SSH :22)
       ├── 1. Staging upload: stream candidate sub.yaml via SSH stdin to /etc/mihomo/proxy-providers/sub.yaml
       ├── 2. Dynamic reload: PUT /providers/proxies/Gemini_Nodes (<50ms, zero-downtime)
       └── 3. Rapid batch delay probe: GET /group/Gemini_Auto/delay?url=https://www.gstatic.com/generate_204
              - Keep nodes that answer through the router WAN, with the router-measured delay
       │
       ▼ (router-verified nodes)
[Phase 2: Speedtest] (Throughput measurement on top verified nodes)
       │
       ▼
[Production Router Deployment]
       ├── Direct SSH stdin streaming of apply_to_router.sh
       ├── Atomic staging (.tmp) and pre-flight syntax check (/usr/bin/mihomo -t)
       ├── Failover health checks aligned to https://www.gstatic.com/generate_204 (expected-status: "204")
       ├── Restart services (mihomo, magitrickle) with automatic rollback on failure
       └── Verify service health post-restart
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Mihomo REST API Client | Async client for :9090 endpoints (`/version`, `/providers/proxies`, `/group/{name}/delay`, `/proxies`) | M1 | Survey 2 |
| 2 | Robust Paramiko SSH Runner | Replace brittle `pty.fork()` in `ssh_router.py` with reliable, non-interactive Paramiko CLI execution | M1 | Survey 1, 2 |
| 3 | Direct SSH File Streaming | Replace host HTTP server in `pusher.py` with direct SSH stdin file streaming (`cat > target`) | M1 | Survey 2 |
| 4 | Router Health Check Parity | Set provider & group health checks to `https://www.gstatic.com/generate_204` with `expected-status: "204"` | M2 | Survey 1, 3 |
| 5 | IPv6 Routing Disparity Fix | Disable `prefer-ipv6` in router DNS and config to prevent blackholing Google AAAA queries on WAN without IPv6 | M2 | Survey 1, 2 |
| 6 | Dedicated Router Test Listener | Removed with the per-site checks (was: port 7891 listener bound to a `Gemini_Manual` selector group) | M2 | Survey 1, 2, 3 |
| 7 | Pre-flight Configuration Syntax Check | Validate syntax with `/usr/bin/mihomo -t` before replacing production configurations | M2 | Survey 2, 3 |
| 8 | Atomic Deployment & Rollback | Staging via `.tmp`, automatic rollback to `.bak` on error, and post-restart status check in `apply_to_router.sh` | M2 | Survey 2, 3 |
| 9 | Staged Router-Representative Pipeline | `RouterValidator` workflow: Stage 1 local IP check -> Stage 2 router staging and delay probe | M3 | Survey 1, 3 |
| 10| In-Situ Google/Gemini Geoblock Verification | Removed with the per-site checks; Stage 2 now ends at the delay probe | M3 | Survey 1, 2, 3 |
| 11| Dashboard & Pipeline Integration | Integrate Stage 2 verification into `dashboard.py` and pipeline orchestrators | M3 | Survey 1 |
| 12| E2E Test Suite Infrastructure (Tiers 1-4) | Design and implement opaque-box test runner and test harnesses | E2E Track | Survey 3 |
| 13| Tier 1: Unit & Component Isolation Tests | In-memory unit tests for parsers, configs, REST client, SSH runner, and AGENTS.md concurrency rules | E2E Track | Survey 3 |
| 14| Tier 2: Mock Subsystem Integration Tests | Mock REST API (:9090), mock SSH, and real `./mihomo -t` validation | E2E Track | Survey 3 |
| 15| Tier 3: Opaque-box Staged Workflow Simulation | End-to-end pipeline simulation: host IP check -> router staging -> WAN-dead node drop -> script generation | E2E Track | Survey 3 |
| 16| Tier 4: Hardware-in-the-Loop Smoke Tests | Live OpenWrt router smoke tests for REST API, proxy port, and SSH service status | E2E Track | Survey 3 |
| 17| 100% E2E Pass & Tier 5 Adversarial Hardening | Validate 100% test pass on all tiers, then run adversarial coverage hardening with challenger | M4 | Project Pattern |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Router Communication & Tooling Layer | Implement `RouterClient` (`proxy_sites/router/client.py`), modernize `ssh_router.py` with Paramiko, update `pusher.py` to use SSH stdin streaming | none | DONE |
| M2 | Router Configuration Parity & Deployment Hardening | Update `ROUTER_CONFIG_TEMPLATE` (`proxy_sites/constants.py`), `config_builder.py`, `script_generator.py` with Google 204 health checks, `prefer-ipv6: false`, pre-flight syntax check, and atomic rollback | none | DONE |
| M3 | Staged Router-Representative Validation Pipeline | Implement `RouterValidator` (`proxy_sites/core/router_validator.py`), integrate Stage 1/2 workflow into `dashboard.py` and `tester.py` | M1, M2 | DONE |
| M4 | Final Milestone: E2E Test Pass & Adversarial Hardening | Pass 100% of Dual-Track E2E tests (Tiers 1-4), then execute Phase 2 adversarial coverage hardening (Tier 5) | M1, M2, M3, E2E Track | DONE |

## Parallel Track: E2E Testing Track
| Track | Name | Scope | Dependencies | Status |
|-------|------|-------|-------------|--------|
| E2E | Opaque-Box Test Suite Creation | Create `TEST_INFRA.md`, implement Tier 1-4 tests in `tests/`, publish `TEST_READY.md` | none | DONE |

## Interface Contracts

The Mihomo identifiers `Gemini_Nodes` and `Gemini_Auto` are retained for
compatibility with existing router configurations. Router validation uses these
identifiers before deploying a new configuration.

### `NodeTester` ↔ `dashboard.py`
- `class NodeTester`:
  - `async def async_check_tcp_node(node, timeout=1.5) -> Optional[str]`: Phase 0 TCP reachability.
  - `async def test_node_full(idx, node) -> Optional[Tuple[str, float, str]]`: Stage 1 IP check. Returns `(relabelled_node, latency_ms, tested_node)` or `None`; the outcome, including a drop reason, is recorded in `node_metadata`.
  - `async def speedtest_node(idx, node, timeout) -> Optional[Tuple[str, float, float]]`: Returns `(relabelled_node, bytes_per_second, location_score)`.

### `RouterClient` ↔ `RouterValidator` / `pusher.py`
- `class RouterClient`:
  - `async def is_api_alive() -> bool`: Returns True if `GET http://192.168.1.1:9090/version` returns 200.
  - `async def reload_provider(provider_name: str = "Gemini_Nodes") -> bool`: `PUT /providers/proxies/{name}`, returns True on 200/204.
  - `async def probe_group_delay(group_name: str, url: str = "https://www.gstatic.com/generate_204", timeout_ms: int = 3000) -> Dict[str, int]`: Returns map of `{proxy_name: delay_ms}`.
  - `def exec_command(cmd: str, timeout: float = 15.0) -> Tuple[int, str, str]`: Returns `(exit_code, stdout, stderr)`.
  - `def stream_file_to_router(content: str, remote_path: str, mode: str = "0644") -> bool`: Streams content via SSH stdin to remote file; returns True if exit code is 0.

### `RouterValidator` ↔ `dashboard.py`
- `class RouterValidator`:
  - `def __init__(self, router_client: Optional[RouterClient] = None, config: Optional[dict] = None, fallback_on_unreachable: bool = True)`: Initializes validator.
  - `async def verify_nodes_on_router(self, candidate_nodes: List[Any]) -> List[Any]`:
    1. Checks if the router API is reachable. If unreachable, gracefully logs warning and returns candidate_nodes (or raises in strict mode).
    2. Uploads candidate `sub.yaml` via `stream_file_to_router()`.
    3. Triggers `reload_provider("Gemini_Nodes")`.
    4. Probes batch delays via `probe_group_delay("Gemini_Auto", GOOGLE_HEALTHCHECK_URL)`.
    5. Returns the candidates that answered through the router WAN, in their original shape, with tuple/list latency replaced by the router-measured delay.

### `routing.py` ↔ `steer.py` / `dashboard.py`
- `normalize_routing(value) -> dict`: Validates `routing` (`enabled`, `main.excluded_countries`, `main.allowed_countries`, `main.min_agreement`, `main.min_votes`). Drops `services` saved by earlier versions, reads their `target: "forkozz"` as `"steer"`, and refuses the former `main.mode: "preserve"`.
- `main_policy_failure(policy, evidence) -> Optional[str]`: Why ipregion evidence does not satisfy the main policy, or `None`.
- `select_main_pool(candidates, metadata, routing) -> {"policy", "eligible", "excluded"}`: Every qualifying node, ranked.
- `write_steer_artifacts(route, config) -> dict`: Writes the redacted report and, when the pool is not empty, the ranked server list and apply script.
- Router contract of the apply script (Zapret Manager panel backend, `/opt/zapret-manager-luci/backend.sh`): `steer_action sub_status` (JSON with `exit`, `kind`, `url`, `vpn.up`), `steer_action sub_links_get`, `steer_action sub_set @stdin` (starts job `steer`), `job_status steer`, `log_tail steer`. The script prints `PSC_OK:` only after the panel shows the new list; `PSC_ERROR:`, `PSC_LOG:` and `PSC_NOTE:` lines carry failures, panel log excerpts and warnings back to `dashboard.py`.

## Code Layout
```
proxy_sites/
├── constants.py                     # ROUTER_CONFIG_TEMPLATE, router connection constants
├── routing.py                       # Main-pool location policy and candidate selection
├── location.py                      # ipregion GeoIP consensus through a node's proxy
├── geo.py                           # Country name and IP country lookups
├── core/
│   ├── mihomo.py                    # Local Mihomo subprocess runner (ephemeral ports)
│   ├── router_validator.py          # Staged router verification (Stage 2)
│   └── tester.py                    # Node tester: TCP ping, IP check, speedtest
├── router/
│   ├── client.py                    # RouterClient (REST API + Paramiko SSH)
│   ├── config_builder.py            # build_router_config_yaml
│   ├── steer.py                     # Steer main-pool report, server list and apply script
│   ├── pusher.py                    # push_to_router (SSH stdin streaming)
│   └── script_generator.py          # generate_router_script (apply_to_router.sh)
└── ui/
    ├── cli.py                       # Command-line entry point
    ├── dashboard.py                 # Pipeline UI and workflow coordinator
    └── routing.py                   # Steer routing menu
ssh_router.py                        # Standalone SSH CLI helper (Paramiko-based)
update_ipregion.py                   # Replaces the bundled ipregion.sh with the latest upstream version
tests/                               # Test suite
```

## Guidelines Adherence (.agents/AGENTS.md)
1. **Async Stream Teardown Safety**: Any network writer teardown must wrap `await writer.wait_closed()` in `asyncio.wait_for(..., timeout=0.2)` or `try/except`.
2. **Ephemeral Subprocess Port Binding**: Dynamic kernel allocation `s.bind(('127.0.0.1', 0))` must be used for any local test proxies or servers. Never use static port increments.
3. **Single-Attempt Cache Pattern**: No falsy collection checks under async locks; use explicit `_attempted = True` flags.
