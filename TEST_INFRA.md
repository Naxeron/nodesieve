# Test Infrastructure & E2E Testing Framework

## 1. Overview & Test Philosophy

The testing framework for nodesieve provides an end-to-end, multi-tier testing pipeline ensuring that candidate proxy nodes and router configurations are 100% representative of real OpenWrt router environments.

The framework adheres to an **opaque-box, requirement-driven** methodology:
- **Opaque-Box Verification**: Tests validate observable behaviors, network interactions, return codes, structured configurations, and interface contracts without coupling to private internal state.
- **Category-Partition Testing**: Inputs are systematically partitioned into discrete categories (e.g., protocol families: VLESS, Trojan, Shadowsocks, WireGuard/AmneziaWG, WARP; candidate node health states: alive, dead, no outbound connectivity, rejected exit country, unreachable from the router WAN; router endpoints: :9090 REST API, :7890 mixed proxy, :22 SSH).
- **Boundary Value Analysis (BVA)**: Edge cases are tested across timeout limits (0.2s stream teardown, 1.5s TCP ping, 3000ms delay probes), retry boundaries (`max-failed-times: 2`), port ranges (ephemeral kernel allocation port 0, privileged vs unprivileged ports), and HTTP status codes (200, 204, 302, 403, 429, 500).
- **Pairwise Combinatorial Testing**: Combinations of network configurations (IPv4/IPv6 prefer-flags, TLS security mechanisms, multiplexing settings) are verified against downstream routing rules.
- **Real-World Workload Simulation**: Multi-stage pipeline runs simulate realistic candidate batches (e.g., 50 candidate nodes) undergoing Phase 0 TCP filtering, the Stage 1 local IP check, and Stage 2 router-side verification.
- **AGENTS.md Concurrency Rules Compliance**: Every test strictly enforces:
  1. Safe async stream teardown with `asyncio.wait_for(writer.wait_closed(), timeout=0.2)`.
  2. Ephemeral subprocess and server port binding via OS kernel (`s.bind(('127.0.0.1', 0))`).
  3. Single-attempt cache patterns with explicit `_attempted = True` boolean gates.

---

## 2. Test Architecture & Tier Layout

The test suite is structured across 4 progressive tiers, plus existing foundational unit tests:

```
tests/
├── Existing Tests (Foundational Baseline):
│   ├── test_concurrency.py             # AGENTS.md compliance, stream teardown, socket allocation
│   ├── test_config.py                  # ConfigManager load/save, normalization
│   ├── test_parsers.py                 # Protocol extraction (vless, trojan, ss, warp), naming
│   ├── test_tester.py                  # NodeTester TCP ping, IP resolution, Phase 1 IP check, speedtest
│   ├── test_location.py                # ipregion GeoIP consensus and its subprocess handling
│   ├── test_main_routing.py            # Main-pool location policy and candidate selection
│   ├── test_multiplexing.py            # use_mux: a node is checked without multiplexing and keeps it,
│   │                                   # up to the router config, only if its server answers through it
│   ├── test_routing_ui.py              # Routing menu and routing CLI flags
│   ├── test_routing_pipeline.py        # Steer check/export/deploy boundaries
│   ├── test_steer_export.py            # Steer artifacts; the apply script run in /bin/sh against a
│   │                                   # stand-in for the Zapret Manager panel backend
│   ├── test_sub_cache.py               # Subscription cache: fallback to the last good payload,
│   │                                   # also against a local HTTP server that fails
│   ├── test_update_ipregion.py         # ipregion.sh updater, with GitHub replaced by canned answers
│   └── test_warp_and_router.py         # WarpScanner endpoints & baseline router script
│
├── Tier 1: Unit & Component Isolation
│   └── test_router_config_parity.py    # Router config parameters (Google 204, expected-status: "204",
│                                       # prefer-ipv6: false), AGENTS.md async rules,
│                                       # parser fidelity, and schema boundary partitions
│
├── Tier 2: Mock Subsystem Integration
│   └── test_router_integration_tier2.py# Real `./mihomo -t` configuration syntax validation,
│                                       # Mock Mihomo REST API (:9090) endpoints & error cases
│
├── Tier 3: Opaque-box Staged Workflow Simulation
│   └── test_staged_pipeline_e2e.py     # End-to-end staged validation: Stage 1 local IP check ->
│                                       # Stage 2 router staging and WAN delay probe,
│                                       # fallback failover parity,
│                                       # atomic deployment script generation (.tmp / .bak / rollback)
│
└── Tier 4: Hardware-in-the-Loop Live Router Smoke
    └── test_live_router_smoke.py       # Live OpenWrt router verification (192.168.1.1:9090 REST API,
                                        # 192.168.1.1:7890 proxy port, SSH port 22 connectivity),
                                        # with graceful skip if router hardware is unreachable
```

---

## 3. Feature Inventory Coverage Matrix

Every feature defined in `PROJECT.md` is mapped to its implementing test tiers and test modules:

| # | Feature | Milestone | Primary Test Tier | Test Module & Coverage |
|---|---------|-----------|-------------------|------------------------|
| 1 | Mihomo REST API Client | M1 | Tier 1, Tier 2, Tier 4 | `test_router_integration_tier2.py` (mock REST API), `test_live_router_smoke.py` (live :9090 probe) |
| 2 | Robust Paramiko SSH Runner | M1 | Tier 1, Tier 2, Tier 4 | `test_router_integration_tier2.py` (mock SSH execution & timeouts), `test_live_router_smoke.py` (live SSH check) |
| 3 | Direct SSH File Streaming | M1 | Tier 2, Tier 3 | `test_staged_pipeline_e2e.py` (staging file upload via SSH stdin streaming) |
| 4 | Router Health Check Parity | M2 | Tier 1, Tier 2, Tier 3 | `test_router_config_parity.py` (Google 204, expected-status: "204"), `test_router_integration_tier2.py` (`./mihomo -t`) |
| 5 | IPv6 Routing Disparity Fix | M2 | Tier 1, Tier 2 | `test_router_config_parity.py` (`prefer-ipv6: false`), `test_router_integration_tier2.py` (`./mihomo -t`) |
| 6 | Dedicated Router Test Listener | M2 | — | Removed together with the per-site checks; `test_warp_and_router.py` asserts no extra listener is deployed |
| 7 | Pre-flight Config Syntax Check | M2 | Tier 2, Tier 3 | `test_router_integration_tier2.py` (real `./mihomo -t` valid/invalid tests), `test_staged_pipeline_e2e.py` |
| 8 | Atomic Deployment & Rollback | M2 | Tier 3 | `test_staged_pipeline_e2e.py` (atomic staging `.tmp`, rollback on error, service health verification) |
| 9 | Staged Validation Pipeline | M3 | Tier 3 | `test_staged_pipeline_e2e.py` (Stage 1 local pre-filter -> Stage 2 router validation) |
| 10 | In-Situ Geoblock Verification | M3 | — | Removed together with the per-site checks; Stage 2 keeps the router WAN delay probe (`test_router_validator.py`) |
| 11 | Dashboard & Pipeline Integration | M3 | Tier 3 | `test_staged_pipeline_e2e.py` (coordinator simulation) |
| 12 | E2E Test Suite Infrastructure | E2E Track | All Tiers | `TEST_INFRA.md`, runner configuration, test harness utilities |
| 13 | Tier 1: Unit & Component Isolation | E2E Track | Tier 1 | `test_router_config_parity.py` |
| 14 | Tier 2: Mock Subsystems | E2E Track | Tier 2 | `test_router_integration_tier2.py` |
| 15 | Tier 3: Opaque-box Staged Workflow | E2E Track | Tier 3 | `test_staged_pipeline_e2e.py` |
| 16 | Tier 4: Hardware-in-the-Loop Smoke | E2E Track | Tier 4 | `test_live_router_smoke.py` |
| 17 | 100% E2E Pass & Adversarial Hardening | M4 | M4 Gate | All test tiers executed together with adversarial validation |

---

## 4. Test Execution Guide

### Running the Entire Suite
To run all tests (baseline + Tiers 1–4):
```bash
pytest -v tests/
```

### Running by Tier
```bash
# Tier 1: Router Configuration Parity & Concurrency Rules
pytest -v tests/test_router_config_parity.py

# Tier 2: Mock Subsystems & ./mihomo -t Syntax Validation
pytest -v tests/test_router_integration_tier2.py

# Tier 3: Opaque-Box Staged Pipeline Simulation
pytest -v tests/test_staged_pipeline_e2e.py

# Tier 4: Hardware-in-the-Loop Live Router Smoke Tests
pytest -v tests/test_live_router_smoke.py
```

### Running with Specific Filters
```bash
# Run only router-related tests
pytest -v -k "router or staged"

# Run tests skipping hardware-in-the-loop (if router is offline)
pytest -v -k "not live_router"
```

---

## 5. Concurrency & Ephemeral Port Harness

All integration and mock server tests implement dynamic OS kernel socket binding:
```python
def get_ephemeral_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port
```
All TCP connections wrap `writer.wait_closed()` with `asyncio.wait_for(..., timeout=0.2)` to eliminate hanging sockets and descriptor leaks across test runs.

---

## 6. Project Directory Isolation

The checker writes its output into the project directory (`apply_to_router.sh`, which
`deploy` pushes to the router unchanged, `crashed_nodes.txt`, `sub_cache/`). `tests/conftest.py`
points `PROJECT_ROOT` in every module that builds such paths at an empty temporary
directory for each test, and fails the session, listing the files, if any file in the real
project directory changed during the run. A module that starts building paths from
`PROJECT_ROOT` belongs in `_PROJECT_ROOT_USERS` there.
