# Proxy Site Checker

Check VPN proxy nodes by their exit IP — reachability, exit address, country and
location agreement — measure performance, and deploy suitable nodes to an OpenWrt
router using Mihomo.

Also supports **Steer** from [Zapret Manager](https://github.com/StressOzz/Zapret-Manager):
the checker ranks nodes by location agreement and supplies the servers of Steer's
main section.

```sh
pip install -r requirements.txt
python check_proxy_sites.py --add-sub "https://example.org/your-subscription"
python check_proxy_sites.py check
```

Use `check` to test and verify nodes. The default `run` action also deploys results
to the configured router. `--help` lists every option.

## Setup

Developed and tested on Linux with Python 3.14.

- **Mihomo.** Each node is checked through a local
  [Mihomo](https://github.com/MetaCubeX/mihomo) instance. If the project directory
  has no `mihomo` binary, the first check downloads the latest alpha build for this
  platform from Mihomo's GitHub releases.
- **Settings** are stored in `proxy_sites_config.json` in the project directory. The
  file is created the first time settings are saved, for example by `--add-sub`, and
  git ignores it because it holds subscription links and router credentials.
  `--show-config` prints the active settings and `--remove-sub` removes a
  subscription.
- **Router access.** Router validation and deployment reach the router at
  `router_host` (default `192.168.1.1`) and log in over SSH as `router_ssh_user`
  (default `root`). While `router_ssh_pass` is empty, which is the default, the SSH
  agent and default key files are used. For password login, set `router_ssh_pass`
  in `proxy_sites_config.json` or pass `--router-ssh-pass` for a single run.
- **WARP (optional).** `use_warp_scanner` adds Cloudflare WARP endpoints to a scan.
  They connect with your own WARP registration, for example from a
  [wgcf](https://github.com/ViRb3/wgcf) profile: put its private key in
  `warp_private_key` and, for IPv6 inside the tunnel, its IPv6 address in
  `warp_ipv6`. Without a key the WARP endpoints are skipped.

The files a scan writes (`apply_to_router.sh`, `steer-output/`, `crashed_nodes.txt`)
contain proxy credentials and are ignored by git as well.

## What is checked

Every node from the configured subscriptions goes through the same IP check:

1. **TCP reachability.** A raw connection to the node's host and port.
2. **Exit IP.** The node is started in a temporary local Mihomo instance and asked
   for its exit address through Cloudflare's trace endpoint, over IPv4 and IPv6
   separately. This yields the exit IP, its country and the latency. A node is
   dropped when its exit address is this computer's own address (an IP leak) and,
   for the Mihomo target, when it has no outbound connectivity at all. `ip_mode`
   can require one or both families.
3. **Country.** For the Mihomo target, exits in RU, BY, CN, IR, KP, SY and CU are
   always rejected and `--countries US,DE` restricts the rest to an allowlist. For
   Steer, the main pool's own location policy decides instead (below).

No individual website is probed. A node that passes describes a working proxy with
a known exit location, not access to any particular service.

Successful nodes are relabelled with what was measured, for example:

```text
[VLESS: MyServer] 🇺🇸 United-States | 203.0.113.10
[VLESS: MyServer] 🇩🇪 Germany | 203.0.113.10 | Location DE 75% (3/4 votes)
```

The first form is the Mihomo target: the country is the one Cloudflare reports for
the exit IP, followed by `⚡ … MB/s` after the speedtest and `LOC: …%` when
`enable_loc_ranking` is on. The second is Steer: the country is the GeoIP
consensus, with its agreement and vote count.

### Mihomo target

After the IP check, surviving nodes are staged on the router and kept only if they
answer a connectivity probe through the router's own WAN (`--no-router-validation`
skips this). The top nodes by measured download speed are written to
`apply_to_router.sh` and, with `run`, deployed over SSH with a syntax pre-flight and
automatic rollback.

## Steer main pool

Open the terminal menu, set the location preferences, enable Steer, and save:

```sh
python check_proxy_sites.py routing
python check_proxy_sites.py check
```

Steer mode supplies the servers of Steer's **main section**. The menu edits excluded
countries, an optional country allowlist, the agreement threshold and the minimum
report count. Blank input keeps the current setting; `-` clears a country list.
The existing Mihomo workflow remains the default until you enable Steer.

The default exclusions are **RU, BY, CN, IR, KP, SY, CU**. Eligible exits need at
least **60% country agreement** and **3 valid country reports per IP family**,
using the bundled [ipregion.sh](https://github.com/vernette/ipregion) GeoIP
providers (its `geoip` group). Agreement is the number of reports for the
most reported country divided by all valid country reports: 3 of 5 means 60%.
IPv4 and IPv6 are checked separately. Tied leading countries, unknown countries,
excluded countries, and insufficient evidence cannot qualify. An allowlist, when
set, further limits eligible countries. The global `--countries` restriction does
not apply to Steer.

The scan shows the winning country, agreement percentage, and vote count for
each node. Missing/failed reports do not vote. GeoIP checks run through each
node's proxy with six concurrent ipregion processes and a three-minute limit
per probe; a timeout or missing dependency leaves a node's location unknown.
The required tools are Bash 4.4 or newer, curl, and jq. The scanner does not
install packages or prompt while scanning. The bundled script must be an
ipregion release that prints JSON report version 2.

The server list contains **all nodes that pass the country and evidence
requirements**, ordered by country agreement, then the number of valid reports,
then latency. Which of them carries traffic is Steer's own server selection
setting: "first working" follows this order, so the best-agreed node is used while
it works; "by ping" picks the fastest of the list regardless of agreement.

These preferences live under `routing.main` in `proxy_sites_config.json`; see
[examples/steer-routing.json](examples/steer-routing.json):

```json
{
  "excluded_countries": ["RU", "BY", "CN", "IR", "KP", "SY", "CU"],
  "allowed_countries": [],
  "min_agreement": 0.6,
  "min_votes": 3
}
```

### Export and deployment

`check` writes three files to `steer-output/` when the main pool has qualifying
proxies:

- `routing-report.json` explains exclusions and records country evidence and
  latency. It does not contain proxy credentials.
- `steer-servers.txt` is the ranked server list, one link per line. It can also be
  pasted by hand into the panel (Steer → Connection → VPN).
- `apply_steer.sh` is the script that deployment runs on the router.

The last two contain credentials and are created with restricted permissions. If
a new scan finds no qualifying proxy, the old script and list are removed and
nothing is deployed: there is no fallback to an unqualified proxy.

After inspecting the report, deploy with:

```sh
python check_proxy_sites.py deploy
```

The default `run` action performs both checking and deployment. `--dry-run` runs
checks and exports without SSH changes; `deploy --dry-run` checks artifact age,
integrity, and matching preferences without connecting. Deployment refuses results
older than 24 hours or generated for different preferences/router.

For one-off use without saving preferences:

```sh
python check_proxy_sites.py check --target steer --output-dir steer-output
python check_proxy_sites.py deploy --target steer --output-dir steer-output
python check_proxy_sites.py --routing-show
```

Deployment streams the script to the router over SSH. The script never edits
Steer's files: it hands the list to Zapret Manager's own panel backend, the same
way the panel's Connection tab does (behaviour read from
[Zapret Manager v5.085](https://github.com/StressOzz/Zapret-Manager/blob/1ff3f5aa01e85125548eccc0a1dd6229a99123fb/ZapretManager_LuCI.sh)),
so the panel validates the links, installs any core plugin they need and applies
them. In order, it:

1. Requires the main section to be connected through **VPN** already. A main section
   on WARP or an AmneziaWG interface is left alone; connect it to VPN in the panel
   once.
2. Remembers what the section uses now, a subscription link or its own servers.
3. **Replaces the servers of the main section with the scanned list.** A subscription
   connected there is replaced too and no longer updates itself; the checker becomes
   the source of the list. Services, devices, exclusions and other sections are not
   touched.
4. Waits for the panel to finish and checks that Steer shows the new list.
5. If applying fails, puts the previous subscription or servers back and reports the
   panel's own log lines.

To see whether the router is ready without changing anything, run the script
with `PSC_CHECK_ONLY=1`; it stops after step 2:

```sh
ssh root@192.168.1.1 'PSC_CHECK_ONLY=1 sh -s' < steer-output/apply_steer.sh
```

### What the checks establish

- **Location:** country agreement is evidence about where GeoIP providers place
  an exit IP. It is not a guarantee that any website or service will allow access
  from it.
- **Location of checks:** Steer probes run on this computer. The Mihomo router
  validator is skipped because it stages nodes on Mihomo, not on Steer.
  Subscription nodes supported by this checker/exporter are VLESS, Trojan, and
  Shadowsocks; local AWG/WARP pseudo-URLs cannot be exported as server links.
- **Freshness:** Steer keeps choosing among the scanned servers by reachability or
  ping. It does not recheck location agreement or country exclusions. Rerun
  `check` and `deploy` when those conditions change.
- **Verification:** the script's read-only checks have run against a live router
  (Zapret Manager v5.085, 2026-11-17), which also has every panel command the
  script uses. Replacing the servers has only been tested against a stand-in for
  the panel backend.

## Upgrading from earlier versions

Earlier versions also probed Gemini, Twitter/X, ChatGPT, Grok and Discord, and
deployed to Forkozz (NetShift) with a separate route for each. Both are gone:

- **Forkozz export was replaced by Steer.** `routing.target` is now `"steer"`; a
  saved `"forkozz"` is read as `"steer"`. `--target forkozz`, `--forkozz-config` and
  the `forkozz_config` setting no longer exist, and output goes to `steer-output/`
  instead of `forkozz-output/`. Nothing on a Forkozz router is changed any more,
  including the `psc_*` service sections an earlier deployment created there.
- `routing.services` in an existing configuration is ignored and dropped the next
  time the configuration is saved. `routing.main.mode` is no longer a setting:
  `"location"` is accepted and dropped, while `"preserve"` is refused, because
  routing now only manages the main pool — remove it and keep routing disabled to
  leave the main servers untouched.
- The Mihomo router configuration no longer opens the extra verification listener
  on port 7891, and `--router-test-port` no longer exists.

The command-line entry point is `check_proxy_sites.py`, the Python package is
`proxy_sites`, and settings are stored in `proxy_sites_config.json`.
See [PROJECT.md](PROJECT.md) for pipeline
architecture and [TEST_INFRA.md](TEST_INFRA.md) for testing details.

## Tests

```sh
pip install pytest
python -m pytest
```

Most of the suite runs offline, but two groups are hardware tests that run whenever
a device answers at `192.168.1.1`. `tests/test_live_router_smoke.py` queries the
router's Mihomo API, proxy port and SSH service. `TestStreamFileToRouterHardware`
logs in over SSH as `root`, then writes and removes temporary files in the router's
`/tmp`. To leave the router alone:

```sh
python -m pytest --ignore=tests/test_live_router_smoke.py --deselect tests/test_router_adversarial.py::TestStreamFileToRouterHardware
```

The hardware tests log in with the SSH agent or default key files. The smoke test
uses a password instead when `ROUTER_SSH_PASS` is set.

## Third-party software

`ipregion.sh` is an unmodified copy of [ipregion](https://github.com/vernette/ipregion)
by vernette, under the MIT License; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Mihomo is not included and is
downloaded at run time.
