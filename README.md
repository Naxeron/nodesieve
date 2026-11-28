# nodesieve

Checks VPN proxy subscriptions (VLESS, Trojan, Shadowsocks, Hysteria 2) through local Xray or Mihomo instances, filters out dead nodes, IP leaks, and blocked exit countries, and publishes the working nodes as a subscription feed.

Runs on an **OpenWrt router**, a regular computer, or **Termux (Android)**. See [PROJECT.md](PROJECT.md) for architecture details.

## Quick start (computer)

```sh
pip install -r requirements.txt
python -m nodesieve --add-sub "https://example.org/your-subscription"
python -m nodesieve check
python -m nodesieve serve
```

`check` is the default action and downloads the latest Xray binary on first run (checked against its release SHA-256). `serve` prints the subscription URLs on `127.0.0.1:9876` (pass `--feed-host <LAN-IP>` to serve other devices). Run `python -m nodesieve --help` for all options.

## Running on OpenWrt (with Steer)

Install `python3-aiohttp` (`python3-yaml` is only needed for Mihomo or `clash.yaml`) and shallow-clone into writable storage:

```sh
opkg update && opkg install python3-aiohttp   # or: apk add python3-aiohttp
git clone --depth 1 https://github.com/Naxeron/nodesieve /opt/nodesieve
```

If the router already has a compatible `xray` binary (Xray 26+ for FinalMask / Hysteria 2), symlink it to `/opt/nodesieve/xray` instead of downloading a second copy.

On OpenWrt with `uhttpd` (including Zapret Manager LuCI), serve a token-protected directory directly instead of running `serve` in RAM:

```sh
TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
mkdir -p "/www/nodesieve/$TOKEN"
chmod 711 /www/nodesieve "/www/nodesieve/$TOKEN"
: > /www/nodesieve/index.html && chmod 644 /www/nodesieve/index.html
echo "http://127.0.0.1/nodesieve/$TOKEN/links.txt"
```

Put your settings in `/opt/nodesieve/nodesieve_config.json`:

```json
{
  "subscriptions": ["https://example.org/your-subscription"],
  "use_mux": false,
  "feed_dir": "/www/nodesieve/<token>",
  "feed_formats": ["links"],
  "feed_command": "/opt/zapret-manager-luci/backend.sh steer_action sub_refresh x",
  "routing_output_dir": "/tmp/nodesieve-report"
}
```

Run `python3 -m nodesieve check`, subscribe Steer's main section to `http://127.0.0.1/nodesieve/<token>/links.txt`, and schedule updates in `crontab -e` (enable cron with `/etc/init.d/cron enable && /etc/init.d/cron start`):

```cron
17 */6 * * * cd /opt/nodesieve && PATH=/usr/sbin:/usr/bin:/sbin:/bin flock -n /var/lock/nodesieve.lock sh -c 'nice -n 10 python3 -m nodesieve check > /tmp/nodesieve.log 2>&1'
```

## Termux (Android)

Keep the repo in `~/` (shared storage is `noexec`), install `requirements-termux.txt`, and scan with your VPN app off or Termux excluded from split tunnelling:

```sh
pkg install git python
git clone --depth 1 https://github.com/Naxeron/nodesieve ~/nodesieve
cd ~/nodesieve
pip install -r requirements-termux.txt
python -m nodesieve --add-sub "https://example.org/your-subscription"
python -m nodesieve check
python -m nodesieve serve
```

DNS automatically uses Android's resolver, and concurrency is capped at 64 nodes (≤3 core processes) to stay below Android's phantom process limit.

## How scans work

1. **Fetch & cache** — downloads subscriptions (falling back to the last good copy in `sub_cache/` if a fetch fails).
2. **Reachability** — fast TCP ping filter (Hysteria 2 skips TCP and goes straight to QUIC in the core).
3. **Exit IP & country check** — tests nodes in batches of up to 32 per local core instance (`--core xray` default, or `--core mihomo`), dropping dead nodes and real-IP leaks.
4. **Rank & publish** — writes the feed atomically; if a scan finds nothing, the previous feed stays untouched.

### Scan targets

Both targets publish the same `links.txt` feed (usable by Steer or any VPN app):

| Target | How it qualifies & ranks | Notes |
|---|---|---|
| `mihomo` *(default)* | Cloudflare exit country (blocks `RU, BY, CN, IR, KP, SY, CU`; optional `--countries`), then **sequential speedtest** | Keeps up to 30 nodes ≥ `min_speed_percent` (default `50%`) of fastest. Downloads up to 100 MB per working node. |
| `steer` (`--target steer` or `python -m nodesieve routing`) | **16-provider GeoIP consensus** per IP family; skips speedtest | Requires ≥60% country agreement and ≥3 votes per IP family outside excluded countries (configured under `routing.main`, see [examples/steer-routing.json](examples/steer-routing.json)). Keeps all qualifying nodes ranked by agreement, votes, and latency; writes a redacted report to `steer-output/routing-report.json`. |

## Subscription feed & settings

Settings live in `nodesieve_config.json` (git-ignored; inspect with `--show-config`, manage subs with `--add-sub` / `--remove-sub`).

| File | Format | Used by |
|---|---|---|
| `links.txt` | One share link per line | Steer, v2rayNG, Hiddify, NekoBox, Happ, v2RayTun |
| `links-base64.txt` | Base64-encoded `links.txt` | Clients requiring base64 |
| `clash.yaml` | Full Clash/Mihomo profile (`Auto` fallback group in rank order) | Clash Meta / FlClash (requires `PyYAML`) |

Useful config keys:
- `feed_dir` — output directory (default `feed/`; writes `0644` when world-traversable for `uhttpd`, otherwise `0600`).
- `feed_formats` — subset of `["links", "base64", "clash"]` to write.
- `feed_command` — shell command run after a scan changes the feed's ordered servers (skipped on `--dry-run` or when server order is unchanged).
- `core` — `"xray"` (default) or `"mihomo"`; delete the binary to re-download the latest release.
- `use_mux` — probe sing-mux when scanning with Mihomo (ignored by Xray/Steer; set `false` if unused).
- `min_speed_percent` — relative speed cutoff for speedtest scans (`0` disables, default `50`).

## Tests & notices

```sh
pip install pytest
python -m pytest
```

GeoIP provider checks are adapted from [ipregion](https://github.com/vernette/ipregion) (MIT); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [TEST_INFRA.md](TEST_INFRA.md).
