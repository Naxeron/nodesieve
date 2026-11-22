# nodesieve

nodesieve checks VPN proxy nodes by their exit IP — reachability, exit address,
country and location agreement — measures performance, and publishes the working ones
as a subscription feed for VPN apps. Run it directly on an OpenWrt router to check nodes
through the router's own connection. It also runs locally on a computer or in Termux
on Android. [Subscription feed](#subscription-feed) · [Termux setup](#termux-android)

Nodesieve can also rank the feed by location agreement for Steer's main section in
[Zapret Manager](https://github.com/StressOzz/Zapret-Manager).

## Running on the router

Start with a checkout on writable storage on the router. If the router has Git and
HTTPS access to the repository, `git clone https://github.com/Naxeron/nodesieve /opt/nodesieve`
creates the directory used below. Allow about 150 MB for Python, its dependencies and
the proxy core. Install the packages from the router's shell with its package manager.

- **opkg** — `opkg update && opkg install python3 python3-aiohttp python3-yaml`
- **apk** — `apk add python3 python3-aiohttp python3-yaml`

Add a subscription, run the first scan, then serve the results.

```sh
cd /opt/nodesieve
python3 -m nodesieve --add-sub "https://example.org/your-subscription"
python3 -m nodesieve check
python3 -m nodesieve serve
```

`check` is the default action. Use the full option names or short flags shown by
`--help`. `serve` runs in the foreground and prints feed URLs
on `127.0.0.1:9876` for apps on the router. To serve LAN clients, use `--feed-host`
with the router's LAN address. If uhttpd already serves your configured `feed_dir`,
each scan updates the files at their existing URLs.

For Steer, enable main-pool ranking with `python3 -m nodesieve routing` before scanning.
In Zapret Manager's Steer connection tab, subscribe the main section to the `links.txt`
URL. To refresh Steer after each feed update, set `feed_command` in
`nodesieve_config.json` to `/opt/zapret-manager-luci/backend.sh steer_action sub_refresh x`.

With `flock` installed, add this entry with `crontab -e` to scan every six hours.
It skips the run if the previous scheduled scan is still active.

```cron
0 */6 * * * cd /opt/nodesieve && flock -n /var/lock/nodesieve.lock sh -c 'python3 -m nodesieve check > /tmp/nodesieve.log 2>&1'
```

Enable and start cron with `/etc/init.d/cron enable` and `/etc/init.d/cron start`.
A Mihomo-target scan can download up to 25 MB per node that passes the IP check.

## Setup

Developed and tested on Linux with Python 3.14, and on OpenWrt's Python 3.11.
On a computer, install the dependencies with `python -m pip install -r requirements.txt`
in the project directory. Use `python3` on OpenWrt wherever the examples use `python`.

- **Core.** Nodes are checked through local instances of a proxy core, each serving up
  to 32 of them (see [Local core instances](#local-core-instances)):
  [Xray](https://github.com/XTLS/Xray-core), the default, which share links are
  written for, or [Mihomo](https://github.com/MetaCubeX/mihomo), with `"core": "mihomo"`
  in `nodesieve_config.json`. `--core` picks one for a single run. If the project
  directory has no `xray` binary, the first check downloads the latest Xray release for
  this platform from Xray's GitHub releases and checks it against the SHA-256 published
  with it; Mihomo's is the latest alpha build, from Mihomo's.
- **Settings** are stored in `nodesieve_config.json` in the project directory. The
  file is created the first time settings are saved, for example by `--add-sub`, and
  git ignores it because it holds subscription links and the feed token.
  `--show-config` prints the active settings and `--remove-sub` removes a
  subscription. Older settings files drop their router login fields on the next save.
- **Subscription cache.** Every subscription that downloads with usable nodes is
  saved in `sub_cache/` in the project directory. When a subscription later can't be
  downloaded (timeout, connection error, an HTTP error) or returns no usable nodes,
  the scan warns and tests the nodes from its last good download instead, and the
  saved copy is kept until a download succeeds again. Dead nodes in an old copy are
  dropped by the checks like any others. Delete `sub_cache/` to clear the cache.
- **Scan target.** A scan ranks one of two ways. The **Mihomo target**, the default,
  ranks by exit country and download speed. The **Steer target** ranks by location
  agreement, for [Steer's main pool](#steer-main-pool). `--target` picks one for a
  single run. Either core checks the nodes for either target.

The files a scan writes (`feed/`, `crashed_nodes.txt`, `sub_cache/`) contain proxy
credentials and are ignored by git, as is `steer-output/`, whose routing report holds
none.

### Termux (Android)

In [Termux](https://termux.dev), install from `requirements-termux.txt`, which pip
installs by itself:

```sh
pkg install git python
git clone https://github.com/Naxeron/nodesieve ~/nodesieve
cd ~/nodesieve
pip install -r requirements-termux.txt
```

- **Keep the project in Termux's home directory.** Shared storage (`~/storage/shared`)
  is mounted `noexec`, so the core can't run from there.
- **Android's child process limit.** Android 12 and newer kill child processes when
  more than 32 run across all apps, the oldest first. A scan stays well under it, Steer
  scans included: it checks up to 64 nodes at once through at most three core
  processes, and asks the GeoIP providers from Python itself. If other apps run many
  processes too, turn the limit off: on Android 14 and newer with Developer options →
  *Disable child process restrictions*; on Android 12L and 13 with
  `adb shell "settings put global settings_enable_monitor_phantom_procs false"` from a
  computer; for Android 12, see
  [these notes by a Termux maintainer](https://github.com/agnostic-apollo/Android-Docs/blob/master/en/docs/apps/processes/phantom-cached-and-empty-processes.md#how-to-disable-the-phantom-processes-killing).
- **DNS.** The cores find no `/etc/resolv.conf` on Android and would look host names up
  through public DNS servers themselves (Mihomo through 114.114.114.114 and 8.8.8.8).
  So on Android, nodesieve resolves each node's server through Android's resolver and
  passes the addresses to the core. Private DNS, a VPN's DNS, and networks that block
  other DNS servers then work as they do for every other app.
- **Scan with your VPN app off, or with Termux excluded from it** (the app's per-app
  proxy or split tunnelling setting). While a VPN app is connected, Termux's connections
  go through it too, so every node would be checked through your current VPN instead of
  the phone's own network.
- **To use the results in a VPN app on the phone**, run `python -m nodesieve serve` in a
  second Termux session and subscribe the app to an address it prints; see
  [Subscription feed](#subscription-feed). Termux has to keep running in the background
  for the app's updates to reach it.

#### Serving and scanning in the background

To serve the feed from boot and scan on a schedule, install the
[Termux:Boot](https://wiki.termux.com/wiki/Termux:Boot) app from the same place as
Termux, open it once, and in Termux run:

```sh
pkg install cronie termux-services
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/nodesieve <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
. $PREFIX/etc/profile
cd ~/nodesieve && nohup python -m nodesieve serve >> ~/nodesieve-serve.log 2>&1 &
EOF
chmod +x ~/.termux/boot/nodesieve
```

Then restart Termux, run `sv-enable crond`, and add the scan to the crontab with
`crontab -e`:

```text
PATH=/data/data/com.termux/files/usr/bin
0 */6 * * * cd ~/nodesieve && python -m nodesieve check > ~/nodesieve-scan.log 2>&1
```

`termux-wake-lock` keeps Android from pausing Termux. Exclude Termux from battery
optimization as well, or Android may stop it anyway.

## What is checked

Every node from the configured subscriptions goes through the same IP check:

1. **TCP reachability.** A raw connection to the node's host and port for TCP-based
   nodes. Hysteria 2 uses QUIC over UDP and goes straight to the exit IP check.
2. **Exit IP.** The node is reached through a local port of its own on a local
   instance of the core and asked for its exit address through Cloudflare's trace
   endpoint, over IPv4 and IPv6 separately. This yields the exit IP, its country and
   the latency. A node is dropped when its exit address is this computer's own
   address (an IP leak) and, for the Mihomo target, when it has no outbound
   connectivity at all. `ip_mode` can require one or both families.
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

### How a node is connected

Both cores accept `hysteria2://` and `hy2://` links in plain-text and base64
subscriptions. A link with no port uses UDP 443. Port lists and ranges, SNI,
certificate pins (`pinSHA256`), and Salamander or Gecko obfuscation carry through
to the connection and the Clash profile. For a self-signed Hysteria 2 server,
include its certificate pin or use `--core mihomo` for a link that relies on
`insecure=1`. Xray 26 requires a trusted certificate or a matching pin.

Through Xray, each link becomes an Xray outbound with every option it carries, so a
node is checked the way Xray-based apps (v2rayN, v2rayNG, Happ and others) connect to
it: REALITY and XTLS Vision; the TCP, WebSocket, HTTPUpgrade, gRPC and XHTTP
transports with their settings, the request shaping in an XHTTP link's `extra`
included; `vcn`, the certificate name of a node that is addressed by IP; and `fm`,
Xray's FinalMask, which for example fragments the TLS ClientHello. What Xray 26 no
longer does fails as it does in those apps: the HTTP/2 transport, and `insecure=1`,
after which the certificate is checked all the same.

Through Mihomo, each link is translated into a Mihomo proxy, as for the feed's Clash
profile, so a node is checked the way Clash apps connect to it. The same transports,
`extra` and `vcn` are read, but `fm` has no Mihomo counterpart and is not applied: a
node that only works with it fails the check.

`use_mux`, on by default, adds sing-mux multiplexing (Mihomo's `smux`) to every node
except VLESS with XTLS Vision and Hysteria 2, which already multiplexes streams over QUIC.
Sing-mux only works when the node's server supports it, which a link doesn't say,
and a server without it, which includes every
Xray server, drops each multiplexed connection. So a node is always checked without
multiplexing. One that qualifies is then asked for a single request through it and
keeps multiplexing, in the speedtest and in the feed's Clash profile, only if it
answers; the scan reports how many nodes do. Set `use_mux` to `false` in `nodesieve_config.json` to
skip that request. Only Mihomo speaks sing-mux, so only a scan through Mihomo asks:
after a scan through Xray, no node in the Clash profile has multiplexing, and the scan
says so. Steer connects with its own core, so a Steer scan never asks.

### Local core instances

One instance of the core serves up to 32 nodes. Each node is a proxy of its own in the
instance's configuration and has a local port that uses only that node: an HTTP and
SOCKS5 listener on 127.0.0.1. The instance refuses anything else, so no check goes out
directly. A node whose multiplexing is to be tried gets a second port on the same
instance, for the node with multiplexing.

A scan checks as many nodes at once as memory allows, at most 256, or 64 on Android. It
counts 8 MB for each node (`mem_per_worker`) and 24 MB for each instance, and leaves
500 MB free. It runs one instance for every 32 nodes plus one, so that a new batch can
start while the last nodes of another are still being checked. A router with 1 GB of
RAM, about 790 MB of it available, checks 30 nodes at once through two instances.
`workers` (or `--workers`) sets a lower number. The speedtest measures up to 8 nodes at
once, through one instance.

- **A node the core refuses.** Xray and Mihomo refuse a whole configuration over one
  proxy they can't use. Such a node is set aside with the core's reason, shown with its
  number and written to `crashed_nodes.txt`, and the other nodes of its batch start
  without it.
- **A node that crashes the core.** When an instance exits in the middle of the checks,
  the nodes it was still checking are checked again, each with an instance of its own.
  The node that crashes the core again is recorded in `crashed_nodes.txt`; the others
  are checked as usual.

### Mihomo target

After the IP check, nodesieve measures each working node's download speed. By default
a node must reach at least **50% of the fastest speed in that scan**. If the fastest
downloads at 20 MB/s, nodes at 10 MB/s or above qualify. Up to 30 qualifying nodes
go to the [subscription feed](#subscription-feed) in rank order.

Set `min_speed_percent` in `nodesieve_config.json`, or use
`python -m nodesieve check --min-speed-percent 75` for one scan. A value of `0`
disables the cutoff and `100` keeps only nodes tied for fastest. If every speedtest
fails, the scan falls back to the first 30 IP-verified nodes in latency order.

## Subscription feed

Every scan that finds nodes also writes them to `feed/` in the project directory, as a
subscription that VPN apps can follow. Apps on a phone can't be configured by another
program, but all of them can subscribe to an address, so this is how nodesieve works
with any of them:

| File | Contents | Read by |
|---|---|---|
| `links.txt` | One share link per line | v2rayNG, Hiddify, NekoBox, Happ, v2RayTun, Steer |
| `links-base64.txt` | The same list, base64-encoded | Apps that read only that |
| `clash.yaml` | A complete Clash/Mihomo profile | Clash Meta for Android, FlClash and other Clash apps |

The feed holds up to 30 nodes in rank order for the Mihomo target, or the ranked
main pool for Steer. The profile's `Auto` group uses the first
node in that order that answers, and the `nodesieve` group in front of it lets you pick
a node by hand. Multiplexing is on only for nodes whose server answered through it in
the scan. The feed accepts VLESS, Trojan, Shadowsocks and Hysteria 2 links.

A scan that finds nothing leaves the feed as it was, so subscribed apps keep the nodes
of the last scan that found some. The scan says how old they are.

To hand the feed to apps, keep this running:

```sh
python -m nodesieve serve
```

The first run creates `feed_token`, a random part of the feed's address, saves it to
`nodesieve_config.json`, and prints the three addresses to subscribe to, such as
`http://127.0.0.1:9876/<token>/links.txt`. Files are read on every request, so `serve`
hands out each new scan's results without a restart. Apps that read the server's
update interval refresh every 6 hours (`feed_update_hours`); others have an update
setting of their own.

- **Who can reach it.** By default, `serve` listens on `127.0.0.1` for apps on the
  same device. Set `--feed-host` (or `feed_host`) to the LAN address to serve nearby
  devices. `0.0.0.0` listens on every IPv4 interface. Anyone who can reach the server
  and knows the feed URL can read the nodes. `--feed-port` (or `feed_port`) changes
  the port.
- **Credentials.** The feed holds proxy credentials. Its files are readable only by
  you, unless `feed_dir` is a directory others may enter, as a web server's must be,
  and git ignores `feed/`. To change the address, clear `feed_token` and restart
  `serve`; subscribed apps then need the new one.
- **Elsewhere.** `feed_dir` writes the feed to another directory; a relative path is
  taken from the project directory.
- **After a scan.** `feed_command` is a shell command run after each scan that updated
  the feed, except with `--dry-run`, for example to have an app fetch it right away.
  If it fails, the scan says so, and its result stands.

## Steer main pool

Open the terminal menu, set the location preferences, enable Steer, and save:

```sh
python -m nodesieve routing
python -m nodesieve check
```

Steer mode ranks the servers of Steer's **main section**. The menu edits excluded
countries, an optional country allowlist, the agreement threshold and the minimum
report count. Blank input keeps the current setting; `-` clears a country list.
Scans use the Mihomo target until you enable Steer.

The default exclusions are **RU, BY, CN, IR, KP, SY, CU**. Eligible exits need at
least **60% country agreement** and **3 valid country reports per IP family**
from 16 GeoIP providers: those of [ipregion](https://github.com/vernette/ipregion)'s
`geoip` group, asked the way ipregion asks them. Agreement is the number of reports
for the most reported country divided by all valid country reports: 3 of 5 means 60%.
IPv4 and IPv6 are checked separately. Tied leading countries, unknown countries,
excluded countries, and insufficient evidence cannot qualify. An allowlist, when
set, further limits eligible countries. The global `--countries` restriction does
not apply to Steer.

The scan shows the winning country, agreement percentage, and vote count for
each node. Missing/failed reports do not vote. Every request goes through the
node, six nodes at a time with up to 16 requests each, and may take five
seconds; a probe that doesn't finish within a minute leaves the node's location
unknown. The address the providers look up is the one identity services such as
icanhazip.com see. Some nodes leave through different addresses for different
destinations, a server in one country sending some traffic out directly and the
rest abroad: their location is that of the address identity services see, even
where Cloudflare's trace sees another.

The list in the feed contains **all nodes that pass the country and evidence
requirements**, ordered by country agreement, then the number of valid reports,
then latency. Which of them carries traffic is Steer's own server selection
setting: "first working" follows this order, so the best-agreed node is used while
it works; "by ping" picks the fastest of the list regardless of agreement.

These preferences live under `routing.main` in `nodesieve_config.json`; see
[examples/steer-routing.json](examples/steer-routing.json):

```json
{
  "excluded_countries": ["RU", "BY", "CN", "IR", "KP", "SY", "CU"],
  "allowed_countries": [],
  "min_agreement": 0.6,
  "min_votes": 3
}
```

### Report

`check` writes `steer-output/routing-report.json` (`--output-dir` puts it elsewhere).
It explains each exclusion and records the country evidence and latency of each node
that qualified, without proxy credentials. The ranked list itself goes to the
[subscription feed](#subscription-feed), which Steer subscribes to; see
[Running on the router](#running-on-the-router). A scan that finds no qualifying proxy
fails and leaves the feed as it was.

For one-off use without saving preferences:

```sh
python -m nodesieve check --target steer
python -m nodesieve --routing-show
```

### What the checks establish

- **Location:** country agreement is evidence about where GeoIP providers place
  an exit IP. It is not a guarantee that any website or service will allow access
  from it.
- **Location of checks:** the checks run where nodesieve runs, through that
  device's connection: on the router, from the router's own. Steer takes VLESS,
  Trojan, Shadowsocks and Hysteria 2 nodes from nodesieve.
- **Freshness:** Steer keeps choosing among the scanned servers by reachability or
  ping. It does not recheck location agreement or country exclusions; the next scan
  does.

## Tests

```sh
pip install pytest
python -m pytest
```

The suite runs offline using fixtures and loopback servers.
Each test gets an empty temporary project directory, so a test run doesn't write
to your `feed/`, `crashed_nodes.txt` or `sub_cache/`. If a test changes a file in the
project directory anyway, the run fails and lists the file. See [PROJECT.md](PROJECT.md)
for the architecture and [TEST_INFRA.md](TEST_INFRA.md) for the tests.

## Updating dependencies

- **GeoIP providers** are listed in `nodesieve/location.py`, with their addresses,
  headers and demo keys, as of the ipregion commit recorded in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). When a provider changes its API
  or a demo key stops working, it stops voting; change its entry there, or compare
  with the `geoip` checks of a newer ipregion.
- **Python packages** are not pinned: `pip install -U -r requirements.txt` brings
  them up to date.
- **Xray and Mihomo** are downloaded only while the project directory has no `xray` or
  `mihomo` binary. Delete the binary to get Xray's current release, or Mihomo's current
  alpha build, on the next check through it.

## Third-party software

The location checks are adapted from the GeoIP checks of
[ipregion](https://github.com/vernette/ipregion) by vernette, under the MIT License; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Xray and Mihomo are not included and
are downloaded at run time.
