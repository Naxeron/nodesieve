"""Steer export contract and isolated router-script transaction checks."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from proxy_sites.router.steer import routing_fingerprint, write_steer_artifacts
from proxy_sites.routing import normalize_routing


NODE = "vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?security=tls&sni=example.org#First%20server"
OTHER = "trojan://private-password@192.0.2.2:443?security=tls#Second"
OLD_LINKS = "vless://22222222-2222-4222-8222-222222222222@192.0.2.9:443?security=tls#Old%20one\ntrojan://old-secret@192.0.2.10:443#Old%20two"
OLD_URL = "https://subscription.example.org/old-secret"


def config(tmp_path, **overrides):
    return {"routing_output_dir": str(tmp_path / "output"), "routing": normalize_routing(), "router_host": "router.example", **overrides}


def export(route, options):
    # Most cases focus on export behavior: derive matching preferences explicitly.
    # Contract mismatch tests below call the production function directly.
    options["routing"] = normalize_routing({"main": route["policy"]})
    return write_steer_artifacts(route, options)


def location(counts=None):
    counts = counts or {"DE": 3}
    country = max(counts, key=counts.get)
    total = sum(counts.values())
    consensus = {"country": country, "score": counts[country] / total, "votes": counts[country], "total": total, "counts": counts}
    return {"source": "ipregion", "status": "ok", **consensus, "tested_families": ["ipv4"], "families": {"ipv4": dict(consensus)}}


def main_route(node=NODE, evidence=None, **policy):
    return {"policy": normalize_routing({"main": policy})["main"],
            "eligible": [{"node": node, "evidence": location() if evidence is None else evidence}], "excluded": []}


def two_servers():
    route = main_route()
    route["eligible"].append(main_route(OTHER)["eligible"][0])
    return route


def test_exports_server_list_script_and_redacted_evidence(tmp_path):
    options = config(tmp_path)
    result = export(two_servers(), options)
    assert result["ready"], result["errors"]
    assert Path(result["servers_path"]).read_text() == NODE + "\n" + OTHER + "\n"
    report_text = Path(result["report_path"]).read_text()
    report = json.loads(report_text)
    assert set(report) == {"ready", "created_at", "config_fingerprint", "script_sha256", "main", "errors", "warnings"}
    assert [node["country"] for node in report["main"]["eligible"]] == ["DE", "DE"]
    for secret in ("11111111", "192.0.2.1", "private-password", "First", "router.example", "vless://"):
        assert secret not in report_text
    script = Path(result["script_path"])
    assert script.name == "apply_steer.sh"
    assert report["script_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
    assert report["config_fingerprint"] == routing_fingerprint(options)
    assert report["created_at"].endswith("+00:00")
    assert script.stat().st_mode & 0o777 == 0o700
    assert Path(result["report_path"]).stat().st_mode & 0o777 == 0o600
    assert Path(result["servers_path"]).stat().st_mode & 0o777 == 0o600
    # The links travel inside a quoted here-document, in ranked order, and nowhere else.
    text = script.read_text()
    assert "<<'PSC_SERVERS_END' || outcome=$?\n" + NODE + "\n" + OTHER + "\nPSC_SERVERS_END\n" in text
    assert text.count("192.0.2.") == 2
    subprocess.run(["sh", "-n", str(script)], check=True)


def test_failure_removes_stale_script_and_server_list(tmp_path):
    options = config(tmp_path)
    good = export(main_route(), options)
    failed = export({"policy": normalize_routing()["main"], "eligible": [],
                     "excluded": [{"node": NODE, "reason": "failed vless://secret-password@server"}]}, options)
    assert not failed["ready"] and failed["script_path"] is None and failed["servers_path"] is None
    assert "main: no supported proxy satisfies the location policy" in failed["errors"]
    assert not Path(good["script_path"]).exists()
    assert not Path(good["servers_path"]).exists()
    assert "secret-password" not in Path(failed["report_path"]).read_text()


@pytest.mark.parametrize("node", ["awg_conf:/tmp/private.conf", "warp://192.0.2.1:2408", "mihomo://secret", "socks5://user:password@example.org:1080", "vless://bad", NODE + "\nmalicious", "PSC_SERVERS_END", "http://example.org:8080"])
def test_unsupported_or_malformed_uri_cannot_make_empty_pool_ready(tmp_path, node):
    result = export(main_route(node), config(tmp_path))
    assert not result["ready"]
    assert result["script_path"] is None


def test_fingerprint_changes_with_policy_or_target(tmp_path):
    options = config(tmp_path)
    original = routing_fingerprint(options)
    assert original != routing_fingerprint({**options, "router_host": "other-router"})
    assert original != routing_fingerprint({**options, "routing": normalize_routing({"main": {"min_votes": 4}})})
    assert original != routing_fingerprint({**options, "routing": normalize_routing({"enabled": True})})
    assert original == routing_fingerprint({**options, "routing_output_dir": "/different/output"})
    # Preferences saved by earlier versions describe the same main-pool policy.
    legacy = {"target": "forkozz", "main": {"mode": "location"}, "services": {"twitter": {"mode": "country", "countries": ["US"]}}}
    assert original == routing_fingerprint({**options, "routing": legacy})


def test_missing_route_and_policy_drift_refuse_export(tmp_path):
    options = config(tmp_path)
    for missing in ({}, None):
        result = write_steer_artifacts(missing, options)
        assert not result["ready"]
        assert result["errors"] == ["Missing main route"]
    drifted = write_steer_artifacts(main_route(min_votes=2), options)
    assert not drifted["ready"]
    assert drifted["errors"] == ["main: route policy does not match the configured policy"]


@pytest.mark.parametrize("reason,expected", [
    ("Location country excluded: RU private-host", "Location country is excluded or not allowed"),
    ("IPV4: Location agreement below threshold private-url", "Location agreement is below the required threshold"),
    ("Location probe failed: ipregion timed out private-response", "Location evidence is unavailable or incomplete"),
    ("Location probe detected an IP leak 198.51.100.7 private-ip", "Location probe detected an IP leak"),
    ("Something unexpected private-cookie", "Location evidence did not satisfy this policy"),
])
def test_report_keeps_safe_failure_categories_and_policy(tmp_path, reason, expected):
    candidate = main_route(allowed_countries=["DE"])
    candidate["excluded"] = [{"node": OTHER, "reason": reason}]
    result = export(candidate, config(tmp_path))
    report = json.loads(Path(result["report_path"]).read_text())
    assert report["main"]["excluded"][0]["reason"] == expected
    assert report["main"]["allowed_countries"] == ["DE"]
    assert report["main"]["min_agreement"] == 0.6
    assert "private-" not in Path(result["report_path"]).read_text()


def test_main_report_retains_and_ranks_all_qualified_nodes_and_redacts_evidence(tmp_path):
    best = location({"DE": 8, "US": 2})
    best["ip"] = "198.51.100.100"
    best["private_response"] = "private-location-secret"
    best["latency_ms"] = 50
    smaller_sample = "trojan://smaller-sample@192.0.2.3:443"
    lower_score = "trojan://lower-score@192.0.2.4:443"
    unknown_latency = "trojan://unknown-latency@192.0.2.5:443"
    blocked = "trojan://blocked-country@192.0.2.6:443"
    insufficient = "trojan://low-agreement@192.0.2.7:443"
    candidate = main_route(evidence=best)
    candidate["eligible"].extend([
        {"node": smaller_sample, "evidence": {**location({"DE": 4, "US": 1}), "latency_ms": 1}},
        {"node": OTHER, "evidence": {**location({"DE": 8, "US": 2}), "latency_ms": 10}},
        {"node": lower_score, "evidence": {**location({"DE": 3, "US": 2}), "latency_ms": 0.5}},
        {"node": unknown_latency, "evidence": location({"DE": 8, "US": 2})},
        {"node": blocked, "evidence": location({"RU": 3})},
        {"node": insufficient, "evidence": location({"DE": 2, "US": 1, "FR": 1})},
        {"node": OTHER + "-renamed-duplicate", "evidence": {**location({"DE": 9, "US": 1}), "latency_ms": 5}},
    ])
    result = export(candidate, config(tmp_path))
    assert result["ready"], result["errors"]
    # Best agreement first, then more reports, then lower latency: Steer's "first working" follows this order.
    servers = Path(result["servers_path"]).read_text().splitlines()
    assert servers == [OTHER, NODE, unknown_latency, smaller_sample, lower_score]
    assert blocked not in Path(result["script_path"]).read_text()
    report_text = Path(result["report_path"]).read_text()
    report = json.loads(report_text)["main"]
    assert report["excluded_countries"] == ["RU", "BY", "CN", "IR", "KP", "SY", "CU"]
    assert report["eligible"][0]["counts"] == {"DE": 8, "US": 2}
    assert report["eligible"][0]["score"] == 0.8
    assert [(node["score"], node["total"], node["latency_ms"]) for node in report["eligible"]] == [
        (0.8, 10, 10), (0.8, 10, 50), (0.8, 10, None), (0.8, 5, 1), (0.6, 5, 0.5)]
    assert [node["reason"] for node in report["excluded"]] == [
        "Location country is excluded or not allowed", "Location agreement is below the required threshold"]
    for secret in ("198.51.100.100", "private-location-secret", "192.0.2.1", "private-password", "smaller-sample", "lower-score", "blocked-country"):
        assert secret not in report_text
    assert any("its own server selection setting" in warning for warning in result["warnings"])
    subprocess.run(["sh", "-n", result["script_path"]], check=True)


@pytest.mark.parametrize("evidence", [None, {"source": "node-label", "country": "DE"}, location({"RU": 3}), location({"DE": 2})])
def test_invalid_or_missing_main_location_refuses_export_and_removes_stale_script(tmp_path, evidence):
    options = config(tmp_path)
    successful = export(main_route(), options)
    assert successful["ready"]
    candidate = main_route(evidence=evidence or {})
    result = export(candidate, options)
    assert not result["ready"]
    assert result["script_path"] is None
    assert not Path(successful["script_path"]).exists()


# A stand-in for Zapret Manager's panel backend, modelled on the upstream commands the
# script relies on. Every invocation drains its stdin, as a careless child process on
# the router might: the script is itself read from stdin and must survive that.
FAKE_BACKEND = r'''
import json, os, pathlib, re, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
env = os.environ.get
stdin = sys.stdin.read()
args = sys.argv[1:]
with (root / 'calls').open('a') as out:
    out.write(json.dumps({'args': args, 'stdin': stdin if '@stdin' in args else ''}) + '\n')

def read(name, default=''):
    path = root / name
    return path.read_text() if path.exists() else default

def reply(value, code=0):
    print(json.dumps(value, ensure_ascii=False))
    sys.exit(code)

LINK = re.compile(r'^(vless|vmess|trojan|ss|socks5?|hysteria2|hy2)://', re.I)
log = root / 'steer.log'
if args[:1] == ['job_status']:
    polls = int(read('polls', '0')) + 1
    (root / 'polls').write_text(str(polls))
    text = read('steer.log')
    done = '__DONE__' in text and polls > int(env('TEST_SLOW', '0')) and not env('TEST_HANG')
    rc = text.rsplit('__DONE__ ', 1)[1].split()[0] if done else ''
    reply({'running': not done and log.exists(), 'done': done, 'rc': rc})
if args[:1] == ['log_tail']:
    reply({'lines': '\n'.join(l for l in read('steer.log').splitlines() if not l.startswith('__DONE__'))})
if args[:1] != ['steer_action'] or env('TEST_OLD_PANEL'):
    reply({'error': 'неизвестное действие'}, 1)
action = args[1]
servers, url = read('sub.txt'), read('sub.url').strip()
if action == 'sub_status':
    kind = ('url' if url else 'links') if servers.strip() else ''
    route = read('exit', 'none').strip()
    vpn = {'up': not env('TEST_VPN_DOWN'), 'failed': False} if route == 'vpn' and servers.strip() else None
    reply({'ext': True, 'has': bool(servers.strip()), 'kind': kind, 'url': url, 'title': 'private-title',
           'exit': route, 'node': '', 'list': [{'name': 'ignored'}], 'vpn': vpn})
if action == 'sub_links_get':
    if not servers.strip():
        reply({'error': 'подписки нет'}, 1)
    if url:
        reply({'error': 'это подписка по ссылке — её серверы задаёт сервис, а не вы'}, 1)
    reply({'links': '\n'.join(l for l in servers.splitlines() if LINK.match(l))})
if action == 'sub_set':
    if env('TEST_BUSY'):
        reply({'error': 'дождитесь окончания текущей операции'}, 1)
    text = '\n'.join(l.strip() for l in stdin.splitlines() if l.strip())
    is_url = re.fullmatch(r'https?://\S+', text) is not None
    if not is_url and not any(LINK.match(l) for l in text.splitlines()):
        reply({'error': 'нужна ссылка на подписку (https://…) или ссылки на серверы'}, 1)
    (root / 'polls').write_text('0')
    attempt = int(read('attempts', '0')) + 1
    (root / 'attempts').write_text(str(attempt))
    failing = env('TEST_FAIL_APPLY') == 'always' or (env('TEST_FAIL_APPLY') == 'first' and attempt == 1)
    if env('TEST_FAIL_VALIDATE'):
        log.write_text('==> Проверяем ссылки\nОШИБКА: в подписке нет узлов, с которыми умеет работать Steer\n__DONE__ 1\n')
    else:
        if is_url:
            (root / 'sub.url').write_text(text + '\n')
            (root / 'sub.txt').write_text('vless://fetched@192.0.2.50:443#From%20subscription\n')
        else:
            (root / 'sub.url').unlink(missing_ok=True)
            (root / 'sub.txt').write_text(text + '\n')
        (root / 'exit').write_text('vpn\n')
        if failing:
            log.write_text('==> Ссылки сохранены\nОШИБКА: ядро steer не приняло настройки\n__DONE__ 1\n')
        else:
            log.write_text('==> Ссылки сохранены\n==> Готово\n__DONE__ 0\n')
    reply({'started': True, 'job': 'steer'})
reply({'error': 'неизвестное действие'}, 1)
'''

FAKE_JSONFILTER = r'''
import json, sys
path = sys.argv[sys.argv.index('-e') + 1]
try:
    value = json.loads(sys.stdin.read())
    for key in path.removeprefix('@.').split('.'):
        value = value[key]
except Exception:
    sys.exit(1)
if value is None:
    sys.exit(1)
print(('true' if value else 'false') if isinstance(value, bool) else value)
'''


def isolated_router(tmp_path, route="vpn", servers=OLD_LINKS, url=""):
    router = tmp_path / "router"
    bins = router / "bin"
    bins.mkdir(parents=True)
    scripts = {"backend.sh": FAKE_BACKEND, "jsonfilter": FAKE_JSONFILTER, "sleep": "import sys\nsys.exit(0)"}
    for name, body in scripts.items():
        target = bins / name
        target.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body))
        target.chmod(0o700)
    (router / "exit").write_text(route + "\n")
    if servers:
        (router / "sub.txt").write_text(servers + "\n")
    if url:
        (router / "sub.url").write_text(url + "\n")
    env = {**os.environ, "PATH": str(bins) + ":" + os.environ["PATH"], "TEST_ROOT": str(router)}
    return router, env


def run_script(result, router, env, edit=None):
    script = Path(result["script_path"]).read_text()
    script = script.replace("/opt/zapret-manager-luci/backend.sh", str(router / "bin" / "backend.sh"))
    # Tests can run as an unprivileged developer; only this root preflight is
    # replaced. Checks, the hand-over, waiting, verification and restoring all run.
    script = script.replace('[ "$(id -u)" = 0 ]', 'true')
    if edit:
        script = edit(script)
    # Streamed over stdin exactly as deployment does over SSH.
    return subprocess.run(["sh", "-s"], input=script, text=True, capture_output=True, env=env, timeout=60)


def calls(router, action=None):
    path = router / "calls"
    recorded = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return [call for call in recorded if action is None or call["args"][:2] == ["steer_action", action]]


def state(router):
    return {name: (router / name).read_text() if (router / name).exists() else None for name in ("exit", "sub.txt", "sub.url")}


@pytest.mark.parametrize("servers,url", [(OLD_LINKS, ""), ("vless://fetched@192.0.2.50:443#From%20subscription", OLD_URL)])
def test_script_replaces_main_servers_and_quotes_credentials_without_execution(tmp_path, servers, url):
    marker = tmp_path / "must-not-exist"
    node = "trojan://'$(touch${IFS}" + str(marker) + ")`touch${IFS}" + str(marker) + "`@192.0.2.3:443#private"
    route = main_route(node)
    route["eligible"].append(main_route(OTHER, evidence=location({"DE": 4}))["eligible"][0])
    result = export(route, config(tmp_path))
    assert result["ready"], result["errors"]
    router, env = isolated_router(tmp_path, servers=servers, url=url)
    completed = run_script(result, router, env)
    assert completed.returncode == 0, completed.stderr
    assert not marker.exists()
    assert completed.stdout.splitlines() == ["PSC_OK: Steer main servers replaced: 2 servers"]
    assert completed.stderr == ""
    # A subscription connected there is replaced by the scanned list; the route stays VPN.
    assert state(router) == {"exit": "vpn\n", "sub.txt": OTHER + "\n" + node + "\n", "sub.url": None}
    assert [call["stdin"] for call in calls(router, "sub_set")] == [OTHER + "\n" + node + "\n"]
    assert "old-secret" not in completed.stdout + completed.stderr


@pytest.mark.parametrize("servers,url,described", [(OLD_LINKS, "", "its own server list"), ("vless://fetched@192.0.2.50:443", OLD_URL, "a subscription link")])
def test_check_only_reads_the_router_and_changes_nothing(tmp_path, servers, url, described):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path, servers=servers, url=url)
    before = state(router)
    completed = run_script(result, router, {**env, "PSC_CHECK_ONLY": "1"})
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"PSC_OK: Steer is ready: its main section uses VPN with {described}. Nothing was changed."
    assert state(router) == before
    assert calls(router, "sub_set") == []
    assert "old-secret" not in completed.stdout + completed.stderr


@pytest.mark.parametrize("route,servers", [("warp", OLD_LINKS), ("iface", OLD_LINKS), ("none", "")])
def test_main_section_that_is_not_on_vpn_is_left_alone(tmp_path, route, servers):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path, route=route, servers=servers)
    before = state(router)
    completed = run_script(result, router, env)
    assert completed.returncode != 0
    assert f"PSC_ERROR: The main section of Steer is not connected through VPN (now: {route})" in completed.stderr
    assert state(router) == before
    assert calls(router, "sub_set") == []


def test_missing_panel_or_unknown_status_fail_before_any_change(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    before = state(router)
    completed = run_script(result, router, {**env, "TEST_OLD_PANEL": "1"})
    assert completed.returncode != 0
    assert "PSC_ERROR: Steer did not report its main connection" in completed.stderr
    (router / "bin" / "jsonfilter").unlink()
    completed = run_script(result, router, env)
    assert completed.returncode != 0
    assert completed.stderr.strip() == "PSC_ERROR: Required command missing: jsonfilter"
    (router / "bin" / "backend.sh").unlink()
    completed = run_script(result, router, env)
    assert completed.returncode != 0
    assert completed.stderr.strip() == "PSC_ERROR: Zapret Manager is not installed: its panel backend was not found."
    assert state(router) == before
    assert calls(router, "sub_set") == []


def test_unreadable_current_servers_prevent_any_change(tmp_path):
    result = export(main_route(), config(tmp_path))
    # Reported as its own links, yet none can be read back: nothing could be restored.
    router, env = isolated_router(tmp_path, servers="proxies:\n  - name: opaque")
    before = state(router)
    completed = run_script(result, router, env)
    assert completed.returncode != 0
    assert "could not be restored after a failure. Nothing was changed." in completed.stderr
    assert state(router) == before
    assert calls(router, "sub_set") == []


def test_panel_refusal_is_reported_and_changes_nothing(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    before = state(router)
    completed = run_script(result, router, {**env, "TEST_BUSY": "1"})
    assert completed.returncode != 0
    assert "PSC_ERROR: Steer did not apply the new servers: дождитесь окончания текущей операции" in completed.stderr
    assert "PSC_ERROR: The previous servers are still in place." in completed.stderr
    assert state(router) == before
    assert len(calls(router, "sub_set")) == 1


def test_rejected_servers_leave_the_previous_list_and_show_the_panel_log(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    before = state(router)
    completed = run_script(result, router, {**env, "TEST_FAIL_VALIDATE": "1"})
    assert completed.returncode != 0
    assert "PSC_ERROR: Steer did not apply the new servers: the panel reported a failure while applying" in completed.stderr
    assert "PSC_LOG: ОШИБКА: в подписке нет узлов, с которыми умеет работать Steer" in completed.stderr
    assert "__DONE__" not in completed.stderr
    assert "PSC_ERROR: The previous servers are still in place." in completed.stderr
    assert state(router) == before
    assert len(calls(router, "sub_set")) == 1


@pytest.mark.parametrize("servers,url,resubmitted", [
    (OLD_LINKS, "", OLD_LINKS + "\n"),
    ("vless://fetched@192.0.2.50:443#From%20subscription", OLD_URL, OLD_URL + "\n"),
])
def test_failed_apply_restores_the_previous_servers(tmp_path, servers, url, resubmitted):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path, servers=servers, url=url)
    before = state(router)
    completed = run_script(result, router, {**env, "TEST_FAIL_APPLY": "first"})
    assert completed.returncode != 0
    assert "PSC_LOG: ОШИБКА: ядро steer не приняло настройки" in completed.stderr
    assert "Restoring the previous Steer servers" in completed.stdout
    assert completed.stderr.splitlines()[-1] == "PSC_ERROR: The previous servers were restored."
    assert state(router) == before
    assert [call["stdin"] for call in calls(router, "sub_set")] == [NODE + "\n", resubmitted]
    assert "old-secret" not in completed.stdout + completed.stderr


def test_failed_restore_says_so_and_points_to_the_panel(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    completed = run_script(result, router, {**env, "TEST_FAIL_APPLY": "always"})
    assert completed.returncode != 0
    assert completed.stderr.splitlines()[-1] == (
        "PSC_ERROR: The previous servers could not be restored (the panel reported a failure while applying). "
        "Set them again in the panel: Steer, Connection tab.")
    assert len(calls(router, "sub_set")) == 2


def test_panel_still_busy_after_the_wait_is_not_interrupted(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    # Keep the wait short; the production script allows five minutes.
    completed = run_script(result, router, {**env, "TEST_HANG": "1"},
                           edit=lambda script: script.replace('[ "$waited" -lt 300 ]', '[ "$waited" -lt 20 ]'))
    assert completed.returncode != 0
    assert "the panel is still working after 5 minutes" in completed.stderr
    assert completed.stderr.splitlines()[-1] == (
        "PSC_ERROR: The previous servers were not restored because the panel is still busy. Check Steer in the panel.")
    assert completed.stdout.splitlines() == ["Waiting for Steer: 10s", "Waiting for Steer: 20s"]
    assert len(calls(router, "sub_set")) == 1


def test_script_waits_for_a_slow_panel_and_notes_a_tunnel_that_is_down(tmp_path):
    result = export(main_route(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    completed = run_script(result, router, {**env, "TEST_SLOW": "4", "TEST_VPN_DOWN": "1"})
    assert completed.returncode == 0, completed.stderr
    assert len([call for call in calls(router) if call["args"] == ["job_status", "steer"]]) == 5
    assert completed.stdout.splitlines() == [
        "PSC_NOTE: Steer accepted the servers, but its VPN tunnel is not up yet. Check the panel.",
        "PSC_OK: Steer main servers replaced: 1 server",
    ]
    assert state(router)["sub.txt"] == NODE + "\n"


@pytest.mark.parametrize("cut", ["half", "before the call", "inside the server list"])
def test_script_cut_short_in_transit_changes_nothing_and_confirms_nothing(tmp_path, cut):
    result = export(two_servers(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    before = state(router)

    def truncate(script):
        if cut == "half":
            return script[:len(script) // 2]
        if cut == "before the call":
            return script[:script.rindex("psc_main")]
        return script[:script.index(OTHER)]

    completed = run_script(result, router, env, edit=truncate)
    assert "PSC_OK" not in completed.stdout
    assert state(router) == before
    assert calls(router) == []


def test_script_survives_a_child_that_drains_stdin(tmp_path):
    result = export(two_servers(), config(tmp_path))
    router, env = isolated_router(tmp_path)
    # Even without the /dev/null redirect, the shell has already read the whole script.
    completed = run_script(result, router, env, edit=lambda script: script.replace(
        '"$backend" "$@" </dev/null 2>/dev/null', '"$backend" "$@" 2>/dev/null'))
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == ["PSC_OK: Steer main servers replaced: 2 servers"]
    assert state(router)["sub.txt"] == NODE + "\n" + OTHER + "\n"
