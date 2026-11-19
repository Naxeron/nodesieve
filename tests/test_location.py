"""Location evidence is provider consensus, with bounded proxy-only subprocesses."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import unittest
import urllib.parse
from unittest.mock import AsyncMock, MagicMock, patch

from proxy_sites.location import empty_location, parse_ipregion, probe_ipregion
from proxy_sites.core.tester import NodeTester
from proxy_sites.routing import main_policy_failure, normalize_routing


AUTO = object()


def address(ip):
    """ipregion's description of one exit address, or null when it found none."""
    if not ip:
        return None
    return {"ip": ip, "asn": 64496, "org": "Example Hosting", "registered": "DE", "maxmind_failure": None}


def answer(country=None, reason=None):
    return {"country": country, "access": None, "reason": reason}


def cell(values, index):
    """One provider's answer for a family; null when ipregion did not check that family."""
    if not values:
        return None
    value = values[index] if index < len(values) else None
    return answer(reason="timeout") if value is None else answer(value)


def report(v4=("DE", "DE", "DE", "US"), v6=(), ipv4=AUTO, ipv6=AUTO, **extra):
    """An ipregion version 2 JSON report as printed by `ipregion.sh -j -g geoip`."""
    records = [{"id": f"provider_{i}", "service": f"provider-{i}", "ipv4": cell(v4, i), "ipv6": cell(v6, i),
                "proxy": None} for i in range(max(len(v4), len(v6)))]
    if ipv4 is AUTO:
        ipv4 = "192.0.2.5" if v4 else None
    if ipv6 is AUTO:
        ipv6 = "2001:db8::5" if v6 else None
    return {"version": 2, "ipv4": address(ipv4), "ipv6": address(ipv6),
            "verdict": {"country": None, "tied": []}, "attention": [],
            "results": {"platforms": [], "cdn": [], "availability": [], "ai": [], "geoip": records}, **extra}


class TestLocationConsensus(unittest.TestCase):
    def test_majority_and_private_summary(self):
        evidence = parse_ipregion(report())
        self.assertEqual((evidence["country"], evidence["score"], evidence["votes"], evidence["total"]), ("DE", .75, 3, 4))
        self.assertEqual(evidence["counts"], {"DE": 3, "US": 1})
        self.assertEqual(evidence["tested_families"], ["ipv4"])
        self.assertNotIn("192.0.2.5", json.dumps(evidence))
        self.assertIsNone(main_policy_failure(normalize_routing({})["main"], evidence))

    def test_ties_are_unknown(self):
        evidence = parse_ipregion(report(("DE", "US")))
        self.assertIsNone(evidence["country"])
        self.assertEqual(evidence["status"], "unknown")
        self.assertEqual(evidence["score"], .5)

    def test_statuses_non_countries_and_other_groups_do_not_vote(self):
        data = report(("DE", "Timeout", "Error", "XX", "ZZ", "EU", "AP", "UN", "N/A", "", None, 42))
        extra = {"id": "extra", "service": "extra", "ipv4": answer("US"), "ipv6": None, "proxy": None}
        for group in ("platforms", "cdn", "availability", "ai"):
            data["results"][group] = [extra] * 50
        # An answer that is not tied to an IP family is not evidence for either one.
        data["results"]["geoip"].append(
            {"id": "unplaced", "service": "unplaced", "ipv4": None, "ipv6": None, "proxy": answer("US")})
        self.assertEqual(parse_ipregion(data)["counts"], {"DE": 1})

    def test_failed_lookups_and_the_family_a_proxy_did_not_use_do_not_vote(self):
        data = report(("DE",) * 4, ("DE",) * 4)
        rows = data["results"]["geoip"]
        rows[0]["ipv4"] = answer(reason="proxy picked IPv6")
        rows[1]["ipv6"] = answer(reason="rate limited (429)")
        evidence = parse_ipregion(data)
        self.assertEqual(evidence["families"]["ipv4"]["counts"], {"DE": 3})
        self.assertEqual(evidence["families"]["ipv6"]["counts"], {"DE": 3})
        self.assertEqual((evidence["country"], evidence["total"]), ("DE", 6))
        self.assertEqual(evidence["tested_families"], ["ipv4", "ipv6"])

    def test_duplicates_count_once_and_conflicting_duplicate_is_excluded(self):
        data = report(("DE", "DE", "US"))
        rows = data["results"]["geoip"]
        rows += [dict(rows[0])] * 8
        rows.append({"id": "PROVIDER_1", "service": "provider-1", "ipv4": answer("US")})
        evidence = parse_ipregion(data)
        self.assertEqual(evidence["counts"], {"DE": 1, "US": 1})
        self.assertEqual(evidence["total"], 2)

    def test_each_family_remains_independent(self):
        evidence = parse_ipregion(report(("DE",) * 6, ("RU",) * 3))
        self.assertEqual(evidence["country"], "DE")
        self.assertEqual(evidence["families"]["ipv6"]["country"], "RU")
        self.assertIsNotNone(main_policy_failure(normalize_routing({})["main"], evidence))

    def test_missing_known_family_cannot_be_hidden(self):
        evidence = parse_ipregion(report(), families=["ipv4", "ipv6"])
        self.assertEqual(evidence["tested_families"], ["ipv4", "ipv6"])
        self.assertEqual(evidence["families"]["ipv6"]["total"], 0)
        self.assertIsNotNone(main_policy_failure(normalize_routing({})["main"], evidence))

    def test_discovered_family_without_votes_is_still_required(self):
        evidence = parse_ipregion(report(ipv6="2001:db8::1"))
        self.assertEqual(evidence["tested_families"], ["ipv4", "ipv6"])
        self.assertEqual(evidence["families"]["ipv6"]["country"], None)

    def test_real_ip_leak_and_malformed_json_fail_closed(self):
        evidence = parse_ipregion(report(), real_ip="192.0.2.5")
        self.assertTrue(evidence["ip_leak"])
        self.assertEqual(evidence["status"], "failed")
        for invalid in (b"", "{}", "[]", "not json", {"version": 2, "results": {"geoip": None}}):
            self.assertEqual(parse_ipregion(invalid)["status"], "failed")

    def test_report_from_another_ipregion_version_fails_closed(self):
        version_1 = {"version": 1, "ipv4": "192.0.2.5", "ipv6": None,
                     "results": {"primary": [{"service": "MAXMIND", "ipv4": "DE", "ipv6": None}] * 4}}
        for other in (version_1, {**report(), "version": 3}, {**report(), "version": None}):
            evidence = parse_ipregion(other)
            self.assertEqual(evidence["status"], "failed")
            self.assertIn("version", evidence["reason"])
            self.assertEqual(evidence["total"], 0)


class TestLocationSubprocess(unittest.IsolatedAsyncioTestCase):
    async def test_real_timeout_leaves_no_running_child_process(self):
        bash = shutil.which("bash")
        if not bash or not Path("/proc").is_dir():
            self.skipTest("Requires Linux process groups and bash")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "probe.sh"
            child_pid_file = Path(directory) / "child.pid"
            script.write_text("#!/bin/bash\n(trap '' TERM; echo $BASHPID > \"$PSC_CHILD_PID\"; sleep 30) &\nwait\n")
            with patch.dict(os.environ, {"PSC_CHILD_PID": str(child_pid_file)}), \
                    patch("proxy_sites.location.shutil.which", return_value=bash):
                evidence = await probe_ipregion(script, "127.0.0.1:23456", timeout=.1)
            self.assertEqual(evidence["reason"], "ipregion timed out")
            self.assertTrue(child_pid_file.is_file())
            status = Path("/proc") / child_pid_file.read_text().strip() / "status"
            if status.exists():
                self.assertRegex(status.read_text(), r"State:\s+Z\b")

    async def test_proxy_command_dependencies_and_no_bypass_environment(self):
        process = MagicMock(pid=54321)
        process.communicate = AsyncMock(return_value=(json.dumps(report()).encode(), b""))
        # Only what the bundled script itself needs: column and nslookup are no longer used.
        installed = {"bash", "jq", "curl"}
        with patch("proxy_sites.location.shutil.which",
                   side_effect=lambda name: "/usr/bin/" + name if name in installed else None), \
                patch("proxy_sites.location.Path.is_file", return_value=True), \
                patch("proxy_sites.location.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            evidence = await probe_ipregion("/tmp/ipregion.sh", "127.0.0.1:23456", families=["ipv4"])
        self.assertEqual(evidence["country"], "DE")
        self.assertEqual(spawn.call_args.args, (
            "/usr/bin/bash", "/tmp/ipregion.sh", "-p", "127.0.0.1:23456", "-j", "-g", "geoip", "-t", "2"))
        self.assertNotIn("-4", spawn.call_args.args)
        self.assertNotIn("-6", spawn.call_args.args)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.assertEqual(spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["env"]["NO_PROXY"], "")

    async def test_missing_dependencies_do_not_launch_installer(self):
        with patch("proxy_sites.location.shutil.which", return_value=None), \
                patch("proxy_sites.location.asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            evidence = await probe_ipregion("ipregion.sh", "127.0.0.1:23456")
        self.assertEqual(evidence["status"], "failed")
        self.assertIn("Missing dependencies", evidence["reason"])
        spawn.assert_not_awaited()

    async def test_timeout_and_cancellation_kill_entire_process_group(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                started, finish = asyncio.Event(), asyncio.Event()
                async def communicate():
                    started.set()
                    await finish.wait()
                    return b"", b""
                process = MagicMock(pid=54321)
                process.communicate = communicate
                process.wait = AsyncMock(return_value=-9)
                def kill_group(pid, sig):
                    if sig == signal.SIGTERM:
                        finish.set()
                with patch("proxy_sites.location.shutil.which", return_value="/usr/bin/tool"), \
                        patch("proxy_sites.location.Path.is_file", return_value=True), \
                        patch("proxy_sites.location.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)), \
                        patch("proxy_sites.location.os.killpg", side_effect=kill_group) as kill:
                    task = asyncio.create_task(probe_ipregion("/tmp/script.sh", "127.0.0.1:23456", timeout=.01))
                    await started.wait()
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        self.assertEqual((await task)["reason"], "ipregion timed out")
                self.assertEqual([call.args for call in kill.call_args_list], [(54321, signal.SIGTERM), (54321, signal.SIGKILL)])


class TestMainLocationIntegration(unittest.IsolatedAsyncioTestCase):
    async def _run(self, location, trace=(None, None, float("inf"))):
        tester = NodeTester({"routing": {"enabled": True}}, real_ip="198.51.100.1")
        node = "vless://abc@192.0.2.1:443?encryption=foo#original"
        runner = MagicMock(proxy_url="http://127.0.0.1:23456", port=23456)
        with patch("proxy_sites.core.tester.MihomoRunner") as runner_cls, \
                patch("proxy_sites.core.tester.aiohttp.ClientSession") as session_cls, \
                patch("proxy_sites.core.tester.aiohttp.TCPConnector") as connector_cls, \
                patch.object(tester, "_fetch_ip", new=AsyncMock(return_value=trace)), \
                patch.object(tester, "fetch_location", new=AsyncMock(return_value=location)) as location_probe, \
                patch("proxy_sites.core.tester.GeolocationService.get_country_name", new=AsyncMock(return_value="Germany")):
            runner_cls.return_value.__aenter__ = AsyncMock(return_value=runner)
            runner_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            session_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await tester.test_node_full(1, node)
        connector_cls.assert_called_once_with(ssl=True, limit=10)
        return result, tester.node_metadata[node], location_probe

    async def test_main_qualifies_when_cloudflare_trace_fails(self):
        evidence = parse_ipregion(report())
        result, metadata, probe = await self._run(evidence)
        self.assertIsNotNone(result)
        self.assertEqual(metadata["loc_score"], .75)
        self.assertEqual(metadata["location"], evidence)
        self.assertEqual(metadata["country_code"], "DE")
        probe.assert_awaited_once_with(23456, None, None)

    async def test_survivor_is_renamed_with_consensus_and_keeps_shared_metadata(self):
        result, metadata, _ = await self._run(parse_ipregion(report()), trace=("192.0.2.5", "US", 10))
        survivor, latency, tested = result
        self.assertEqual(latency, 10)
        self.assertEqual(tested, "vless://abc@192.0.2.1:443?encryption=none#original")
        self.assertEqual(
            urllib.parse.unquote(survivor.split("#", 1)[1]),
            "[VLESS: original] \U0001F1E9\U0001F1EA Germany | 192.0.2.5 | Location DE 75% (3/4 votes)",
        )
        self.assertEqual(metadata["latency_ms"], 10)

    async def test_restricted_or_weak_location_is_dropped_with_its_evidence(self):
        for evidence, reason in (
            (parse_ipregion(report(("RU",) * 3)), "Location country excluded: RU"),
            (parse_ipregion(report(("DE", "DE"))), "Too few location reports"),
        ):
            with self.subTest(reason=reason):
                result, metadata, _ = await self._run(evidence, trace=("192.0.2.5", "DE", 10))
                self.assertIsNone(result)
                self.assertTrue(metadata["dropped"])
                self.assertEqual(metadata["reason"], reason)
                self.assertEqual(metadata["location"], evidence)

    async def test_tied_consensus_does_not_fall_back_to_single_provider_country_label(self):
        result, metadata, _ = await self._run(parse_ipregion(report(("DE", "FI"))), trace=("192.0.2.5", "DE", 10))
        self.assertIsNone(result)
        self.assertIsNone(metadata["country_code"])
        self.assertIn("tied", metadata["reason"])

    async def test_failed_probe_reports_why_location_is_unknown(self):
        result, metadata, _ = await self._run(empty_location("failed", "ipregion timed out", ("ipv4",)))
        self.assertIsNone(result)
        self.assertEqual(metadata["reason"], "Location probe failed: ipregion timed out")

    async def test_leaked_ip_discovered_by_ipregion_drops_the_node(self):
        evidence = parse_ipregion(report(ipv4="198.51.100.1"), real_ip="198.51.100.1")
        result, metadata, _ = await self._run(evidence)
        self.assertIsNone(result)
        self.assertEqual(metadata["reason"], "Proxy leaks real IP")

    async def test_legacy_score_api_uses_allowed_country_votes(self):
        tester = NodeTester({})
        with patch.object(tester, "fetch_location", new=AsyncMock(return_value=parse_ipregion(report()))):
            self.assertEqual(await tester.fetch_loc_score(23456, ["DE"]), .75)
            self.assertEqual(await tester.fetch_loc_score(23456, ["US"]), .25)
            self.assertEqual(await tester.fetch_loc_score(23456, []), 0)
