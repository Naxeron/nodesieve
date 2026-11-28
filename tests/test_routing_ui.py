"""Editing local routing preferences and displaying them without credentials."""

from copy import deepcopy
import io
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from nodesieve.routing import normalize_routing
from nodesieve.ui.cli import build_parser, main
from nodesieve.ui.routing import format_routing, routing_menu


class RoutingMenuTests(unittest.TestCase):
    def edit(self, config, answers):
        replies = iter(answers)
        output = []
        result = routing_menu(config, input_fn=lambda _: next(replies), output_fn=output.append)
        return result, "\n".join(output)

    def test_defaults_show_exclusions_and_threshold_without_exposing_secrets(self):
        text = format_routing({
            "feed_token": "DO-NOT-PRINT",
            "subscriptions": ["https://secret.example/token"],
        })
        self.assertIn("Enabled: OFF", text)
        self.assertIn("Main proxy pool: automatic location ranking", text)
        self.assertIn("RU, BY, CN, IR, KP, SY, CU", text)
        self.assertIn("60% agreement", text)
        self.assertIn("3 valid reports per IP family", text)
        self.assertIn("All qualifying nodes; ranked by agreement, reports, then latency", text)
        self.assertIn("Steer then picks a working server by its own selection setting", text)
        self.assertIn("Steer's own services and devices still decide which traffic uses its main section", text)
        self.assertIn("Output directory: steer-output", text)
        self.assertTrue(text.startswith("Steer routing\n"))
        self.assertNotIn("DO-NOT-PRINT", text)
        self.assertNotIn("secret.example", text)

    def test_edit_preserves_unrelated_config_and_only_save_returns_new_config(self):
        config = {"feed_token": "keep", "routing": normalize_routing(None)}
        original = deepcopy(config)
        result, text = self.edit(config, ["1", "2", "ru, by", "3", "us de", "4", "75.5%", "4", "6"])
        self.assertEqual(config, original)
        self.assertEqual(result["routing"], {
            "enabled": True, "target": "steer", "default_policy": "preserve",
            "main": {"excluded_countries": ["RU", "BY"], "allowed_countries": ["US", "DE"],
                     "min_agreement": 0.755, "min_votes": 4},
        })
        self.assertEqual(result["feed_token"], "keep")
        self.assertIn("3 of 5 reports agreeing means 60%", text)
        self.assertIn("IPv4 and IPv6 are checked separately", text)

    def test_enable_toggles_and_save_aliases(self):
        result, _ = self.edit({}, ["1", "save"])
        self.assertTrue(result["routing"]["enabled"])
        result, _ = self.edit({"routing": {"enabled": True}}, ["1", "s"])
        self.assertFalse(result["routing"]["enabled"])

    def test_cancel_discards_draft_and_handles_eof(self):
        config = {"routing": normalize_routing(None)}
        original = deepcopy(config)
        for cancel in ("0", "q", "cancel"):
            result, text = self.edit(config, ["1", "2", "-", cancel])
            self.assertIsNone(result)
            self.assertEqual(config, original)
            self.assertIn("not saved", text)
        with patch("builtins.input", side_effect=EOFError):
            self.assertIsNone(routing_menu(config, output_fn=lambda _: None))

    def test_clear_country_lists_and_keep_blank_thresholds(self):
        routing = normalize_routing(None)
        routing["main"]["allowed_countries"] = ["US"]
        result, _ = self.edit({"routing": routing}, ["2", "-", "3", "-", "4", "", "", "2", "", "6"])
        self.assertEqual(result["routing"]["main"]["excluded_countries"], [])
        self.assertEqual(result["routing"]["main"]["allowed_countries"], [])
        self.assertEqual(result["routing"]["main"]["min_agreement"], 0.6)
        self.assertEqual(result["routing"]["main"]["min_votes"], 3)

    def test_invalid_preferences_leave_previous_settings(self):
        config = {"routing": normalize_routing(None)}
        for answers in (
            ["2", "not-a-country", "6"],
            ["3", "ru", "6"],
            ["4", "101", "3", "6"],
            ["4", "60", "0", "6"],
            ["4", "many", "three", "6"],
        ):
            with self.subTest(answers=answers):
                result, text = self.edit(config, answers)
                self.assertEqual(result, config)
                self.assertIn("settings were not changed", text)
        result, text = self.edit(config, ["7", "6"])
        self.assertEqual(result, config)
        self.assertIn("Choose a number from 0 to 6", text)

    def test_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result, text = self.edit({}, ["5", directory, "6"])
            self.assertEqual(result["routing_output_dir"], directory)
            self.assertIn("Output directory: " + directory, text)
            result, _ = self.edit(result, ["5", "", "6"])
            self.assertEqual(result["routing_output_dir"], os.path.abspath("steer-output"))

    def test_settings_routing_does_not_know_are_refused(self):
        for routing in ({"target": "forkozz"}, {"services": {}}, {"main": {"mode": "location"}}):
            with self.subTest(routing=routing), self.assertRaises(ValueError):
                routing_menu({"routing": routing}, input_fn=lambda _: "0", output_fn=lambda _: None)


class RoutingCLITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config_file = os.path.join(self.directory.name, "config.json")
        with open(self.config_file, "w", encoding="utf-8") as stream:
            json.dump({"feed_token": "private-feed-token"}, stream)

    def invoke(self, args, tty=False, menu_result=None):
        with (
            patch("nodesieve.ui.cli.sys.stdin.isatty", return_value=tty),
            patch("nodesieve.ui.cli.routing_menu", return_value=menu_result) as menu,
            patch("nodesieve.ui.cli.VPNDashboard") as dashboard,
            patch("sys.stdout", new_callable=io.StringIO) as output,
            self.assertRaises(SystemExit) as raised,
        ):
            main(["--config-file", self.config_file, *args])
        dashboard.assert_not_called()
        return raised.exception.code, output.getvalue(), menu

    def test_routing_action_nonterminal_prints_and_does_not_prompt(self):
        code, text, menu = self.invoke(["routing"])
        self.assertEqual(code, 0)
        self.assertIn("Main proxy pool: automatic location ranking", text)
        self.assertNotIn("private-feed-token", text)
        menu.assert_not_called()

    def test_routing_show_never_prompts_even_in_terminal_and_applies_overrides(self):
        code, text, menu = self.invoke(["--routing-show", "--rank-by", "location", "--output-dir", "example-output"], tty=True)
        self.assertEqual(code, 0)
        self.assertIn("Enabled: ON", text)
        self.assertIn(os.path.abspath("example-output"), text)
        menu.assert_not_called()

    def test_setup_requires_terminal_without_attempting_input(self):
        code, _, menu = self.invoke(["--routing-setup"])
        self.assertEqual(code, 1)
        menu.assert_not_called()

    def test_routing_terminal_saves_to_requested_config_file(self):
        routing = normalize_routing(None)
        routing["enabled"] = True
        code, text, menu = self.invoke(["routing"], tty=True, menu_result={"routing": routing})
        self.assertEqual(code, 0)
        self.assertIn("Saved routing preferences", text)
        menu.assert_called_once()
        with open(self.config_file, encoding="utf-8") as stream:
            self.assertTrue(json.load(stream)["routing"]["enabled"])

    def test_conflicting_actions_never_launch_pipeline_or_editor(self):
        for args in (
            ["routing", "--dry-run"], ["check", "--routing-show"],
            ["--routing-setup", "--dry-run"], ["config", "--routing-show"],
            ["routing", "--add-sub", "https://example.test"],
        ):
            with self.subTest(args=args):
                code, _, menu = self.invoke(args, tty=True)
                self.assertEqual(code, 1)
                menu.assert_not_called()

    def test_config_display_receives_rank_by_override(self):
        code, text, _ = self.invoke(["config", "--rank-by", "location"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(text)["routing"]["enabled"])

    def test_rank_by_speed_disables_previously_enabled_routing_for_pipeline(self):
        routing = normalize_routing(None)
        routing["enabled"] = True
        with open(self.config_file, "w", encoding="utf-8") as stream:
            json.dump({"routing": routing}, stream)
        with patch("nodesieve.ui.cli.VPNDashboard") as dashboard:
            dashboard.return_value.run_pipeline_async = AsyncMock(return_value=True)
            main(["--config-file", self.config_file, "check", "--rank-by", "speed"])
        self.assertFalse(dashboard.call_args.kwargs["config"]["routing"]["enabled"])
        with open(self.config_file, encoding="utf-8") as stream:
            self.assertTrue(json.load(stream)["routing"]["enabled"])

    def test_unknown_routing_settings_are_refused_before_anything_runs(self):
        for routing in ({"enabled": False, "main": {"mode": "preserve"}}, {"enabled": True, "services": {}},
                        {"enabled": True, "target": "forkozz"}):
            with open(self.config_file, "w", encoding="utf-8") as stream:
                json.dump({"routing": routing}, stream)
            for args in (["--routing-show"], ["check", "--rank-by", "location"], ["check"]):
                with self.subTest(routing=routing, args=args):
                    code, _, menu = self.invoke(args, tty=True)
                    self.assertEqual(code, 1)
                    menu.assert_not_called()

    def test_parser_accepts_rank_by_location_and_rejects_removed_or_ambiguous_flags(self):
        args = build_parser().parse_args(["check", "--rank-by", "location", "--output-dir", "out"])
        self.assertEqual((args.rank_by, args.routing_output_dir), ("location", "out"))
        for removed in (["--target", "steer"], ["--rank-by", "forkozz"], ["--forkozz-config", "netshift.uci"], ["--routing-setup", "--routing-show"]):
            with self.subTest(removed=removed), self.assertRaises(SystemExit):
                build_parser().parse_args(removed)

    def test_empty_output_directory_is_refused(self):
        code, _, menu = self.invoke(["--routing-show", "--output-dir", "  "])
        self.assertEqual(code, 1)
        menu.assert_not_called()


if __name__ == "__main__":
    unittest.main()
