"""Adversarial stress-test suite for RouterClient and pusher.py.

Evaluates failure modes, edge cases, payload boundaries, shell injections,
and exit code propagation contracts.
"""

import os
import shlex
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from nodesieve.router.client import RouterClient
from nodesieve.router.pusher import push_to_router

ROUTER_HOST = "192.168.1.1"
ROUTER_SSH_PORT = 22
ROUTER_REST_PORT = 9090


def is_live_ssh_available() -> bool:
    """Checks if live router SSH is reachable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        res = s.connect_ex((ROUTER_HOST, ROUTER_SSH_PORT))
        s.close()
        return res == 0
    except Exception:
        return False


class TestStreamFileToRouterMock(unittest.TestCase):
    """Adversarial unit tests for stream_file_to_router using mocks."""

    def setUp(self):
        self.client = RouterClient(host="192.168.1.1", ssh_port=22)

    def test_special_shell_characters_in_remote_path_are_quoted(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        bad_path = "/tmp/test; rm -rf /; `reboot` $VAR 'single' \"double\""
        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            ok = self.client.stream_file_to_router("content", bad_path)
            self.assertTrue(ok)
            expected_quoted = shlex.quote(bad_path)
            call_cmd = mock_ssh.exec_command.call_args[0][0]
            self.assertIn(f"cat > {expected_quoted}", call_cmd)
            self.assertIn(
                f"chmod {shlex.quote('0644')} {expected_quoted}", call_cmd
            )

    def test_mode_parameter_injection_is_quoted(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        malicious_mode = "0755; touch /tmp/pwned"
        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            ok = self.client.stream_file_to_router(
                "content", "/tmp/file.txt", mode=malicious_mode
            )
            self.assertTrue(ok)
            expected_mode = shlex.quote(malicious_mode)
            call_cmd = mock_ssh.exec_command.call_args[0][0]
            self.assertIn(f"chmod {expected_mode}", call_cmd)

    def test_bytes_payload_raw_bytes_streamed_without_decoding(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        invalid_bytes = b"\x80\x81\xff\xfe\xaa"
        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            ok = self.client.stream_file_to_router(
                invalid_bytes, "/tmp/bytes.bin"
            )
            self.assertTrue(ok)
            mock_stdin.channel.sendall.assert_called_once_with(invalid_bytes)

    def test_ssh_connection_failure_returns_false(self):
        with patch.object(
            self.client,
            "_create_ssh",
            side_effect=Exception("SSH connection refused"),
        ):
            ok = self.client.stream_file_to_router("content", "/tmp/file.txt")
            self.assertFalse(ok)


class TestStreamFileToRouterHardware(unittest.TestCase):
    """Hardware-in-the-loop stress tests against physical OpenWrt router."""

    def setUp(self):
        if not is_live_ssh_available():
            self.skipTest(f"Live router SSH at {ROUTER_HOST} is offline")
        self.client = RouterClient(host=ROUTER_HOST, ssh_port=ROUTER_SSH_PORT)

    def test_streaming_large_payloads(self):
        """Streams 512KB, 1MB, 2MB payloads and verifies remote byte counts."""
        for size_kb in [512, 1024, 2048]:
            content = "X" * (size_kb * 1024)
            remote_path = f"/tmp/adversarial_test_{size_kb}k.tmp"
            ok = self.client.stream_file_to_router(content, remote_path)
            self.assertTrue(ok, f"Failed streaming {size_kb}KB payload")

            code, out, _ = self.client.exec_command(f"wc -c {remote_path}")
            self.assertEqual(code, 0)
            byte_count = int(out.strip().split()[0])
            self.assertEqual(byte_count, size_kb * 1024)

            self.client.exec_command(f"rm -f {remote_path}")

    def test_multibyte_unicode_and_special_strings(self):
        """Verifies exact round-trip string preservation across alphabets."""
        unicode_corpus = {
            "chinese": "你好世界，测试节点：Gemini 节点 123",
            "japanese": "こんにちは世界！nodesieveテスト 🇯🇵",
            "russian": "Привет, мир! Тестирование маршрутизатора OpenWrt 🇷🇺",
            "emojis": "🚀⚡🔥🎉🛡️🤖 🇭🇰 🇯🇵 🇺🇸 🇸🇬",
            "arabic": "مرحبا بالعالم اختبار التوجيه",
            "mixed_symbols": "double\" quote 'single' `backtick` $VAR %",
            "newlines_and_tabs": "line1\r\nline2\twith\ttabs\r\nline3\n",
        }

        for name, text in unicode_corpus.items():
            remote_path = f"/tmp/test_unicode_{name}.txt"
            ok = self.client.stream_file_to_router(text, remote_path)
            self.assertTrue(ok, f"Failed streaming unicode corpus: {name}")

            code, out, _ = self.client.exec_command(f"cat {remote_path}")
            self.assertEqual(code, 0)
            self.assertEqual(out, text)
            self.client.exec_command(f"rm -f {remote_path}")

    def test_special_shell_characters_in_remote_path(self):
        """Verifies safe handling of paths with quotes, spaces, and symbols."""
        paths = [
            "/tmp/test space.txt",
            "/tmp/test\"doublequote.txt",
            "/tmp/test'singlequote.txt",
            "/tmp/test$dollar.txt",
            "/tmp/test`backtick`.txt",
            "/tmp/test;semicolon.txt",
            "/tmp/test&ampersand.txt",
        ]

        for p in paths:
            ok = self.client.stream_file_to_router("sample_payload", p)
            self.assertTrue(ok, f"Failed streaming to special path: {p}")

            quoted = shlex.quote(p)
            code, out, _ = self.client.exec_command(f"cat {quoted}")
            self.assertEqual(code, 0)
            self.assertEqual(out, "sample_payload")
            self.client.exec_command(f"rm -f {quoted}")

    def test_failure_on_nonexistent_directory(self):
        """Verifies stream fails gracefully when directory does not exist."""
        ok = self.client.stream_file_to_router(
            "data", "/nonexistent_dir_8888/test.txt"
        )
        self.assertFalse(ok)

    def test_failure_on_directory_target(self):
        """Verifies stream fails gracefully when target path is a directory."""
        ok = self.client.stream_file_to_router("data", "/tmp")
        self.assertFalse(ok)

    def test_failure_on_invalid_chmod_mode(self):
        """Verifies stream fails when chmod mode argument is invalid."""
        ok = self.client.stream_file_to_router(
            "data", "/tmp/test_mode.txt", mode="9999"
        )
        self.assertFalse(ok)
        self.client.exec_command("rm -f /tmp/test_mode.txt")

    def test_mode_command_injection_prevention(self):
        """Verifies chmod command injection attempts fail and do not run."""
        injected_mode = "0755; touch /tmp/adversarial_pwned"
        ok = self.client.stream_file_to_router(
            "data", "/tmp/test_inject.txt", mode=injected_mode
        )
        self.assertFalse(ok)

        code, _, _ = self.client.exec_command(
            "test -f /tmp/adversarial_pwned"
        )
        self.assertNotEqual(code, 0, "Injected command must not execute")
        clean_cmd = "rm -f /tmp/test_inject.txt /tmp/adversarial_pwned"
        self.client.exec_command(clean_cmd)


class TestPusherAdversarial(unittest.TestCase):
    """Adversarial tests for pusher.py edge cases and failure modes."""

    def test_push_missing_script_file_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing = os.path.join(tmp_dir, "missing.sh")
            with patch("nodesieve.router.pusher.ROUTER_SCRIPT_FILE", missing):
                res = push_to_router()
                self.assertFalse(res)

    def test_push_unreadable_script_file_returns_false(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/sh\necho hi\n")
            unreadable = f.name

        os.chmod(unreadable, 000)
        try:
            with patch(
                "nodesieve.router.pusher.ROUTER_SCRIPT_FILE", unreadable
            ):
                res = push_to_router()
                self.assertFalse(res)
        finally:
            os.chmod(unreadable, 0o600)
            os.unlink(unreadable)

    def test_push_unreachable_router_returns_false(self):
        unreachable = RouterClient(host="192.0.2.1")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/sh\necho hi\n")
            script_path = f.name

        try:
            with patch.object(
                unreachable,
                "_create_ssh",
                side_effect=socket.timeout("SSH connect timeout"),
            ):
                with patch(
                    "nodesieve.router.pusher.ROUTER_SCRIPT_FILE", script_path
                ):
                    res = push_to_router(router_client=unreachable)
                    self.assertFalse(res)
        finally:
            os.unlink(script_path)

    def test_shell_compound_command_preserves_exit_code(self):
        """Verifies that '; rc=$?; rm -f ...; exit $rc' preserves exit code."""
        cmd = (
            "/bin/sh /tmp/apply_to_router.sh; rc=$?; "
            "rm -f /tmp/apply_to_router.sh; exit $rc"
        )
        with open("/tmp/apply_to_router.sh", "w") as f:
            f.write("#!/bin/sh\nexit 42\n")

        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        self.assertEqual(
            res.returncode,
            42,
            "Non-zero exit code must be preserved after rm -f",
        )
        self.assertFalse(os.path.exists("/tmp/apply_to_router.sh"))

    def test_push_to_router_detects_script_runtime_failure(self):
        """Tests that push_to_router() returns False on script failure."""
        mock_client = MagicMock()
        mock_client.stream_file_to_router.return_value = True

        def realistic_shell_exec(cmd, timeout=15.0):
            res = subprocess.run(
                cmd, shell=True, capture_output=True, text=True
            )
            return res.returncode, res.stdout, res.stderr

        mock_client.exec_command.side_effect = realistic_shell_exec

        with tempfile.TemporaryDirectory() as tmp_dir:
            script_path = os.path.join(tmp_dir, "apply_to_router.sh")
            with open(script_path, "w") as f:
                f.write("#!/bin/sh\necho 'Service failed' >&2\nexit 1\n")

            with open("/tmp/apply_to_router.sh", "w") as f:
                f.write("#!/bin/sh\necho 'Service failed' >&2\nexit 1\n")

            with patch(
                "nodesieve.router.pusher.ROUTER_SCRIPT_FILE", script_path
            ):
                res = push_to_router(router_client=mock_client)
                self.assertFalse(
                    res,
                    "push_to_router() must return False on non-zero exit code",
                )

    def test_push_to_router_detects_script_syntax_error(self):
        """Tests that push_to_router() returns False on script syntax error."""
        mock_client = MagicMock()
        mock_client.stream_file_to_router.return_value = True

        def realistic_shell_exec(cmd, timeout=15.0):
            res = subprocess.run(
                cmd, shell=True, capture_output=True, text=True
            )
            return res.returncode, res.stdout, res.stderr

        mock_client.exec_command.side_effect = realistic_shell_exec

        with tempfile.TemporaryDirectory() as tmp_dir:
            script_path = os.path.join(tmp_dir, "apply_to_router.sh")
            with open(script_path, "w") as f:
                f.write("#!/bin/sh\nif [ ; then fi\n")

            with open("/tmp/apply_to_router.sh", "w") as f:
                f.write("#!/bin/sh\nif [ ; then fi\n")

            with patch(
                "nodesieve.router.pusher.ROUTER_SCRIPT_FILE", script_path
            ):
                res = push_to_router(router_client=mock_client)
                self.assertFalse(
                    res,
                    "push_to_router() must return False on syntax error",
                )


if __name__ == "__main__":
    unittest.main()
