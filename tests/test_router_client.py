"""RouterClient: the SSH commands and file streams install-router uses."""

import importlib.util
import unittest
from unittest.mock import MagicMock, patch

from nodesieve.router.client import RouterClient

# Paramiko is optional in Termux; the tests that patch it need it installed.
needs_paramiko = unittest.skipUnless(importlib.util.find_spec("paramiko"), "Paramiko is not installed")


class TestRouterClientSSH(unittest.TestCase):
    """Unit tests for RouterClient Paramiko SSH operations using mocks."""

    def setUp(self):
        self.client = RouterClient(
            host="192.168.1.1", ssh_port=22, ssh_user="root", ssh_pass="test-password"
        )

    def test_exec_command_success(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"root\n"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            code, out, err = self.client.exec_command("whoami")
            self.assertEqual(code, 0)
            self.assertEqual(out, "root\n")
            self.assertEqual(err, "")
            mock_ssh.exec_command.assert_called_once_with(
                "whoami", timeout=15.0
            )
            mock_ssh.close.assert_called_once()

    def test_exec_command_non_zero_status(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"sh: command not found\n"
        mock_stdout.channel.recv_exit_status.return_value = 127
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            code, out, err = self.client.exec_command("invalid_command")
            self.assertEqual(code, 127)
            self.assertIn("command not found", err)
            mock_ssh.close.assert_called_once()

    def test_exec_command_exception(self):
        with patch.object(
            self.client,
            "_create_ssh",
            side_effect=Exception("SSH connect timeout"),
        ):
            code, out, err = self.client.exec_command("uptime")
            self.assertEqual(code, -1)
            self.assertEqual(out, "")
            self.assertIn("SSH connect timeout", err)

    def test_stream_file_to_router_success(self):
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

        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            content = "#!/bin/sh\necho deployed\n"
            ok = self.client.stream_file_to_router(
                content, "/tmp/script.sh", mode="0755"
            )
            self.assertTrue(ok)
            mock_stdin.write.assert_called_once_with(content)
            mock_stdin.flush.assert_called_once()
            mock_stdin.channel.shutdown_write.assert_called_once()
            mock_ssh.close.assert_called_once()

    def test_stream_file_to_router_failure_exit_status(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_stderr.read.return_value = b"Read-only file system\n"
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            ok = self.client.stream_file_to_router("content", "/tmp/fail.txt")
            self.assertFalse(ok)
            mock_ssh.close.assert_called_once()

    def test_stream_file_to_router_exception(self):
        mock_ssh = MagicMock()
        mock_ssh.exec_command.side_effect = Exception("Broken pipe")

        with patch.object(self.client, "_create_ssh", return_value=mock_ssh):
            ok = self.client.stream_file_to_router("content", "/tmp/fail.txt")
            self.assertFalse(ok)
            mock_ssh.close.assert_called_once()

    @needs_paramiko
    def test_create_ssh_parameters(self):
        with patch("paramiko.SSHClient") as mock_ssh_cls:
            mock_inst = MagicMock()
            mock_ssh_cls.return_value = mock_inst
            client = RouterClient(
                host="10.0.0.1",
                ssh_port=2222,
                ssh_user="admin",
                ssh_pass="secret",
            )
            created = client._create_ssh()
            self.assertEqual(created, mock_inst)
            mock_inst.connect.assert_called_once_with(
                hostname="10.0.0.1",
                port=2222,
                username="admin",
                password="secret",
                timeout=5.0,
                banner_timeout=5.0,
            )

    def test_stream_file_to_router_raw_bytes(self):
        client = RouterClient(host="192.168.1.1")
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

        with patch.object(client, "_create_ssh", return_value=mock_ssh):
            binary_data = b"\x80\x81\x82\xfe\xff"
            ok = client.stream_file_to_router(binary_data, "/tmp/raw.bin")
            self.assertTrue(ok)
            mock_stdin.channel.sendall.assert_called_once_with(binary_data)
            mock_stdin.flush.assert_called_once()
            mock_stdin.channel.shutdown_write.assert_called_once()

    def test_exec_command_timeout_error_message(self):
        client = RouterClient(host="192.168.1.1")
        mock_ssh = MagicMock()
        mock_ssh.exec_command.side_effect = TimeoutError()

        with patch.object(client, "_create_ssh", return_value=mock_ssh):
            code, out, err = client.exec_command("sleep 10", timeout=1.0)
            self.assertEqual(code, -1)
            self.assertEqual(out, "")
            self.assertTrue(len(err) > 0)
            self.assertIn("timed out", err)

    def test_without_paramiko_ssh_says_what_to_install(self):
        client = RouterClient(host="192.0.2.1")
        with patch.dict("sys.modules", {"paramiko": None}):
            code, out, err = client.exec_command("true")
        self.assertEqual((code, out), (-1, ""))
        self.assertIn("pip install paramiko", err)


def test_router_exec_streams_stdin_and_closes_the_connection():
    router = RouterClient()
    ssh, stdin, stdout, stderr = [MagicMock() for _ in range(4)]
    ssh.exec_command.return_value = (stdin, stdout, stderr)
    stdout.read.return_value = b"ok"
    stderr.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    with patch.object(router, "_create_ssh", return_value=ssh):
        assert router.exec_command("/bin/sh -s", stdin_data="echo ok\n") == (0, "ok", "")
    stdin.write.assert_called_once_with("echo ok\n")
    stdin.channel.shutdown_write.assert_called_once()
    ssh.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
