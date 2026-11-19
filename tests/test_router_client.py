"""Unit tests for RouterClient, ssh_router.py, and pusher.py."""

import os
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import aiohttp
from aiohttp import web

from proxy_sites.router.client import RouterClient
from proxy_sites.router.pusher import push_to_router
import ssh_router


class TestRouterClientREST(unittest.IsolatedAsyncioTestCase):
    """Unit tests for RouterClient REST API operations using mocks."""

    async def asyncSetUp(self):
        self.client = RouterClient(host="192.168.1.1", api_port=9090)

    async def test_is_api_alive_success(self):
        mock_resp = MagicMock()
        mock_resp.status = 200

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.get", return_value=MockContext()):
            alive = await self.client.is_api_alive()
            self.assertTrue(alive)

    async def test_is_api_alive_failure_status(self):
        mock_resp = MagicMock()
        mock_resp.status = 502

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.get", return_value=MockContext()):
            alive = await self.client.is_api_alive()
            self.assertFalse(alive)

    async def test_is_api_alive_exception(self):
        with patch(
            "aiohttp.ClientSession.get",
            side_effect=Exception("Connection refused"),
        ):
            alive = await self.client.is_api_alive()
            self.assertFalse(alive)

    async def test_reload_provider_success_204(self):
        mock_resp = MagicMock()
        mock_resp.status = 204

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch(
            "aiohttp.ClientSession.put", return_value=MockContext()
        ) as mock_put:
            res = await self.client.reload_provider("Gemini_Nodes")
            self.assertTrue(res)
            mock_put.assert_called_once_with(
                "http://192.168.1.1:9090/providers/proxies/Gemini_Nodes",
                timeout=aiohttp.ClientTimeout(total=5.0),
            )

    async def test_reload_provider_success_200(self):
        mock_resp = MagicMock()
        mock_resp.status = 200

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.put", return_value=MockContext()):
            res = await self.client.reload_provider("Gemini_Nodes")
            self.assertTrue(res)

    async def test_reload_provider_quoted_name(self):
        mock_resp = MagicMock()
        mock_resp.status = 204

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch(
            "aiohttp.ClientSession.put", return_value=MockContext()
        ) as mock_put:
            res = await self.client.reload_provider("Custom Provider Name")
            self.assertTrue(res)
            mock_put.assert_called_once_with(
                "http://192.168.1.1:9090/providers/proxies/"
                "Custom%20Provider%20Name",
                timeout=aiohttp.ClientTimeout(total=5.0),
            )

    async def test_reload_provider_failure(self):
        mock_resp = MagicMock()
        mock_resp.status = 404

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.put", return_value=MockContext()):
            res = await self.client.reload_provider("Unknown_Provider")
            self.assertFalse(res)

    async def test_reload_provider_exception(self):
        with patch(
            "aiohttp.ClientSession.put", side_effect=Exception("Timeout")
        ):
            res = await self.client.reload_provider("Gemini_Nodes")
            self.assertFalse(res)

    async def test_probe_group_delay_success(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        expected_data = {"Node1": 60, "Node2": 110}

        async def mock_json():
            return expected_data

        mock_resp.json = mock_json

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch(
            "aiohttp.ClientSession.get", return_value=MockContext()
        ) as mock_get:
            result = await self.client.probe_group_delay(
                "Gemini_Auto", "https://www.gstatic.com/generate_204", 3000
            )
            self.assertEqual(result, expected_data)
            mock_get.assert_called_once_with(
                "http://192.168.1.1:9090/group/Gemini_Auto/delay",
                params={
                    "url": "https://www.gstatic.com/generate_204",
                    "timeout": "3000",
                },
                timeout=aiohttp.ClientTimeout(total=5.0),
            )

    async def test_probe_group_delay_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status = 503

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.get", return_value=MockContext()):
            result = await self.client.probe_group_delay("Gemini_Auto")
            self.assertEqual(result, {})

    async def test_probe_group_delay_invalid_json(self):
        mock_resp = MagicMock()
        mock_resp.status = 200

        async def mock_json():
            return "not a dict"

        mock_resp.json = mock_json

        class MockContext:
            async def __aenter__(self):
                return mock_resp

            async def __aexit__(self, exc_type, exc, tb):
                pass

        with patch("aiohttp.ClientSession.get", return_value=MockContext()):
            result = await self.client.probe_group_delay("Gemini_Auto")
            self.assertEqual(result, {})

    async def test_probe_group_delay_exception(self):
        with patch(
            "aiohttp.ClientSession.get", side_effect=Exception("Network error")
        ):
            result = await self.client.probe_group_delay("Gemini_Auto")
            self.assertEqual(result, {})

    async def test_context_manager(self):
        async with RouterClient(host="192.168.1.1") as c:
            self.assertIsNotNone(c.session)
            self.assertFalse(c.session.closed)
        self.assertIsNone(c.session)


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


class TestSSHRouterScript(unittest.TestCase):
    """Unit tests for ssh_router.py CLI helper."""

    def test_run_ssh_success(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"status: ok\n"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            with patch("sys.stdout.write") as mock_out, patch(
                "sys.stderr.write"
            ) as mock_err:
                ret = ssh_router.run_ssh("echo ok")
                self.assertEqual(ret, "status: ok\n")
                mock_out.assert_called_once_with("status: ok\n")
                mock_err.assert_not_called()
                mock_ssh.close.assert_called_once()

    def test_run_ssh_propagates_remote_exit_status(self):
        mock_ssh = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"error code 2\n"
        mock_stdout.channel.recv_exit_status.return_value = 2
        mock_ssh.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        with patch("paramiko.SSHClient", return_value=mock_ssh):
            with patch("sys.stdout.write"), patch(
                "sys.stderr.write"
            ) as mock_err:
                with self.assertRaises(SystemExit) as cm:
                    ssh_router.run_ssh("exit 2")
                self.assertEqual(cm.exception.code, 2)
                mock_err.assert_called_once_with("error code 2\n")
                mock_ssh.close.assert_called_once()

    def test_run_ssh_connection_exception_exits_1(self):
        with patch("paramiko.SSHClient") as mock_ssh_cls:
            mock_inst = MagicMock()
            mock_inst.connect.side_effect = Exception("SSH host unreachable")
            mock_ssh_cls.return_value = mock_inst

            with patch("sys.stderr.write") as mock_err:
                with self.assertRaises(SystemExit) as cm:
                    ssh_router.run_ssh("uptime")
                self.assertEqual(cm.exception.code, 1)
                self.assertTrue(mock_err.called)
                mock_inst.close.assert_called_once()


class TestPusher(unittest.TestCase):
    """Unit tests for pusher.py modernized deployment function."""

    def test_push_to_router_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            non_existent = os.path.join(tmp_dir, "does_not_exist.sh")
            with patch(
                "proxy_sites.router.pusher.ROUTER_SCRIPT_FILE", non_existent
            ):
                res = push_to_router()
                self.assertFalse(res)

    def test_push_to_router_stream_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script_file = os.path.join(tmp_dir, "apply_to_router.sh")
            with open(script_file, "w") as f:
                f.write("#!/bin/sh\necho test\n")

            mock_client = MagicMock()
            mock_client.stream_file_to_router.return_value = False

            with patch(
                "proxy_sites.router.pusher.ROUTER_SCRIPT_FILE", script_file
            ):
                res = push_to_router(router_client=mock_client)
                self.assertFalse(res)
                mock_client.stream_file_to_router.assert_called_once_with(
                    "#!/bin/sh\necho test\n",
                    "/tmp/apply_to_router.sh",
                    mode="0755",
                )
                mock_client.exec_command.assert_not_called()

    def test_push_to_router_exec_failure(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script_file = os.path.join(tmp_dir, "apply_to_router.sh")
            with open(script_file, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")

            mock_client = MagicMock()
            mock_client.stream_file_to_router.return_value = True
            mock_client.exec_command.return_value = (1, "", "syntax error")

            with patch(
                "proxy_sites.router.pusher.ROUTER_SCRIPT_FILE", script_file
            ):
                res = push_to_router(router_client=mock_client)
                self.assertFalse(res)
                mock_client.stream_file_to_router.assert_called_once()
                mock_client.exec_command.assert_called_once_with(
                    "/bin/sh /tmp/apply_to_router.sh; rc=$?; "
                    "rm -f /tmp/apply_to_router.sh; exit $rc"
                )

    def test_push_to_router_success(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script_file = os.path.join(tmp_dir, "apply_to_router.sh")
            content = "#!/bin/sh\necho 'deployment complete'\n"
            with open(script_file, "w") as f:
                f.write(content)

            mock_client = MagicMock()
            mock_client.stream_file_to_router.return_value = True
            mock_client.exec_command.return_value = (
                0,
                "deployment complete",
                "",
            )

            with patch(
                "proxy_sites.router.pusher.ROUTER_SCRIPT_FILE", script_file
            ):
                res = push_to_router(router_client=mock_client)
                self.assertTrue(res)
                mock_client.stream_file_to_router.assert_called_once_with(
                    content, "/tmp/apply_to_router.sh", mode="0755"
                )
                mock_client.exec_command.assert_called_once_with(
                    "/bin/sh /tmp/apply_to_router.sh; rc=$?; "
                    "rm -f /tmp/apply_to_router.sh; exit $rc"
                )


class TestRouterClientWithEphemeralServer(unittest.IsolatedAsyncioTestCase):
    """Integration test of RouterClient against an ephemeral HTTP server."""

    async def asyncSetUp(self):
        # Guideline: Dynamically request an available free port from OS kernel
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()

        # Build ephemeral aiohttp web app
        self.app = web.Application()
        self.app.router.add_get("/version", self._handle_version)
        self.app.router.add_put(
            "/providers/proxies/{provider}", self._handle_reload_provider
        )
        self.app.router.add_get(
            "/group/{group}/delay", self._handle_group_delay
        )

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", self.port)
        await self.site.start()

        self.client = RouterClient(host="127.0.0.1", api_port=self.port)

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def _handle_version(self, request):
        return web.json_response({"meta": True, "version": "v1.19.30"})

    async def _handle_reload_provider(self, request):
        provider = request.match_info["provider"]
        if provider == "Gemini_Nodes":
            return web.Response(status=204)
        return web.Response(status=404)

    async def _handle_group_delay(self, request):
        group = request.match_info["group"]
        url = request.query.get("url")
        timeout = request.query.get("timeout")
        if group == "Gemini_Auto" and url and timeout:
            return web.json_response({"NodeA": 45, "NodeB": 85})
        return web.Response(status=400)

    async def test_ephemeral_server_rest_operations(self):
        # 1. is_api_alive
        alive = await self.client.is_api_alive()
        self.assertTrue(alive)

        # 2. reload_provider
        reloaded = await self.client.reload_provider("Gemini_Nodes")
        self.assertTrue(reloaded)
        not_found = await self.client.reload_provider("NonExistent")
        self.assertFalse(not_found)

        # 3. probe_group_delay
        delays = await self.client.probe_group_delay(
            "Gemini_Auto", "https://www.gstatic.com/generate_204", 3000
        )
        self.assertEqual(delays, {"NodeA": 45, "NodeB": 85})


class TestRouterClientRemediation(unittest.IsolatedAsyncioTestCase):
    """Tests specifically covering the Milestone 1 Iteration 2 remediations."""

    def test_ipv6_url_formatting(self):
        # Unbracketed IPv6
        client_ipv6 = RouterClient(
            host="::1", api_port=9090, proxy_port=7890
        )
        self.assertEqual(client_ipv6.api_url, "http://[::1]:9090")
        self.assertEqual(client_ipv6.proxy_url, "http://[::1]:7890")

        # Already bracketed IPv6
        client_bracketed = RouterClient(host="[2001:db8::1]", api_port=9090)
        self.assertEqual(client_bracketed.api_url, "http://[2001:db8::1]:9090")

        # Standard IPv4
        client_ipv4 = RouterClient(host="192.168.1.1", api_port=9090)
        self.assertEqual(client_ipv4.api_url, "http://192.168.1.1:9090")

    async def test_managed_session_enforces_per_request_timeout(self):
        # Verify timeout passed into session.get when managed session is active
        async with RouterClient(host="192.168.1.1") as client:
            mock_resp = MagicMock()
            mock_resp.status = 200

            class MockContext:
                async def __aenter__(self):
                    return mock_resp

                async def __aexit__(self, exc_type, exc, tb):
                    pass

            with patch.object(
                client.session, "get", return_value=MockContext()
            ) as mock_get:
                alive = await client.is_api_alive()
                self.assertTrue(alive)
                mock_get.assert_called_once()
                call_kwargs = mock_get.call_args[1]
                self.assertIn("timeout", call_kwargs)
                self.assertEqual(call_kwargs["timeout"].total, 2.0)

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

    def test_ssh_router_cli_multi_word_arguments(self):
        import sys
        with patch.object(sys, "argv", ["ssh_router.py", "uname", "-a"]):
            with patch("ssh_router.run_ssh") as mock_run:
                cmd = (
                    " ".join(sys.argv[1:])
                    if len(sys.argv) > 1
                    else "logread | grep zapret2"
                )
                mock_run(cmd)
                mock_run.assert_called_once_with("uname -a")


if __name__ == "__main__":
    unittest.main()
