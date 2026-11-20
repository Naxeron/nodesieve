"""What nodesieve needs of a proxy core (Xray or Mihomo), and the downloads that provide one.

The local instances nodes are checked through (core/batch.py) work the same way whichever
core runs them. A core says where its binary is and how to get it, what it makes of a share
link, what its configuration looks like with a listener pinned to each proxy, and how to
read its log when it does not start.
"""

import json
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

LISTEN_HOST = "127.0.0.1"
# How the Go runtime starts the report of a crash.
GO_CRASH = ("panic:", "fatal error:")


def download(url: str, timeout: float = 120.0) -> bytes:
    """The body of an HTTP(S) GET."""
    request = urllib.request.Request(url, headers={"User-Agent": "nodesieve"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def release_assets(api_url: str) -> Dict[str, str]:
    """Download URL of each asset of a GitHub release, by name."""
    release = json.loads(download(api_url, timeout=30.0).decode("utf-8"))
    return {asset.get("name", ""): asset.get("browser_download_url", "") for asset in release.get("assets", [])}


def go_crash(lines: Sequence[str]) -> Optional[str]:
    """The first line of a Go runtime crash in a core's output, if there is one."""
    for line in lines:
        if line.startswith(GO_CRASH):
            return line.strip()[:300]
    return None


class ProxyCore:
    """A proxy core that serves nodes for the checks: one process, a listener per node.

    name is the `core` setting's value, display how messages name the core.
    """

    name = ""
    display = ""
    config_name = "config"

    @property
    def path(self) -> str:
        """Where the core's binary is."""
        raise NotImplementedError

    def setup(self) -> None:
        """Makes sure the binary exists, downloading it when it is absent; exits when it can't."""
        raise NotImplementedError

    def proxy(self, link: str, config: dict) -> Any:
        """The core's proxy for a share link, not named yet; ValueError for a link it can't serve."""
        raise NotImplementedError

    def named(self, proxy: Any, name: str) -> Any:
        """The same proxy under a name of nodesieve's, which its listener and log refer to."""
        raise NotImplementedError

    def server(self, proxy: Any) -> Optional[str]:
        """The address of a proxy's server, as the link gives it."""
        raise NotImplementedError

    def ready_proxy(self, port: int) -> Any:
        """A proxy, not named yet, to the HTTP proxy at 127.0.0.1:port: how a start is noticed."""
        raise NotImplementedError

    def render(self, served: Sequence[Tuple[Any, int]], hosts: Optional[Dict[str, List[str]]] = None) -> str:
        """Configuration serving each named proxy on a mixed listener of its own at 127.0.0.1:port.

        A listener pinned to a proxy sends everything it receives through that proxy, and
        nothing else goes anywhere. hosts gives server names their addresses (on Android).
        """
        raise NotImplementedError

    def command(self, work_dir: str, config_path: str) -> List[str]:
        """How the core is started with a configuration."""
        raise NotImplementedError

    def refused(self, lines: Sequence[str], names: Sequence[str]) -> Optional[Tuple[int, str]]:
        """Which of the named proxies the core refused, by index, and its reason, when that stopped it."""
        raise NotImplementedError

    def busy(self, lines: Sequence[str], listeners: Sequence[Tuple[str, int]]) -> Dict[int, str]:
        """Listeners, by index of their (proxy name, port), whose port was taken meanwhile, and why."""
        raise NotImplementedError

    def detail(self, lines: Sequence[str]) -> str:
        """The core's own account of a failure, from its output: a Go crash, or its last error."""
        raise NotImplementedError
