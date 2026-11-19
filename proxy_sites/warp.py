"""Cloudflare WARP endpoint generator and proxy configuration synthesizer."""

import ipaddress
import random
from typing import List, Optional


class WarpScanner:
    """Discovers and generates Cloudflare WARP WireGuard endpoints with AmneziaWG obfuscation options."""

    # Cloudflare's WARP server key, the same for every registration.
    PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

    POOLS_V4 = [
        "8.6.112.0/24", "8.34.70.0/24", "8.34.146.0/24", "8.35.211.0/24",
        "8.39.125.0/24", "8.39.204.0/24", "8.39.214.0/24", "8.47.69.0/24",
        "162.159.192.0/24", "162.159.195.0/24", "188.114.96.0/24",
        "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
    ]
    PRIMARY_PORTS = [2408, 500, 1701, 4500]

    @classmethod
    def generate_endpoints(cls, ips_per_subnet: int = 5) -> List[str]:
        """Samples random IPv4 hosts across Cloudflare ranges and pairs them with WARP ports."""
        endpoints = []
        for subnet in cls.POOLS_V4:
            net = ipaddress.ip_network(subnet)
            all_ips = list(net.hosts())
            sampled = random.sample(all_ips, min(ips_per_subnet, len(all_ips)))
            for ip in sampled:
                for port in cls.PRIMARY_PORTS:
                    endpoints.append(f"warp://{ip}:{port}#WARP")
        return endpoints

    @staticmethod
    def _setting(config: Optional[dict], key: str) -> str:
        return str((config or {}).get(key) or "").strip()

    @classmethod
    def has_identity(cls, config: Optional[dict]) -> bool:
        """Whether the settings hold a WARP registration to connect with."""
        return bool(cls._setting(config, "warp_private_key"))

    @classmethod
    def generate_warp_proxy_dict(
        cls, host: str, port: int, node_name: str = "WARP", config: Optional[dict] = None
    ) -> dict:
        """Generates a Mihomo WireGuard proxy configuration for Cloudflare WARP with AWG junk packet options.

        The WARP registration is read from the settings: `warp_private_key` and,
        for IPv6 inside the tunnel, the address assigned to it as `warp_ipv6`.
        """
        private_key = cls._setting(config, "warp_private_key")
        if not private_key:
            raise ValueError("WARP nodes need a WARP registration: set warp_private_key in the settings.")
        jmin = random.randint(10, 50)
        proxy = {
            "name": node_name,
            "type": "wireguard",
            "server": str(host),
            "port": int(port),
            "ip": "172.16.0.2",
        }
        ipv6 = cls._setting(config, "warp_ipv6")
        if ipv6:
            proxy["ipv6"] = ipv6
        proxy.update({
            "private-key": private_key,
            "public-key": cls.PUBLIC_KEY,
            "udp": True,
            "mtu": 1280,
            "amnezia-wg-option": {
                "jc": random.randint(4, 6),
                "jmin": jmin,
                "jmax": jmin + random.randint(20, 100),
                "i1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
            },
        })
        return proxy
