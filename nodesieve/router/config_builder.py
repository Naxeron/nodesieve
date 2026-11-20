"""OpenWrt Mihomo router config.yaml builder."""

import re
from typing import List, Optional
from nodesieve.constants import ROUTER_CONFIG_TEMPLATE
from nodesieve.parsers.awg import generate_awg_proxy_yaml


def build_router_config_yaml(
    awg_proxy: Optional[dict] = None,
    warp_proxies: Optional[List[dict]] = None,
    config: Optional[dict] = None,
) -> str:
    """Generates the main /etc/mihomo/config.yaml for OpenWrt deployment."""
    proxies_section = (
        'proxies:\n  - name: "Домашний интернет"\n    type: direct'
    )
    awg_group_entry = ""

    if awg_proxy:
        awg_yaml = generate_awg_proxy_yaml(awg_proxy)
        proxies_section += "\n" + awg_yaml
        escaped_name = awg_proxy["name"].replace('"', '\\"')
        awg_group_entry += f'\n      - "{escaped_name}"'

    if warp_proxies:
        for p in warp_proxies:
            proxies_section += "\n" + generate_awg_proxy_yaml(p)
            escaped_name = p["name"].replace('"', '\\"')
            awg_group_entry += f'\n      - "{escaped_name}"'

    if awg_group_entry:
        awg_group_entry = f"\n    proxies:{awg_group_entry}"

    rendered = ROUTER_CONFIG_TEMPLATE.format(
        proxies_section=proxies_section,
        awg_group_entry=awg_group_entry,
    )

    if config:
        api_port = config.get("router_api_port", 9090)
        proxy_port = config.get("router_proxy_port", 7890)
        if api_port != 9090:
            rendered = re.sub(
                r"external-controller:\s*0\.0\.0\.0:\d+",
                f"external-controller: 0.0.0.0:{api_port}",
                rendered,
            )
        if proxy_port != 7890:
            rendered = re.sub(
                r"(\bmixed-port:\s*)7890\b",
                f"\\g<1>{proxy_port}",
                rendered,
            )

    return rendered
