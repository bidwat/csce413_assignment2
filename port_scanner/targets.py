from __future__ import annotations

import ipaddress
import socket
from typing import List


def expand_targets(target: str) -> List[str]:
    """
    Supports:
      - Single IP: "172.20.0.10"
      - CIDR: "172.20.0.0/24"
      - Hostname: "webapp" (resolves to one IP)
    """
    target = target.strip()
    if not target:
        raise ValueError("Empty target")

    # Try IP or CIDR first
    try:
        ip = ipaddress.ip_address(target)
        return [str(ip)]
    except ValueError:
        pass

    try:
        net = ipaddress.ip_network(target, strict=False)
        # hosts() excludes network + broadcast (good for /24 style)
        hosts = [str(ip) for ip in net.hosts()]
        # if /32 or single-address network
        if not hosts and net.num_addresses == 1:
            hosts = [str(net.network_address)]
        return hosts
    except ValueError:
        pass

    # Fallback: hostname
    try:
        resolved = socket.gethostbyname(target)
        return [resolved]
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve target '{target}': {e}") from e
