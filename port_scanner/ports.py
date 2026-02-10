from __future__ import annotations

from typing import List


def parse_ports(spec: str) -> List[int]:
    """
    Parses a port specification string into a list of ports.
    Supports:
    - Single ports: "80"
    - Ranges: "1-1024"
    - Comma-separated: "22,80,443"
    - Mixed: "1-1024,8080,9000-9005"
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Empty port spec")

    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.append(p)

    # De-dupe, keep sorted
    return sorted(set(ports))
