from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import List, Optional

from .models import ScanResult


def format_row(r: ScanResult) -> str:
    status = "open" if r.is_open else "closed"
    svc = r.service or "null"
    banner = r.banner or "null"
    return f"Target: {r.target} | Port {r.port}: {status} ({r.elapsed_s:.4f}s) | Service: {svc} | Banner: {banner}"


def print_results(results: List[ScanResult], open_only: bool) -> None:
    open_count = sum(1 for r in results if r.is_open)
    print(f"Found {open_count} open ports")

    for r in sorted(results, key=lambda x: (x.target, x.port)):
        if open_only and not r.is_open:
            continue
        print(format_row(r))


def save_results(
    results: List[ScanResult],
    fmt: str,
    out_dir: str = "PortScans",
    open_only: bool = False,
) -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(out_dir, f"{ts}_port_scan.{fmt}")

    filtered = [r for r in results if (r.is_open or not open_only)]

    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"Found {sum(1 for r in results if r.is_open)} open ports\n")
            for r in sorted(filtered, key=lambda x: (x.target, x.port)):
                f.write(format_row(r) + "\n")

    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "port", "status", "elapsed_s", "service", "banner"])
            for r in sorted(filtered, key=lambda x: (x.target, x.port)):
                w.writerow([
                    r.target,
                    r.port,
                    "open" if r.is_open else "closed",
                    r.elapsed_s,
                    r.service or "",
                    r.banner or "",
                ])

    elif fmt == "json":
        payload = [
            {
                "target": r.target,
                "port": r.port,
                "status": "open" if r.is_open else "closed",
                "elapsed_s": r.elapsed_s,
                "service": r.service,
                "banner": r.banner,
            }
            for r in sorted(filtered, key=lambda x: (x.target, x.port))
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    elif fmt == "html":
        with open(path, "w", encoding="utf-8") as f:
            f.write("<html><body>\n")
            f.write("<h1>Port Scan Results</h1>\n")
            f.write(f"<p>Open ports: {sum(1 for r in results if r.is_open)}</p>\n")
            f.write("<ul>\n")
            for r in sorted(filtered, key=lambda x: (x.target, x.port)):
                f.write(f"<li>{format_row(r)}</li>\n")
            f.write("</ul>\n</body></html>\n")

    else:
        raise ValueError(f"Unsupported format: {fmt}")

    return path
