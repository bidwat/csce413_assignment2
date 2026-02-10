from __future__ import annotations

import argparse

from .ports import parse_ports
from .scanner import scan
from .targets import expand_targets
from .output import print_results, save_results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CSCE413 Assignment 2 - Port Scanner")
    p.add_argument("--target", required=True, help="IP, CIDR, or hostname")
    p.add_argument("--ports", required=True, help="Port spec: 1-1024 or 22,80,443 or mixed")
    p.add_argument("--threads", type=int, default=200, help="Thread count (default: 200)")
    p.add_argument("--timeout", type=float, default=0.15, help="Connect timeout seconds (default: 0.15)")
    p.add_argument("--open-only", action="store_true", help="Only display/save open ports")
    p.add_argument("--format", choices=["txt", "csv", "json", "html"], help="Save results to file")
    p.add_argument("--out-dir", default="SCANS", help="Output directory for saved files")
    p.add_argument("--progress-every", type=int, default=5000, help="Progress update interval (default: 5000)")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = expand_targets(args.target)
    ports = parse_ports(args.ports)

    if args.threads < 1:
        raise SystemExit("--threads must be >= 1")

    print(f"[*] Targets: {len(targets)} | Ports: {len(ports)} | Total scans: {len(targets)*len(ports)}")
    results = scan(
        targets=targets,
        ports=ports,
        threads=args.threads,
        timeout_s=args.timeout,
        progress_every=args.progress_every,
    )

    print_results(results, open_only=args.open_only)

    if args.format:
        path = save_results(results, fmt=args.format, out_dir=args.out_dir, open_only=args.open_only)
        print(f"Saved results to {path}")

    return 0
