from __future__ import annotations

import socket
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Iterable, Iterator, List, Optional, Tuple

from .banner import identify_service
from .models import ScanResult


def scan_one(target: str, port: int, timeout_s: float) -> ScanResult:
    start = time.perf_counter()
    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        sock.connect((target, port))
        elapsed = time.perf_counter() - start

        service, banner = identify_service(sock, target)
        return ScanResult(
            target=target,
            port=port,
            is_open=True,
            elapsed_s=round(elapsed, 4),
            service=service,
            banner=banner,
        )
    except (socket.timeout, ConnectionRefusedError, OSError):
        elapsed = time.perf_counter() - start
        return ScanResult(
            target=target,
            port=port,
            is_open=False,
            elapsed_s=round(elapsed, 4),
            service=None,
            banner=None,
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def iter_jobs(targets: List[str], ports: List[int]) -> Iterator[Tuple[str, int]]:
    for t in targets:
        for p in ports:
            yield (t, p)


def scan(
    targets: List[str],
    ports: List[int],
    threads: int,
    timeout_s: float,
    progress_every: int = 5000,
) -> List[ScanResult]:
    """
    Bounded-futures scanner (won’t create millions of futures at once).
    """
    total = len(targets) * len(ports)
    results: List[ScanResult] = []

    jobs = iter_jobs(targets, ports)
    scanned = 0
    open_count = 0
    start_all = time.perf_counter()

    max_pending = max(threads * 4, 100)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        pending = set()

        def submit_next() -> bool:
            try:
                t, p = next(jobs)
            except StopIteration:
                return False
            fut = pool.submit(scan_one, t, p, timeout_s)
            pending.add(fut)
            return True

        # Prime the queue
        while len(pending) < max_pending and submit_next():
            pass

        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done:
                r = fut.result()
                results.append(r)

                scanned += 1
                if r.is_open:
                    open_count += 1

                if progress_every > 0 and (scanned % progress_every == 0 or scanned == total):
                    elapsed = time.perf_counter() - start_all
                    rate = scanned / elapsed if elapsed > 0 else 0.0
                    print(
                        f"\r[*] Scanned {scanned}/{total} | open={open_count} | {rate:.0f} scans/s",
                        end="",
                        flush=True,
                    )

                # Refill queue
                while len(pending) < max_pending and submit_next():
                    pass

    print()  # newline after progress
    return results
