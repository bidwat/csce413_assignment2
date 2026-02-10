"""

Design:
- Userland server listens on knock ports.
- Tracks per-source-IP progress through the knock sequence.
- If sequence is completed in time, opens protected port via iptables
  *for that source IP only* for a short duration, then closes it again.

This matches the assignment requirements:
- Listen for knocks
- Verify correct sequence + timing window
- Dynamically open/close protected port using firewall rules
- Reset on incorrect sequences
"""

import argparse
import logging
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_OPEN_SECONDS = 20.0

IPTABLES_CHAIN = "INPUT"
DEFAULT_DROP_COMMENT = "PK_DEFAULT_DROP_2222"


@dataclass
class KnockState:
    index: int = 0
    start_ts: Optional[float] = None


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    # -w waits for xtables lock (important in containers)
    full = ["iptables", "-w", "2"] + cmd
    logging.debug("RUN: %s", " ".join(full))
    return subprocess.run(full, capture_output=True, text=True)


def iptables_rule_exists(rule: List[str]) -> bool:
    # iptables -C returns exit code 0 if rule exists
    res = _run(["-C"] + rule)
    return res.returncode == 0


def iptables_add(rule: List[str], insert: bool = True):
    # Use -I to ensure allow rules are before the drop rule
    op = "-I" if insert else "-A"
    res = _run([op] + rule)
    if res.returncode != 0:
        raise RuntimeError(f"iptables add failed: {res.stderr.strip()}")


def iptables_delete(rule: List[str]):
    res = _run(["-D"] + rule)
    if res.returncode != 0:
        # If it doesn't exist, that’s fine for cleanup flows.
        logging.debug("iptables delete skipped: %s", res.stderr.strip())


def ensure_default_drop(protected_port: int):
    """
    Ensure the protected port is blocked by default.
    (Allow rules for specific IPs will be inserted above this.)
    """
    drop_rule = [
        IPTABLES_CHAIN,
        "-p", "tcp",
        "--dport", str(protected_port),
        "-m", "comment",
        "--comment", DEFAULT_DROP_COMMENT,
        "-j", "DROP",
    ]
    if not iptables_rule_exists(drop_rule):
        logging.info("[iptables] Adding default DROP for protected port %s", protected_port)
        iptables_add(drop_rule, insert=False)  # append at end
    else:
        logging.info("[iptables] Default DROP already present for port %s", protected_port)


def allow_ip_temporarily(src_ip: str, protected_port: int, open_seconds: float):
    """
    Insert an ACCEPT rule for this src_ip -> protected_port,
    then remove it after open_seconds.
    """
    allow_comment = f"PK_ALLOW_{src_ip}_{protected_port}"
    allow_rule = [
        IPTABLES_CHAIN,
        "-p", "tcp",
        "-s", src_ip,
        "--dport", str(protected_port),
        "-m", "comment",
        "--comment", allow_comment,
        "-j", "ACCEPT",
    ]

    if not iptables_rule_exists(allow_rule):
        logging.info("[iptables] Opening port %s for %s (%.1fs)", protected_port, src_ip, open_seconds)
        iptables_add(allow_rule, insert=True)
    else:
        logging.info("[iptables] Rule already exists for %s on port %s", src_ip, protected_port)

    def _close_later():
        time.sleep(open_seconds)
        logging.info("[iptables] Closing port %s for %s", protected_port, src_ip)
        iptables_delete(allow_rule)

    threading.Thread(target=_close_later, daemon=True).start()


def is_expired(state: KnockState, window_seconds: float) -> bool:
    return state.start_ts is not None and (time.time() - state.start_ts) > window_seconds


def handle_knock(
    src_ip: str,
    dst_port: int,
    sequence: List[int],
    window_seconds: float,
    state_map: Dict[str, KnockState],
    protected_port: int,
    open_seconds: float,
):
    state = state_map.get(src_ip, KnockState())

    # If window expired, reset
    if is_expired(state, window_seconds):
        logging.info("[reset] %s sequence window expired", src_ip)
        state = KnockState()

    expected_port = sequence[state.index] if state.index < len(sequence) else None

    if state.index == 0:
        # Starting new sequence
        if dst_port == sequence[0]:
            state.index = 1
            state.start_ts = time.time()
            logging.info("[knock] %s step 1/%d (port=%d)", src_ip, len(sequence), dst_port)
        else:
            # Ignore random knocks that are not the first port
            return
    else:
        # In-progress
        if dst_port == expected_port:
            state.index += 1
            logging.info("[knock] %s step %d/%d (port=%d)", src_ip, state.index, len(sequence), dst_port)

            if state.index == len(sequence):
                logging.info("[success] %s completed sequence -> opening protected port", src_ip)
                allow_ip_temporarily(src_ip, protected_port, open_seconds)
                state = KnockState()  # reset after success
        else:
            # Wrong knock -> reset (optionally treat it as a new first knock)
            logging.info("[reset] %s wrong knock (got=%d expected=%d)", src_ip, dst_port, expected_port)
            if dst_port == sequence[0]:
                state = KnockState(index=1, start_ts=time.time())
                logging.info("[knock] %s restart step 1/%d (port=%d)", src_ip, len(sequence), dst_port)
            else:
                state = KnockState()

    state_map[src_ip] = state


def listen_on_knock_port(
    port: int,
    sequence: List[int],
    window_seconds: float,
    state_map: Dict[str, KnockState],
    protected_port: int,
    open_seconds: float,
):
    logger = logging.getLogger("KnockServer")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)

    logger.info("Listening on knock port %d", port)

    while True:
        conn, addr = srv.accept()
        src_ip, src_port = addr[0], addr[1]
        logger.info("Received knock from %s:%d on %d", src_ip, src_port, port)

        try:
            handle_knock(
                src_ip=src_ip,
                dst_port=port,
                sequence=sequence,
                window_seconds=window_seconds,
                state_map=state_map,
                protected_port=protected_port,
                open_seconds=open_seconds,
            )
        finally:
            conn.close()


def parse_args():
    p = argparse.ArgumentParser(description="Port knocking server")
    p.add_argument(
        "--sequence",
        default=",".join(str(x) for x in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (e.g., 1234,5678,9012)",
    )
    p.add_argument("--protected-port", type=int, default=DEFAULT_PROTECTED_PORT)
    p.add_argument("--window", type=float, default=DEFAULT_SEQUENCE_WINDOW, help="Seconds to complete sequence")
    p.add_argument("--open-seconds", type=float, default=DEFAULT_OPEN_SECONDS, help="How long to open protected port")
    return p.parse_args()


def main():
    setup_logging()
    args = parse_args()

    try:
        sequence = [int(x.strip()) for x in args.sequence.split(",") if x.strip()]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    logging.info("Knock sequence: %s", sequence)
    logging.info("Protected port: %d", args.protected_port)
    logging.info("Window seconds: %.1f", args.window)
    logging.info("Open seconds: %.1f", args.open_seconds)

    ensure_default_drop(args.protected_port)

    state_map: Dict[str, KnockState] = {}

    for kp in sequence:
        t = threading.Thread(
            target=listen_on_knock_port,
            args=(kp, sequence, args.window, state_map, args.protected_port, args.open_seconds),
            daemon=True,
        )
        t.start()

    # Keep main thread alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
