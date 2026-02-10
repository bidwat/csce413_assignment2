"""
Sends TCP connection attempts (knocks) to the target knock ports.
checks whether the protected port becomes reachable afterward.
"""

import argparse
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3


def send_knock(target: str, port: int, delay: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((target, port))
    except Exception:
        # We only care that a connection attempt happened.
        pass
    finally:
        sock.close()

    time.sleep(delay)


def perform_knock_sequence(target: str, sequence, delay: float):
    for p in sequence:
        send_knock(target, p, delay)


def check_protected_port(target: str, protected_port: int):
    try:
        with socket.create_connection((target, protected_port), timeout=2.0):
            print(f"[+] Connected to protected port {protected_port}")
    except OSError:
        print(f"[-] Could not connect to protected port {protected_port}")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument("--protected-port", type=int, default=DEFAULT_PROTECTED_PORT)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()
