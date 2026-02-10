#!/usr/bin/env python3
import argparse
import re
import string
from pathlib import Path
from typing import Optional

from scapy.all import rdpcap, sniff, wrpcap 
from scapy.layers.inet import IP, TCP 
from scapy.packet import Raw

PRINTABLE = set(bytes(string.printable, "ascii"))

def to_printable(data: bytes) -> str:
    """Keep only printable ASCII; replace others with '.' to make payload readable."""
    return "".join(chr(b) if b in PRINTABLE else "." for b in data)

def looks_like_tls(data: bytes) -> bool:
    """
    Heuristic: TLS record header often starts with:
      0x16 0x03 0x01/0x02/0x03 (Handshake + TLS version)
    """
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03 and data[2] in (0x00, 0x01, 0x02, 0x03, 0x04)

def extract_interesting(text: str) -> Optional[str]:
    """
    Pull out high-signal strings:
      - FLAGS
      - common SQL keywords
      - table names / secrets-like words
    """
    if "FLAG{" in text:
        return "FLAG DETECTED"

    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN"]
    if any(k in text.upper() for k in sql_keywords):
        return "SQL-LIKE TEXT"

    if any(w in text.lower() for w in ["secret", "token", "password", "userdb", "users", "secrets"]):
        return "SENSITIVE-LOOKING TEXT"

    return None

def handle_packet(pkt, show_all: bool = False):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    tcp = pkt[TCP]
    if tcp.sport != 3306 and tcp.dport != 3306:
        return

    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    if not payload:
        return

    printable = to_printable(payload)
    marker = extract_interesting(printable)
    tls = looks_like_tls(payload)

    if show_all or marker or tls:
        direction = f"{pkt[IP].src}:{tcp.sport} -> {pkt[IP].dst}:{tcp.dport}"
        print(f"\n[{direction}] len={len(payload)} tls_guess={tls} marker={marker}")
        # keep output short-ish
        print(printable[:400])

def analyze_pcap(pcap_path: Path, show_all: bool):
    packets = rdpcap(str(pcap_path))
    print(f"Loaded {len(packets)} packets from {pcap_path}")
    for pkt in packets:
        handle_packet(pkt, show_all=show_all)

def sniff_live(iface: str, seconds: int, out_pcap: Path, show_all: bool):
    captured = []
    def _cb(pkt):
        captured.append(pkt)
        handle_packet(pkt, show_all=show_all)

    print(f"Sniffing on iface={iface} for {seconds}s, filter='tcp port 3306' ...")
    sniff(iface=iface, filter="tcp port 3306", prn=_cb, store=False, timeout=seconds)

    if captured:
        wrpcap(str(out_pcap), captured)
        print(f"\nSaved {len(captured)} packets to {out_pcap}")
    else:
        print("\nNo packets captured.")

def main():
    ap = argparse.ArgumentParser(description="MITM analysis for MySQL (port 3306) using Scapy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze an existing pcap file")
    a.add_argument("--pcap", required=True, help="Path to pcap file")
    a.add_argument("--show-all", action="store_true", help="Print all payload packets, not just interesting ones")

    s = sub.add_parser("sniff", help="Live sniff (run with NET_RAW / root privileges)")
    s.add_argument("--iface", default="eth0", help="Interface name (default: eth0)")
    s.add_argument("--seconds", type=int, default=20, help="How long to sniff")
    s.add_argument("--out", default="mysql_3306_live.pcap", help="Where to save captured pcap")
    s.add_argument("--show-all", action="store_true", help="Print all payload packets, not just interesting ones")

    args = ap.parse_args()

    if args.cmd == "analyze":
        analyze_pcap(Path(args.pcap), show_all=args.show_all)
    else:
        sniff_live(args.iface, args.seconds, Path(args.out), show_all=args.show_all)

if __name__ == "__main__":
    main()
