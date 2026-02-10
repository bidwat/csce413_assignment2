from __future__ import annotations

import re
import socket
from typing import Optional, Tuple


_PRINTABLE = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")


def _clean_text(s: str, max_len: int = 300) -> str:
    s = _PRINTABLE.sub("", s)
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _try_recv(sock: socket.socket, n: int = 4096, timeout: float = 0.25) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except Exception:
        return b""


def _detect_mysql(handshake: bytes) -> Optional[str]:
    """
    MySQL handshake: [protocol(1 byte)][server_version null-terminated]...
    """
    if not handshake or len(handshake) < 5:
        return None
    # protocol version is usually 0x0a (10)
    proto = handshake[0]
    if proto not in (0x0a,):
        return None

    try:
        end = handshake.index(b"\x00", 1)
        ver = handshake[1:end].decode(errors="ignore")
        ver = _clean_text(ver, 80)
        if ver:
            return f"mysql {ver}"
    except ValueError:
        pass
    return "mysql"


def _detect_ssh(data: bytes) -> Optional[str]:
    if not data:
        return None
    text = data.decode(errors="ignore")
    if "SSH-" in text:
        # grab the first line that contains SSH-
        for line in text.splitlines():
            if "SSH-" in line:
                return _clean_text(line, 120)
        return "ssh"
    return None


def _probe_http(sock: socket.socket, host: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Send HEAD request; if HTTP response, return service + banner.
    """
    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        data = _try_recv(sock, n=4096, timeout=0.35)
        if not data:
            return None, None
        text = data.decode(errors="ignore")
        if "HTTP/" not in text:
            return None, None

        # banner: Server header if present
        server = None
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break

        if server:
            return "http", _clean_text(f"Server: {server}", 200)
        return "http", _clean_text(text.splitlines()[0], 200)
    except Exception:
        return None, None

def identify_service(sock: socket.socket, target: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Called only after connect() succeeds.
    Returns (service, banner_preview)
    """
    # 1) try to read anything the service sends immediately (SSH/MySQL banners)
    first = _try_recv(sock, n=4096, timeout=0.25)

    ssh_banner = _detect_ssh(first)
    if ssh_banner:
        
        extra = _try_recv(sock, n=4096, timeout=0.25)
        combined = (first + extra).decode(errors="ignore")
        combined = _clean_text(combined, 600)
        return "ssh", combined if combined else ssh_banner

    mysql = _detect_mysql(first)
    if mysql:
        return "mysql", _clean_text(first.decode(errors="ignore"), 200)
    

    svc, banner = _probe_http(sock, target)
    if svc:
        return svc, banner

    if first:
        return None, _clean_text(first.decode(errors="ignore"), 200)

    return None, None
