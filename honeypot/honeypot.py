#!/usr/bin/env python3
import socket
import threading
import time
import paramiko

from logger import create_logger, log_event, AlertTracker

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22

# Match the secret SSH banner you observed via nmap
FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13"

# Generate a host key at startup (fine for the assignment)
HOST_KEY = paramiko.RSAKey.generate(2048)

# Optional alerting
ALERTS = AlertTracker(max_fails=5, window_seconds=60)


def fake_command_output(cmd: str) -> str:
    cmd = cmd.strip()

    # A few realistic-ish outputs
    if cmd in ("whoami",):
        return "root\n"
    if cmd in ("pwd",):
        return "/root\n"
    if cmd.startswith("ls"):
        return "secrets  notes.txt  README\n"
    if cmd == "uname -a":
        return "Linux secret-server 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n"
    if cmd == "cat /etc/os-release":
        return (
            "NAME=\"Ubuntu\"\n"
            "VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n"
            "ID=ubuntu\n"
            "VERSION_ID=\"22.04\"\n"
        )
    if "cat" in cmd and "flag" in cmd.lower():
        return "cat: secrets/flag.txt: No such file or directory\n"

    if cmd == "" or cmd is None:
        return ""
    return f"bash: {cmd}: command not found\n"


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, logger, src_ip: str, src_port: int):
        self.logger = logger
        self.src_ip = src_ip
        self.src_port = src_port
        self.username = None
        self.auth_ok = False

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.username = username

        # Log credentials
        log_event(self.logger, "ssh_auth_password", {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": username,
            "password": password,
        })

        # Alert on repeated failures (we still "accept" to be convincing)
        suspicious = ALERTS.record_fail(self.src_ip)
        if suspicious:
            log_event(self.logger, "alert_bruteforce_suspected", {
                "src_ip": self.src_ip,
                "reason": f"{ALERTS.max_fails}+ password attempts in {ALERTS.window_seconds}s"
            })

        # More convincing: accept auth (but it’s a fake shell)
        self.auth_ok = True
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        # Some attackers will use ssh user@host "id" (exec mode)
        cmd = command.decode(errors="ignore") if isinstance(command, (bytes, bytearray)) else str(command)
        log_event(self.logger, "ssh_exec", {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": self.username,
            "command": cmd,
        })
        out = fake_command_output(cmd)
        if out:
            channel.send(out.encode())
        channel.send_exit_status(0)
        return True


def run_fake_shell(chan, logger, src_ip, src_port, username):
    # Very small “bash-like” interaction loop
    motd = (
        "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n"
        "\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/advantage\n\n"
    )
    chan.send(motd.encode())

    prompt = f"{username}@secret-server:~$ "
    chan.send(prompt.encode())

    buf = b""
    while True:
        try:
            data = chan.recv(1024)
            if not data:
                break
            buf += data

            # Handle line-based input
            while b"\n" in buf or b"\r" in buf:
                line = buf.replace(b"\r", b"\n").split(b"\n", 1)[0]
                buf = b""

                cmd = line.decode(errors="ignore").strip()

                # Log the raw command
                log_event(logger, "ssh_command", {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "username": username,
                    "command": cmd,
                })

                if cmd in ("exit", "logout", "quit"):
                    chan.send(b"logout\n")
                    return

                out = fake_command_output(cmd)
                if out:
                    chan.send(out.encode())

                chan.send(prompt.encode())

        except Exception:
            break


def handle_client(client_sock: socket.socket, addr, logger):
    src_ip, src_port = addr
    session_start = time.time()

    log_event(logger, "connection_open", {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": LISTEN_PORT,
        "proto": "tcp",
    })

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(HOST_KEY)
    transport.local_version = FAKE_BANNER

    server = HoneypotSSHServer(logger, src_ip, src_port)

    try:
        transport.start_server(server=server)

        chan = transport.accept(10)
        if chan is None:
            return

        # If the attacker opens a session shell, give them the fake shell
        if server.auth_ok:
            log_event(logger, "ssh_shell_opened", {
                "src_ip": src_ip,
                "src_port": src_port,
                "username": server.username,
            })
            run_fake_shell(chan, logger, src_ip, src_port, server.username or "user")

        chan.close()

    except Exception as e:
        log_event(logger, "error", {
            "src_ip": src_ip,
            "src_port": src_port,
            "message": str(e),
        })
    finally:
        try:
            transport.close()
        except Exception:
            pass

        duration = round(time.time() - session_start, 3)
        log_event(logger, "connection_close", {
            "src_ip": src_ip,
            "src_port": src_port,
            "duration_s": duration,
        })


def main():
    logger = create_logger()
    log_event(logger, "honeypot_start", {
        "listen_host": LISTEN_HOST,
        "listen_port": LISTEN_PORT,
        "banner": FAKE_BANNER,
    })

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((LISTEN_HOST, LISTEN_PORT))
        server_sock.listen(200)

        while True:
            client, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr, logger), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
