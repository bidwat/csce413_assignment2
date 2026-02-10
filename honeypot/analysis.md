# Honeypot Analysis

## Overview

This honeypot simulates an SSH server and logs attacker interactions in JSON format.
The goal is to detect unauthorized access attempts and capture useful forensic artifacts:
credentials used, command activity, and session timing.

## Where logs are stored

All events are recorded to:

- `honeypot/logs/honeypot.log`

Each line is a JSON object containing:

- `ts` (timestamp)
- `event` (event type)
- additional fields depending on the event

## Summary of Observed Attacks (fill with your test results)

During testing, the honeypot captured:

- Multiple SSH login attempts using different usernames and passwords
- Interactive command execution in a fake shell
- Session durations for each connection
- A brute-force style pattern (optional alert) when repeated attempts occurred within a short time window

## Example Evidence

Below are example event types you should observe after running tests:

1. Connection opened

- `event: connection_open`
- fields: `src_ip`, `src_port`, `dst_port`, `proto`

2. Authentication attempt

- `event: ssh_auth_password`
- fields: `username`, `password`, `src_ip`, `src_port`

3. Shell opened

- `event: ssh_shell_opened`
- fields: `username`, `src_ip`, `src_port`

4. Command captured

- `event: ssh_command`
- fields: `username`, `command`, `src_ip`, `src_port`

5. Connection closed (duration)

- `event: connection_close`
- fields: `src_ip`, `src_port`, `duration_s`

6. Brute-force alert

- `event: alert_bruteforce_suspected`
- fields: `src_ip`, `reason`

```
{"ts": "2026-02-10T03:33:28.623490+00:00", "event": "ssh_shell_request", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin"}
{"ts": "2026-02-10T03:33:40.518604+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": ""}
{"ts": "2026-02-10T03:33:43.785168+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "test 123"}
{"ts": "2026-02-10T03:33:51.488780+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "hello?"}
{"ts": "2026-02-10T03:34:22.103610+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "whoamiwhoamiwhoamiwhoamiwhoamiwhoamiwhoamiwhoami"}
{"ts": "2026-02-10T03:34:24.021247+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "whoami"}
{"ts": "2026-02-10T03:34:50.879595+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "cacat secrets/flats.txt"}
{"ts": "2026-02-10T03:34:59.236422+00:00", "event": "ssh_command", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "username": "admin", "command": "exit"}
{"ts": "2026-02-10T03:34:59.237296+00:00", "event": "connection_close", "session_id": "1d954425-06ab-45b0-a00a-9f2592d95670", "src_ip": "172.20.0.1", "src_port": 52406, "duration_seconds": 93.7212}
{"ts": "2026-02-10T03:47:38", "event": "honeypot_start", "listen_host": "0.0.0.0", "listen_port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13"}
{"ts": "2026-02-10T03:48:27", "event": "connection_open", "src_ip": "172.20.0.1", "src_port": 60470, "dst_port": 22, "proto": "tcp"}
{"ts": "2026-02-10T03:48:27", "event": "error", "src_ip": "172.20.0.1", "src_port": 60470, "message": ""}
```

## Recommendations

- Keep the honeypot isolated from production services
- Forward honeypot logs to centralized logging/SIEM for correlation
- Trigger automated actions on brute-force alerts (e.g., block IP at firewall)
- Rotate credentials/secrets in real services if honeypot activity suggests exposure
