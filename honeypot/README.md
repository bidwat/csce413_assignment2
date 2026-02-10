# SSH Honeypot (Fix 2)

This honeypot simulates an SSH service and logs attacker activity for detection and analysis.  
It is designed to look like a real SSH server (realistic banner + interactive shell), while capturing
connection metadata, login attempts, and attacker commands.

## What this honeypot does

### Protocol simulated

- **SSH over TCP** (inside container on **port 22**)

### Convincing behavior

- Sends a realistic SSH banner:
  - `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13`
- Accepts password authentication (to encourage interaction)
- Provides a small “fake shell” prompt so commands can be typed and logged

### What gets logged

All logs are written as **JSON lines** to:

- `honeypot/logs/honeypot.log` (host-mounted)

Each connection includes:

- Source IP address + source port
- Timestamp (`ts`)
- Connection duration (`duration_s`)
- Username + password attempts
- Commands typed in the fake shell
- Optional alert events for brute-force patterns

## Files

- `honeypot.py` — main SSH honeypot implementation (Paramiko-based)
- `logger.py` — JSON logging helpers + optional brute-force alert tracker
- `Dockerfile` — container build (installs Paramiko)
- `logs/` — output directory (leave empty for submission)
- `analysis.md` — summary + example logged attacks (fill in after testing)

## How to run

### Start only the honeypot container

Run from the repo root:

```bash
docker compose up --build honeypot
```

### Verify it is running

```bash
docker compose ps
```

### View logs live

```bash
tail -f honeypot/logs/honeypot.log
```

## How to test

### 1) SSH into the honeypot

Depending on how your docker-compose maps ports, use one of:

```bash
ssh -p 2222 admin@localhost
```

or (inside the docker network / from another container):

```bash
ssh admin@172.20.0.30 -p 22
```

(Use any password — the honeypot accepts it to capture commands.)

### 2) Run a few commands in the fake shell

Try commands like:

- `whoami`
- `pwd`
- `ls`
- `uname -a`
- `cat /etc/os-release`

### 3) Confirm events are logged

Open the log file:

```bash
cat honeypot/logs/honeypot.log
```

You should see events like:

- `connection_open`
- `ssh_auth_password`
- `ssh_shell_opened`
- `ssh_command`
- `connection_close`
