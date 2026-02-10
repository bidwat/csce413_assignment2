# Port Knocking

This implementation protects an SSH service on TCP port **2222** using **port knocking**.

## Protected Service

- **SSH** on port **2222**
- The port is **blocked by default** via `iptables`
- After a valid knock sequence, the port is opened **only for the source IP** for a short time

## Knock Sequence

Default sequence:

- `1234, 5678, 9012`

Constraints:

- The sequence must be completed within **10 seconds**.
- Any incorrect knock resets progress.
- After success, the protected port opens for **20 seconds**, then closes automatically.

## How it works

### Server (`knock_server.py`)

- Listens on the knock ports using TCP sockets (so it can log and validate knocks).
- Tracks progress per source IP.
- Uses `iptables` to:
  - enforce a default **DROP** rule on the protected port
  - insert a temporary **ACCEPT** rule for the source IP when the sequence is completed

### Client (`knock_client.py`)

- Sends TCP connection attempts to each knock port in order.
- Optionally checks reachability of the protected port after knocking.

## Files

- `knock_server.py` — server-side knock listener + iptables open/close
- `knock_client.py` — client-side knock sender
- `entrypoint.sh` — starts sshd on 2222, then starts knock server
- `Dockerfile` — container image
- `demo.sh` — demonstration script

## Run

From the repo root:

```bash
docker compose up --build port_knocking
```

## Demo (recommended)

Open another terminal (still repo root) and exec into the container:

```bash
docker exec -it 2_network_port_knocking bash
```

Then run:

```bash
./demo.sh 172.20.0.40 "1234,5678,9012" 2222
```

## Manual test (from any container on the same docker network)

Before knocking (should fail):

```bash
ssh -p 2222 knockuser@172.20.0.40
```

Send knocks:

```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```

After knocking (should succeed briefly):

```bash
ssh -p 2222 knockuser@172.20.0.40
```

Demo credentials (assignment-only):

- user: `knockuser`
- pass: `knockme`

## Notes / Real-world security

Port knocking is **defense-in-depth**. It reduces exposure to automated scans,
but it does not replace real hardening:

- prefer SSH keys over passwords
- enforce MFA where possible
- restrict access by network segmentation and allow-lists
