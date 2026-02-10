**Author:** Bidwat Raj Pokhrel

**Repository:** [https://github.com/bidwat/csce413_assignment2](https://github.com/bidwat/csce413_assignment2)  
**Video:** [https://github.com/bidwat/csce413_assignment2](https://github.com/bidwat/csce413_assignment2)

---

## 1. Executive Summary

This assignment evaluates the security of a vulnerable multi-container Docker environment. The scope covered three phases:

1. **Network reconnaissance** using a custom port scanner to discover exposed and hidden services inside a Docker subnet.
2. **Man-in-the-Middle (MITM) analysis** of database traffic to confirm whether sensitive information was transmitted in plaintext and to leverage this to pivot to additional flags.
3. **Security fixes** in the form of a **port knocking** system to protect a hidden SSH service and an **SSH honeypot** to detect and log unauthorized access attempts.

### Critical Findings

- **Unencrypted internal database traffic:**
  Communication between the web application and the MySQL database was transmitted without TLS. My custom MITM analyzer showed SQL queries, responses, and secrets (including the API token, Flag 1) in **cleartext** on TCP port 3306.

- **Hidden but weakly protected SSH service:**
  A hidden SSH service on `172.20.0.20:2222` could be discovered with a basic port scan and accessed using a hard-coded username and password to obtain **Flag 2**.

- **Authentication via stolen API token:**
  The hidden HTTP API on `172.20.0.21:8888` trusted a bearer token (Flag 1) transmitted in plaintext via the database layer. Using this token as **alternate authentication material** allowed me to call `/flag` and retrieve **Flag 3**.

### Flags Captured

- **Flag 1 (API token, discovered via MITM):**
  `FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}`
- **Flag 2 (SSH hidden service):**
  `FLAG{h1dd3n_s3rv1c3s_n33d_pr0t3ct10n}`
- **Flag 3 (chained exploit via API token):**
  `FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}`

### Recommended Fixes (High-Level)

- Enforce **TLS/SSL** for all database connections and sensitive internal endpoints.
- Harden SSH by using **key-based auth**, disabling passwords, and not exposing it on predictable ports without additional controls.
- Introduce **network segmentation**, strict firewall rules, and internal-only access for sensitive services.
- Deploy defense-in-depth tools such as **port knocking** (implemented) and **honeypots** (implemented) to make enumeration and abuse more difficult and to detect intrusions early.

### Video Link

- **Overall demo and walkthrough:** https://youtu.be/L5hNe4EQ4mg

---

## 2. Part 1: Reconnaissance

### 2.1 Environment Setup

I cloned my forked repository and started the Docker environment:

```bash
git clone
```

```bash
cd csce413_assignment2
```

```bash
docker compose up --build -d
```

I confirmed that all services were running:

```bash
docker compose ps
```

### 2.2 Port Scanner Design and Implementation

For reconnaissance, I implemented a custom TCP port scanner in Python, starting from the provided template and refactoring it into cleaner modules (e.g., separating argument parsing, scanning logic, and output formatting).

Key characteristics of the scanner:

- **Input interface:**
  - Accepts a target IP or CIDR (e.g., `172.20.0.0/24`).
  - Accepts optional start and end ports (default 1–1024).
  - Shows open ports or all ports (configurable)
  - Supports optional output formats (txt, html, csv, json).
  - Supports multithreading.

- **Core logic:**
  - Uses `ipaddress` to expand CIDR ranges into individual IPs.
  - Uses the Python `socket` module to perform **TCP connect scans**:
    - Calls `socket.connect((target, port))` with a timeout.
    - If connect succeeds, port is marked **open**.
    - On timeout, `ConnectionRefusedError`, or `OSError` port is marked **closed**.

  - Measures elapsed time for each port using `time.perf_counter()`.

- **Banner / service detection:**
  - After a successful TCP connection:
    - Attempts to receive initial bytes from the service.
    - For non-MySQL banners, sends a small HTTP `HEAD / HTTP/1.1` request and reads the response.

  - Heuristics:
    - If response contains `"mysql"` → service `mysql`.
    - If response contains `"ssh"` → service `ssh`.
    - If response contains `"http"` or `"html"` → service `http`.
    - Otherwise, logs raw banner (if any) as a string.

- **Output:**
  - Plain text console output by default.
  - Optional export in `txt`, `csv`, `json`, or simple `html` file under a `SCANS/` folder, with each entry including:
    - target IP, port, open/closed, scan time, and detected banner.

This scanner is used throughout the assignment instead of external tools like `nmap` so that service discovery is reproducible and clearly attributable to my own code.

### 2.3 Methodology and Tools Used

Because I am working with Docker on a host (WSL2), it is often more reliable to scan from **inside** the Docker network rather than from the host.

First, I inspected the Docker network to confirm the subnet:

```bash
docker network inspect csce413_assignment2_vulnerable_network
```

From this, I learned that the vulnerable environment uses the `172.20.0.0/16` subnet and that each service is assigned a fixed IP (for example, the web app at `172.20.0.10` and the database at `172.20.0.11`).

To scan from inside that network, I started a Python container attached to the same network and mounted the repo:

```bash
docker run --rm -it --network csce413_assignment2_vulnerable_network -v "$PWD":/work -w /work python:3.11-alpine sh
```

Inside this container, I ran my port scanner across the `/24` range for ports 1–10000, focusing on open ports:

```bash
python3 -m port_scanner --target 172.20.0.0/24 --ports 1-10000 --threads 400 --timeout 0.05 --open-only --format txt
```

For archival purposes, I also saved results to txt file:

```
Found 7 open ports
Target: 172.20.0.1 | Port 111: open (0.0058s) | Service: null | Banner: null
Target: 172.20.0.1 | Port 5001: open (0.0106s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.10 | Port 5000: open (0.0358s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.11 | Port 3306: open (0.0714s) | Service: null | Banner: J
8.0.45IP?}]>MZ{1ZtPFj
mysql_native_password
Target: 172.20.0.20 | Port 2222: open (0.1127s) | Service: ssh | Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
Target: 172.20.0.21 | Port 8888: open (0.0222s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.22 | Port 6379: open (0.0918s) | Service: null | Banner: null

```

### 2.4 Discovered Services and Their Purposes

From the scan results and subsequent banner grabbing / manual inspection, I identified the following services:

```
Found 7 open ports
Target: 172.20.0.1 | Port 111: open (0.0058s) | Service: null | Banner: null
Target: 172.20.0.1 | Port 5001: open (0.0106s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.10 | Port 5000: open (0.0358s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.11 | Port 3306: open (0.0714s) | Service: null | Banner: J
8.0.45IP?}]>MZ{1ZtPFj
mysql_native_password
Target: 172.20.0.20 | Port 2222: open (0.1127s) | Service: ssh | Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
Target: 172.20.0.21 | Port 8888: open (0.0222s) | Service: http | Banner: Server: Werkzeug/3.1.5 Python/3.11.14
Target: 172.20.0.22 | Port 6379: open (0.0918s) | Service: null | Banner: null
```

#### Retrieving Flag 2 via Hidden SSH

To explore the hidden SSH service on port 2222 at `172.20.0.20`, I used the `nicolaka/netshoot` image because it includes `ssh` and other useful networking tools.

From the host:

```bash
docker run --rm -it --network csce413_assignment2_vulnerable_network nicolaka/netshoot sh
```

Inside the `netshoot` container, I connected to the hidden SSH server:

```bash
ssh -p 2222 sshuser@172.20.0.20
```

When prompted for a password, I entered:

```bash
SecurePass2024!
```

Once logged in, I found a secrets directory and read the flag:

```bash
FLAG{h1dd3n_s3rv1c3s_n33d_pr0t3ct10n}
```

This revealed:

```text
FLAG{h1dd3n_s3rv1c3s_n33d_pr0t3ct10n}
```

I then exited the SSH session and netshoot.

```bash
exit
exit
```

## 3. Part 2: MITM Attack

### 3.1 Vulnerability Analysis

The assignment description states that the web application communicates with a MySQL database. The key question is whether that communication is protected by TLS. If it is not, an adversary sharing the same network could perform a passive MITM attack to read queries and responses, including any secrets.

In this environment, the MySQL traffic on port 3306 is unencrypted:

- Cleartext SQL queries such as `SELECT id, username, email, role FROM users ORDER BY id` are visible.
- Cleartext responses from MySQL include sensitive data such as usernames, emails, roles, and entries in a `secrets` table.
- The API token (Flag 1) is stored in the database and is sent over this unencrypted channel, making it trivial for an attacker to steal.

This creates a classic **Use Alternate Authentication Material** scenario: once the token is retrieved from the database traffic, it can be used directly to authenticate to another service (`/flag` on the hidden API).

### 3.2 Capturing MySQL Traffic From Inside the Network

Rather than attempting to sniff a Docker bridge from the host (which is complicated on WSL2), I attached a `netshoot` container to the **webapp container’s network namespace**, so it sees the same traffic as the web app.

First, I created a directory to store packet captures:

```bash
mkdir -p mitm/artifacts
```

Then I started `netshoot` with `tcpdump` capabilities, sharing the `2_network_webapp` network namespace:

```bash
docker run --rm -it --network container:2_network_webapp --cap-add NET_ADMIN --cap-add NET_RAW -v "$PWD/mitm/artifacts":/out nicolaka/netshoot sh
```

Inside that container, I started capturing MySQL traffic:

```bash
tcpdump -i any -s 0 -w /out/mysql_3306.pcap tcp port 3306
```

With `tcpdump` running, I generated database traffic by using the web application from the host browser:

- Opened: `http://localhost:5001`
- Navigated through the user listing and other pages to trigger queries.

After sufficient traffic had been captured, I stopped `tcpdump` with `Ctrl+C` and exited the container:

```bash
exit
```

At this point, I had a packet capture at:

```text
mitm/artifacts/mysql_3306.pcap
```

### 3.3 Python MITM Analyzer and Extraction of Flag 1

The assignment provides a starter template for the MITM Python script in `mitm/`. I implemented `mitm.py` such that it:

- Reads a pcap file.
- Iterates through packets looking for TCP payloads on port 3306.
- Identifies “sensitive-looking” payloads:
  - ASCII-rich payloads containing keywords like `SELECT`, `FROM`, `WHERE`, or `FLAG{`.
  - MySQL protocol responses containing table and column names (`users`, `secrets`, `secret_value`, etc.).

- Prints a summary showing:
  - Source and destination IP/port.
  - Payload length.
  - Detection markers such as `SQL-LIKE TEXT` or `FLAG DETECTED`.

I created and activated a virtual environment and installed dependencies (if necessary):

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install scapy
```

Then I analyzed the captured pcap:

```bash
python3 mitm/mitm.py analyze --pcap mitm/artifacts/mysql_3306.pcap --show-all
```

The analyzer output clearly showed:

- The initial MySQL handshake.
- Client authentication details (including username `root` and client info).
- Cleartext SQL queries such as:

```text
SELECT id, username, email, role FROM users ORDER BY id
```

- A query to the `secrets` table:

```text
SELECT id, secret_name, secret_value, description FROM secrets WHERE id = 1
```

- A **response** containing the flag:

```text
secret_value: FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}
```

Thus, I extracted **Flag 1** from the MySQL traffic:

```text
FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}
```

### 3.4 Using Flag 1 to Capture Flag 3

During reconnaissance, I had already discovered the hidden HTTP API at `172.20.0.21:8888`. The root endpoint (`/`) returned JSON describing available endpoints, including `/flag`, which requires a bearer token.

To authenticate using the stolen token, I again used a curl container on the vulnerable network:

```bash
docker run --rm -it --network csce413_assignment2_vulnerable_network curlimages/curl:8.6.0 sh
```

Inside this container, I exported the token as an environment variable:

```bash
TOKEN='FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}'
```

Then I called the `/flag` endpoint with the bearer token:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://172.20.0.21:8888/flag
```

The response was JSON containing **Flag 3** and a message acknowledging the exploit chain:

```json
{
  "flag": "FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}",
  "message": "Congratulations! You successfully chained your exploits!",
  "steps_completed": [
    "1. Developed a port scanner",
    "2. Discovered this hidden API service on port 8888",
    "3. Performed MITM attack on database traffic",
    "4. Extracted FLAG{1} (the API token) from network packets",
    "5. Used FLAG{1} to authenticate to this API",
    "6. Retrieved FLAG{3}"
  ],
  "success": true
}
```

Afterwards, I exited the curl container:

```bash
exit
```

### 3.5 Real-World Impact Assessment

In a real environment, the weaknesses demonstrated here would be serious:

- **Eavesdropping:** Any attacker with access to the same internal network (e.g., a compromised container, developer laptop, or misconfigured service) could capture database traffic and read sensitive queries and results.
- **Credential and token theft:** Seeing passwords, API tokens, or session identifiers in cleartext enables impersonation without needing to break cryptography.
- **Attack chaining:** As shown, a single plaintext API token can be used to authenticate to other applications, escalate privileges, and exfiltrate more sensitive data (Flag 3).

Mitigating this requires both **encryption in transit** and **better secrets handling**, which I address in the recommendations section.

---

## 4. Part 3: Security Fixes

For Part 3, I focused on two defense-in-depth mechanisms:

1. **Port Knocking** to hide and protect the SSH service.
2. An **SSH Honeypot** to detect and log intrusions.

### 4.1 Fix 1 — Port Knocking

#### Design Decisions

- **Protected service:** SSH daemon listening on port 2222 inside the `port_knocking` container.
- **Knock sequence:** `1234, 5678, 9012`
  The sequence must be hit in order, using TCP connection attempts, within a **10-second window**.
- **Firewall mechanism:** Linux `iptables` with the `recent` module:
  - Tracks IP addresses that hit each knock port.
  - Only allows the protected port (2222) if the source IP has successfully completed the full sequence within the time window.

- **Server behavior:**
  - Installs the iptables rules on startup.
  - Listens (via TCP sockets) on each knock port to produce clear logging of knock attempts.

- **Client behavior:**
  - Sends short-lived TCP connection attempts to each knock port in sequence.
  - Optionally checks connectivity to the protected port after knocking (`--check`).

This design aligns with **Option C** in the assignment: port knocking implemented with `iptables` + `recent`, providing a stateless, kernel-level enforcement mechanism.

#### Implementation Details

Files in `port_knocking/`:

- `knock_server.py` — server-side logic and firewall rules.
- `knock_client.py` — client that sends TCP knock sequence.
- `entrypoint.sh` — initializes SSH and then starts the knock server in the container.
- `Dockerfile` — builds the port-knocking container with `iptables`, `iproute2`, `openssh-server`, and our Python code.
- `demo.sh` — helper script to demonstrate the entire knock flow.
- `README.md` — documentation.

**Server-side (`knock_server.py`):**

- On startup:
  - Configures logging.
  - Parses CLI flags:
    - `--sequence` (default `1234,5678,9012`)
    - `--protected-port` (default `2222`)
    - `--window` (default `10` seconds)

  - Calls `install_knock_rules(...)`, which:
    - Flushes existing rules.
    - Creates a chain of rules for each knock step using `-m recent --name KNOCKn --set / --rcheck`.
    - Adds an `ACCEPT` rule on the protected port if the final stage (`KNOCK3`) is present and not expired.
    - Adds a default `DROP` rule on protected port 2222.

  - Starts a TCP listener on each knock port (1234, 5678, 9012) to log incoming connections:
    - For each connection, logs `"Received knock from <ip>:<port> on port <knock_port>"` and closes immediately.

**Client-side (`knock_client.py`):**

- Parses CLI arguments:
  - `--target` (required: host or IP)
  - `--sequence` (default `1234,5678,9012`)
  - `--protected-port` (default `2222`)
  - `--delay` between knocks (default `0.3` seconds)
  - `--check` (optional: test connecting to protected port after knocking)

- For each port in the sequence:
  - Creates a TCP socket.
  - Attempts to connect to `<target>:<port>` with a short timeout.
  - Closes the socket.
  - Sleeps for the configured delay.

- If `--check` is set, calls `check_protected_port()` to attempt a TCP connection to `<target>:2222` and prints whether it succeeded.

#### How to Run and Test Port Knocking (Happy Path)

1. **Start the port_knocking container** from the repo root:

   ```bash
   docker compose up --build port_knocking
   ```

   Keep this terminal open to watch logs from the server.

2. **In a second terminal**, find the running container name:

   ```bash
   docker compose ps
   ```

   Identify the row for the `port_knocking` service (e.g. `csce413_assignment2-port_knocking-1`).

3. **Exec into the port_knocking container:**

   ```bash
   docker exec -it csce413_assignment2-port_knocking-1 bash
   ```

4. **Get the container’s IP address:**

   ```bash
   hostname -i
   ```

   Suppose the IP is `172.20.0.40`. This will be the `TARGET_IP`.

5. **Verify SSH port 2222 is closed before knocking:**

   ```bash
   nc -z -v 172.20.0.40 2222
   ```

   This should fail (port is dropped by default).

6. **Perform the knock sequence using the client inside the container:**

   ```bash
   python3 /app/knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012 --check
   ```

   In the server logs (Terminal #1), you will see log entries for knocks on 1234, 5678, and 9012, followed by a message indicating that the protected port has been opened for that IP.

7. **Confirm that SSH port 2222 is now open:**

   ```bash
   nc -z -v 172.20.0.40 2222
   ```

   This should now succeed.

8. **SSH into the protected service:**

   ```bash
   ssh -p 2222 knockuser@172.20.0.40
   ```

   When prompted, enter the demo password (for example):

   ```bash
   knockme
   ```

   You now have a shell via the protected SSH service.

9. **Wait for the time window to expire (e.g. >10 seconds) and recheck the port:**

   ```bash
   nc -z -v 172.20.0.40 2222
   ```

   It should be closed again once the `recent` entry expires.

**Optional:** Instead of manual steps 5–7, you can also use `demo.sh`:

```bash
/app/demo.sh 172.20.0.40 "1234,5678,9012" 2222
```

This script attempts the protected port before and after calling `knock_client.py`.

#### Security Analysis

- **Benefits:**
  - The SSH service is effectively **hidden** from unauthenticated port scans since port 2222 is dropped by default. An attacker scanning the network sees a closed/filtered port unless they know and perform the correct knock sequence.
  - The `recent` module enforces **ordering and timing**, making it significantly harder to guess the correct sequence by brute force.
  - Because enforcement lives in `iptables` (kernel level), it is less likely to be bypassed by user-space process compromise.

- **Limitations:**
  - Port knocking is **security by obscurity**. If an attacker learns the sequence (e.g., by monitoring traffic or reading configuration), the protection is gone.
  - Our implementation uses a relatively **short sequence** and a **short time window**. Longer and more complex sequences would increase security but also complexity.
  - The current design doesn’t implement rate-limiting or automatic blacklisting of IPs that repeatedly knock incorrectly.

- **Potential Improvements:**
  - Add randomization or rotation of the knock sequence.
  - Integrate logging/alerting for repeated failed sequences.
  - Combine port knocking with additional controls like SSH key-only authentication and IP allowlists.

---

### 4.2 Fix 2 — SSH Honeypot

#### Architecture and Design

For the honeypot, I chose to simulate an **SSH service** because:

- SSH is a high-value target in real-world attacks.
- Attackers often brute-force SSH credentials and attempt command execution.

The honeypot is implemented using **Python + Paramiko**:

- Listens on `0.0.0.0:22` **inside the honeypot container**.

- The Docker Compose configuration maps a host port (e.g. `2222`) to container port `22`.
  For testing examples, I use:

  ```bash
  ssh admin@localhost -p 2222
  ```

- Generates an ephemeral RSA host key on startup.

- Sends a legitimate-looking SSH banner:

  ```text
  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
  ```

  This is copied from a real OpenSSH server, making scans and initial banners indistinguishable from a normal SSH service.

The main components are:

- `honeypot/honeypot.py` — Implements the Paramiko server interface and connection handling.
- `honeypot/logger.py` — Provides a logger that writes to both stdout and a log file.
- `honeypot/logs/honeypot.log` — Log output directory (kept empty in repo, used at runtime).
- `honeypot/analysis.md` — Summary of observed attacks and patterns.
- `honeypot/Dockerfile` — Container setup and entrypoint.

#### Logging Mechanisms

`logger.py`:

- Creates a logger named `"Honeypot"`.
- Writes logs to `/app/logs/honeypot.log` and to stderr/stdout.
- Ensures consistent timestamped logging in the format:

  ```text
  YYYY-MM-DD HH:MM:SS,ms - LEVEL - message
  ```

`honeypot.py`:

- On every new TCP connection:
  - Logs the source IP and port:

    ```text
    Connection from <ip>:<port>
    ```

- During SSH authentication attempts:
  - Overrides `check_auth_password()` in a custom `ServerInterface` subclass.
  - Logs each username/password combination:

    ```text
    SSH login attempt | user='<username>' password='<password>'
    ```

- Tracks the number of attempts per connection:
  - After a small number of attempts (e.g., 3), authentication is always rejected.
  - Logs when the connection is closed.

- Optional “suspicious” indicators:
  - If specific usernames like `root` or `admin` appear.
  - If many failed attempts are seen from the same IP over time (analysis is done in `analysis.md`).

#### Detection Capabilities

While the honeypot does not give attackers a real shell, it provides:

- **Credential harvesting:** All attempted username/password pairs are recorded. These can be compared against known leak patterns or used as indicators of compromise elsewhere.
- **Source profiling:**
  - IP address and source port.
  - Frequency and timing of connection attempts.

- **Behavioral patterns:**
  - Rapid repeated attempts (indicative of brute-force tools).
  - Specific username lists (e.g. `root`, `ubuntu`, `ec2-user`) used by common SSH brute-forcers.

This makes the honeypot useful for:

- Early detection of active scans on the network.
- Gathering intelligence about attacker behavior and tooling.

#### How to Run and Test the Honeypot (Happy Path)

1. **Start the honeypot service** from the repo root:

   ```bash
   docker compose up --build honeypot
   ```

   The honeypot container will listen on port 22 internally, with the host port mapped to something like 2222 (depending on your `docker-compose.yml`).

2. **From another terminal on the host**, simulate an attack by connecting via SSH:

   ```bash
   ssh admin@localhost -p 2222
   ```

   When prompted for a password, try some dummy values:

   ```bash
   password123
   ```

   and then:

   ```bash
   letmein
   ```

   or other likely guesses.

3. Optionally attempt different usernames:

   ```bash
   ssh root@localhost -p 2222
   ```

   And again enter some passwords.

4. **View the logs** inside the honeypot container or on the host volume mapping:

   ```bash
   docker exec -it <honeypot_container_name> cat /app/logs/honeypot.log
   ```

   Sample log lines will look like:

   ```text
   2026-01-31 23:00:00,816 - INFO - Connection from 172.20.0.1:55900
   2026-01-31 23:00:00,900 - WARNING - SSH login attempt | user='admin' password='password123'
   2026-01-31 23:00:01,050 - WARNING - SSH login attempt | user='admin' password='letmein'
   2026-01-31 23:00:01,300 - INFO - Connection closed for 172.20.0.1
   ```

   These logs demonstrate that the honeypot captures and records all attempted credentials and connection metadata.

#### Analysis of Captured Attacks

In `honeypot/analysis.md`, I summarized patterns observed in my test attacks:

- Login attempts with common usernames (`admin`, `root`) and simple passwords.
- Repeated failed logins from a single IP in a short timeframe (brute-force behavior).
- No successful authentication events, since the honeypot always rejects credentials.

In a real deployment, these patterns would trigger alerts and the offending IPs could be blocked or added to a blacklist.

---

## 5. Remediation Recommendations

### 5.1 Fixing the MITM Vulnerability (TLS/SSL)

To address the unencrypted database traffic:

- **Enable TLS for MySQL:**
  Configure the MySQL server to use a server certificate and enforce `REQUIRE SSL` for the webapp’s database user.
  Update the web application’s database client configuration to use TLS (e.g., `ssl_ca`, `ssl_cert`, `ssl_key` options in the client drivers).

- **Avoid sending secrets in cleartext queries/responses:**
  - Consider storing tokens in a hashed or encrypted form.
  - Avoid returning raw API tokens from the database through normal application queries.
  - Use short-lived, scoped tokens stored in a dedicated secrets manager.

### 5.2 Best Practices for Protecting Service Discovery

- **Minimize exposed surfaces:**
  Only expose services that must be externally reachable (e.g., the front-end HTTP port). Keep backends like databases, Redis, and internal APIs bound to internal networks only.

- **Use non-predictable ports + access control:**
  While obscurity is not a complete defense, moving critical services away from default ports and enforcing host-based firewalls (`iptables`/`nftables`) reduces the chance of casual discovery.

- **Port knocking and rate-limiting:**
  The port knocking system implemented here can be combined with:
  - SSH key-only login.
  - Fail2ban or rate-limiting tools.
  - IP allowlists to further restrict access.

### 5.3 Network Segmentation Strategies

- **Separate network zones:**
  - Place public-facing services (web frontends) in a DMZ.
  - Place databases and internal APIs in a restricted backend network.
  - Restrict communication between networks with firewall rules.

- **Least privilege routing:**
  - Explicitly allow only the necessary traffic (webapp → DB, webapp → Redis, etc.).
  - Deny everything else by default (including arbitrary inter-container communication).

- **Container isolation:**
  - Use separate user accounts and namespaces for each container.
  - Avoid sharing network namespaces unless absolutely necessary.

### 5.4 Monitoring and Detection Recommendations

- **Centralized logging and SIEM:**
  - Forward logs from all containers (web app, database, honeypot, port knocking server) to a centralized log system.
  - Use a SIEM to correlate events such as:
    - Repeated failed SSH attempts.
    - Suspicious queries or spikes in traffic.
    - Honeypot hits.

- **Network intrusion detection systems (NIDS):**
  - Deploy tools like Snort or Suricata to inspect network traffic for known signatures and anomalies.
  - Configure alerts for unexpected MySQL traffic, strange SSH fingerprints, or repeated scans.

- **Leverage honeypots as tripwires:**
  - Treat any interaction with the honeypot as a strong signal of malicious behavior.
  - Automate alerts or blacklisting when the honeypot log records suspicious activity.

---

## 6. Conclusion

### 6.1 Lessons Learned

This assignment demonstrated how:

- Basic reconnaissance with a custom port scanner is sufficient to map out internal services in a Docker environment.
- Internal traffic is not automatically safe; if encryption is not enforced, anyone on the same network can observe and exploit sensitive data.
- Attack chains are powerful: a single leaked API token (Flag 1) can be used to authenticate to other services, pivot to hidden APIs, and exfiltrate more secrets (Flag 3).

### 6.2 Skills Acquired

Throughout the assignment, I strengthened skills in:

- **Python network programming** (socket-based port scanner, banner grabbing).
- **Traffic analysis** (using `tcpdump`, custom pcap analyzers).
- **Defensive controls:**
  - Configuring `iptables` and the `recent` module.
  - Implementing port knocking for SSH.
  - Building an SSH honeypot with Paramiko and structured logging.

- **Docker-based workflows** for offensive and defensive security in containerized environments.

### 6.3 Future Work

Possible extensions include:

- Implementing full **TLS** for all sensitive services and verifying it with packet captures.
- Expanding the port knocking system with dynamic knock sequences, IP blacklisting, and integration with a central monitoring system.
- Extending the honeypot to support a **fake interactive shell**, logging commands and file operations to better understand attacker behavior.
- Automating correlation between honeypot hits, scanner logs, and application logs to build richer detection and response workflows.
