# scantop100

Top-100 port scanner with service and version detection.  
Runs `nmap -n --top-ports 100 --min-rate 300 -sV` against each target.  
Designed to feed directly from `fastcheck` output and produce structured data for the attack phase.

## Quick start

```bash
# Single host
python scantop100.py 192.168.1.1

# Feed fastcheck results (up hosts extracted automatically)
python scantop100.py -f fastcheck_results.jsonl -o ports.jsonl

# Subnet
python scantop100.py 192.168.1.0/24 -o ports.jsonl

# Only save hosts that have open ports
python scantop100.py -f targets.jsonl -o ports.jsonl --open-only

# Analyze results on screen
python scantop100.py --analyze ports.jsonl
python scantop100.py --analyze ports.jsonl | less -R
```

## Prerequisites

```bash
brew install nmap      # macOS
apt  install nmap      # Debian / Ubuntu
```

No Python packages required — stdlib only.

---

## Usage

```
python scantop100.py [options] [TARGET]

Positional:
  TARGET              IP, CIDR, range (10.0.0.1-50), or hostname

Scan options:
  -f, --file FILE     Target file: plain text (one per line) or fastcheck .jsonl
  -o, --output FILE   Output .jsonl file
                      Optional for single targets; prompted (mandatory) for multiple
  -w, --workers N     Parallel nmap processes (default: 5)
  --timeout SEC       Per-host nmap timeout in seconds (default: 120)
  --open-only         Only write hosts with at least one open port

Analysis:
  --analyze FILE      Read a .jsonl result file and print a human-readable report
                      Pipe to  | less  or  | less -R  for paging
```

---

## Analyzing results

After a scan, use `--analyze` to get a structured human-readable report on screen:

```bash
python scantop100.py --analyze ports.jsonl
```

Pipe to `less` for paging (plain text, no colour codes):

```bash
python scantop100.py --analyze ports.jsonl | less
```

Keep colours with `less -R`:

```bash
python scantop100.py --analyze ports.jsonl | less -R
```

### Report layout

```
══════════════════════════════════════════════════════════════
  ports.jsonl
══════════════════════════════════════════════════════════════
  Hosts scanned    : 5
  With open ports  : 3
  No open ports    : 1
  Errors / timeout : 1
  Total open ports : 8
  Top services     : ssh(2)  http(2)  https(2)  mysql(1)
══════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────
  10.0.0.1  ·  router.internal  (18s)
──────────────────────────────────────────────────────────────
  22/tcp        ssh              OpenSSH 9.2p1 Debian 2
  80/tcp        http             Apache httpd 2.4.57
  443/tcp       https

──────────────────────────────────────────────────────────────
  10.0.0.5  ·  db01.internal  (22s)
──────────────────────────────────────────────────────────────
  22/tcp        ssh              OpenSSH 8.9p1
  3306/tcp      mysql            MySQL 8.0.32

┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
  No open ports (1):
    10.0.0.9

  Errors / timeout (1):
    10.0.0.12  (timeout)
```

Colours are applied when writing to a terminal and stripped automatically when piped.  
Hosts are sorted by IP address. The footer lists hosts with no open ports and any errors.

---

## Workflow: fastcheck → scantop100

```bash
# Step 1 — discover live hosts
python ../fastcheck/fastcheck.py 10.0.0.0/24 --light -o live.jsonl

# Step 2 — port scan only the live ones
python scantop100.py -f live.jsonl -o ports.jsonl
```

`scantop100` auto-detects the fastcheck `.jsonl` format and extracts only `"status": "up"` entries. No manual filtering needed.

---

## Pause and resume

### Pause
Press **Ctrl+C** during a scan. Workers finish their current host, then wait.  
The footer shows `⏸ PAUSED  ↵ resume  ·  Ctrl+C quit`.

### Resume from pause
Press **Enter**.

### Quit while paused
Press **Ctrl+C** again.

### Resume after a stopped scan

Re-run the **exact same command**. Already-scanned hosts are detected from
the output file and skipped — the scan continues from where it stopped.

```bash
# First run — interrupted at 150/400
python scantop100.py -f live.jsonl -o ports.jsonl

# Re-run — picks up at 151/400
python scantop100.py -f live.jsonl -o ports.jsonl

# Output:
# Resume: 150 already scanned, 250 remaining.
```

The output file is opened in **append mode** on resume, so completed records are preserved.

---

## High-volume scanning

### Memory

Target lists are generated lazily — a `/8` CIDR uses the same ~few MB of RAM as a single IP. A bounded sliding window (`workers × 4` futures) ensures the task queue never grows unbounded.

### Tuning workers

Port scanning is much slower than ping scanning (typically 15–120 s per host). Too many parallel nmap processes creates noise and can trigger IDS/rate-limiting.

| Target count | Recommended `-w` | Notes |
|---|---|---|
| < 100 | `5` (default) | No tuning needed |
| 100 – 1 000 | `10–20` | Good balance of speed vs. noise |
| 1 000 – 10 000 | `20–50` | Use `--open-only` to keep output small |
| 10 000+ | `50–100` | Consider splitting by subnet across machines |

```bash
# Large scan — 20 workers, save only hosts with open ports
python scantop100.py -f live.jsonl -o ports.jsonl -w 20 --open-only
```

---

## Live display

Fixed header, scrolling IP list, fixed footer — the screen never scrolls on large scans.

```
──────────────────────────────────────────────────────────────────
  scantop100  ·  nmap 7.99
  Targets: 142  Workers: 10  Timeout: 120s  →  ports.jsonl
──────────────────────────────────────────────────────────────────
  [  8/142]  10.0.0.8          open  22 80 443                     ▲
  [  9/142]  10.0.0.9          none  14s                            │
  [ 11/142]  10.0.0.11         open  22 3306 8080                   │ scroll
  [ 14/142]  10.0.0.14         down                                 │ region
  [ 15/142]  10.0.0.15         open  80 443                         ▼
──────────────────────────────────────────────────────────────────
  Open: 3      None: 2      [█████████░░░░░░░░░░░░░░░░░░░]  15/142
──────────────────────────────────────────────────────────────────
```

When output is piped or redirected (non-TTY), plain line-by-line output is used instead.

---

## Output format (JSONL)

One JSON object per host, written and flushed immediately on completion.  
Valid JSONL even if the scan is interrupted mid-way.

```jsonl
{"timestamp":"2026-05-08T10:01:15Z","target":"10.0.0.8","input":"live.jsonl","host_status":"up","open_ports":[22,80,443],"ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","version":"OpenSSH 9.2p1"},{"port":80,"protocol":"tcp","state":"open","service":"http","version":"Apache httpd 2.4.57"},{"port":443,"protocol":"tcp","state":"open","service":"https","version":""}],"hostname":"web01.internal","scan_duration_s":18.4,"nmap_version":"7.99"}
{"timestamp":"2026-05-08T10:01:33Z","target":"10.0.0.9","input":"live.jsonl","host_status":"up","open_ports":[],"ports":[],"hostname":null,"scan_duration_s":14.1,"nmap_version":"7.99"}
```

### Fields

| Field            | Type            | Description                                      |
|------------------|-----------------|--------------------------------------------------|
| `timestamp`      | ISO-8601 string | UTC time the scan completed                      |
| `target`         | string          | Scanned IP or hostname                           |
| `input`          | string          | Original source (file path or CLI spec)          |
| `host_status`    | string          | `up`, `down`, `no_response`, `timeout`, `error`  |
| `open_ports`     | int list        | Port numbers with state `open`                   |
| `ports`          | object list     | Full port detail (see below)                     |
| `hostname`       | string / null   | Reverse-DNS or nmap-resolved hostname            |
| `scan_duration_s`| float           | Wall-clock seconds for this host's scan          |
| `nmap_version`   | string          | nmap version used                                |

**`ports[]` object:**

| Field      | Description                              |
|------------|------------------------------------------|
| `port`     | Port number                              |
| `protocol` | `tcp` or `udp`                           |
| `state`    | Always `open` (filtered/closed excluded) |
| `service`  | Service name (e.g. `ssh`, `http`)        |
| `version`  | Product + version string from `-sV`      |

---

## Reading the output for attack phase

### One-liners

```bash
# All hosts with open ports
jq -r 'select(.open_ports | length > 0) | .target' ports.jsonl

# Hosts running SSH
jq -r '.ports[] | select(.service == "ssh") | .port' ports.jsonl   # just ports
jq 'select(.ports[].service == "ssh")' ports.jsonl                  # full records
```

### Python

```python
import json

with open("ports.jsonl") as fh:
    for line in fh:
        r = json.loads(line)
        if r["open_ports"]:
            print(r["target"], r["open_ports"])
```

### jq recipes

```bash
# IPs with SSH open (feed to hydra, ssh-audit, etc.)
jq -r 'select(.ports[].service == "ssh") | .target' ports.jsonl

# IPs with HTTP/HTTPS
jq -r 'select(.open_ports | map(. == 80 or . == 443 or . == 8080 or . == 8443) | any) | .target' ports.jsonl

# Port + service + version for every open port
jq -r '.target as $t | .ports[] | [$t, (.port|tostring), .service, .version] | @tsv' ports.jsonl

# Hosts with more than 5 open ports (high-value targets)
jq 'select(.open_ports | length > 5)' ports.jsonl

# Group by open port (which hosts have port 3306 open?)
jq -r 'select(.open_ports[] == 3306) | .target' ports.jsonl

# Summary: service → count
jq -s '[.[].ports[].service] | group_by(.) | map({service: .[0], count: length}) | sort_by(-.count)' ports.jsonl

# Export for Metasploit (IP:port pairs)
jq -r '.target as $t | .ports[] | "\($t):\(.port)"' ports.jsonl
```

### Shell pipeline example

```bash
# Full workflow: discover → scan → attack SSH
python ../fastcheck/fastcheck.py 10.0.0.0/24 --light -o live.jsonl
python scantop100.py -f live.jsonl -o ports.jsonl --open-only

# Feed SSH targets to hydra
jq -r 'select(.ports[].service == "ssh") | .target' ports.jsonl \
  | xargs -I{} hydra -L users.txt -P passwords.txt {} ssh
```

---

## Notes

- **Root / sudo**: `nmap -sV` defaults to `-sS` (SYN scan) when root, `-sT` (connect scan) when not. Both work; SYN is faster and stealthier.
- **`--min-rate 300`**: enforces a minimum send rate but nmap may go faster. Reduce to `100` on slow or rate-limited networks.
- **Resume safety**: the output file is never truncated on resume — only new records are appended. Duplicate scanning of completed hosts is impossible.
- **Results are unordered**: threads complete in parallel. Use the `timestamp` field to reconstruct chronological order if needed.
- **Non-TTY mode**: when stdout is a pipe or file, plain line-by-line output is used instead of the live TUI.
