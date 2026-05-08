# fastcheck

Rapid host-discovery scanner using `nmap -sn` (ping scan).  
Checks each target individually so CIDR blocks and ranges are handled IP by IP.  
Results stream live inside a fixed terminal view — the screen never scrolls.

## Quick start

```bash
# Default scan (high-accuracy) — requires root/sudo for TCP/UDP probes
sudo python fastcheck.py 8.8.8.8
sudo python fastcheck.py 192.168.1.0/24 -o results.jsonl

# Light scan — ICMP + ARP only, no root required, faster but less thorough
python fastcheck.py 8.8.8.8 --light
python fastcheck.py 192.168.1.0/24 --light -o results.jsonl

# File of targets
sudo python fastcheck.py -f targets.txt -o results.jsonl

# Only write live hosts to the output file
sudo python fastcheck.py -f targets.txt -o up_hosts.jsonl --up-only
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
python fastcheck.py [options] [TARGET]

Positional:
  TARGET              IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname

Options:
  -f, --file FILE     File containing targets, one per line (# = comment)
  -o, --output FILE   Output .jsonl file
                      Optional for single targets; prompted (mandatory) for multiple
  -w, --workers N     Parallel nmap processes (default: 10)
  --timeout SEC       Per-host nmap timeout in seconds
                      Default: 10s (default scan)  /  5s (--light)
  --light             Use ICMP echo + ARP only — no root required, faster,
                      but misses hosts that block ICMP
  --up-only           Only write 'up' hosts to the output file
```

### Target formats

| Input               | Expands to                    |
|---------------------|-------------------------------|
| `8.8.8.8`           | single IP                     |
| `10.0.0.0/24`       | 10.0.0.1 … 10.0.0.254 (254)  |
| `10.0.0.1-10.0.0.5` | 10.0.0.1 … 10.0.0.5  (5)    |
| `10.0.0.1-5`        | 10.0.0.1 … 10.0.0.5  (5)    |
| `example.com`       | hostname (as-is)              |

### Target file format

```
# my network
192.168.1.0/24
10.0.0.1-20
8.8.8.8
example.com
```

---

## Scan modes

### Default — high-accuracy (recommended)

```bash
sudo python fastcheck.py 192.168.1.0/24 -o results.jsonl
```

Uses five probe types in parallel. A host is marked **up** if *any* probe gets a response, so firewalled and filtered hosts are far less likely to be missed.

| Flag | Probe | Why it helps |
|------|-------|--------------|
| `-PS22,80,443` | TCP SYN to ports 22, 80, 443 | Discovers hosts that answer SSH / HTTP / HTTPS even when ICMP is blocked |
| `-PA80,443` | TCP ACK to ports 80, 443 | Bypasses stateful firewalls that silently drop SYN packets |
| `-PU161` | UDP to port 161 (SNMP) | Discovers network devices, printers, and routers that speak UDP only |
| `-PE` | ICMP echo request | Classic ping — works on most unfiltered hosts |
| `-PP` | ICMP timestamp request | Fallback for hosts that block echo but allow timestamp replies |

**Requires root / sudo** because raw TCP and UDP packets need elevated socket privileges.  
Default timeout: **10 s** per host (more probes need more time).

### Light mode (`--light`)

```bash
python fastcheck.py 192.168.1.0/24 --light -o results.jsonl
```

Uses nmap's built-in default probes: ICMP echo + ARP (on local networks).  
No root required. Faster, but will miss hosts that block ICMP.  
Default timeout: **5 s** per host.

---

## Live display

When run in an interactive terminal the screen is split into three fixed zones.
Only the IP list scrolls — the header and progress bar never move.

```
──────────────────────────────────────────────────────────────────
  fastcheck  ·  nmap 7.99
  Targets: 254  Workers: 10  Timeout: 5s  →  results.jsonl
──────────────────────────────────────────────────────────────────
  [ 14/254]  192.168.1.14   up    0.31ms    printer.local          ▲
  [ 22/254]  192.168.1.22   down                                    │
  [ 37/254]  192.168.1.37   up    1.02ms                            │  scroll
  [ 41/254]  192.168.1.41   up    0.88ms    nas.local               │  region
  [ 55/254]  192.168.1.55   down                                    │
  [ 60/254]  192.168.1.60   up    0.54ms    desktop.local           ▼
──────────────────────────────────────────────────────────────────
  Up: 12     Down: 48     [████████████░░░░░░░░░░░░░░░░░░]  60/254
──────────────────────────────────────────────────────────────────

  Summary
  Up     : 42
  Down   : 212
  Output : results.jsonl  (38,291 bytes, 254 records)
──────────────────────────────────────────────────────────────────
```

**Header** (fixed): tool info, target count, output path.  
**Scroll region**: new results appear at the bottom; older ones scroll up and out. The viewport height adjusts to your terminal size.  
**Footer** (fixed): live counts and a progress bar, updated after every result.  
**Summary**: printed once after the scan finishes, below the restored terminal.

When output is piped or redirected (non-TTY), results are printed line-by-line without any cursor movement.

---

## Output format (JSONL)

One JSON object per line, written as each result arrives.  
The file is readable even if the scan is interrupted mid-way.

```jsonl
{"timestamp":"2026-05-08T10:00:01.234Z","input":"192.168.1.0/24","target":"192.168.1.1","status":"up","latency_ms":0.42,"hostname":"router.local","mac":"AA:BB:CC:DD:EE:FF","nmap_version":"7.99"}
{"timestamp":"2026-05-08T10:00:01.891Z","input":"192.168.1.0/24","target":"192.168.1.2","status":"down","latency_ms":null,"hostname":null,"mac":null,"nmap_version":"7.99"}
```

### Fields

| Field          | Type            | Description                                 |
|----------------|-----------------|---------------------------------------------|
| `timestamp`    | ISO-8601 string | UTC time the scan completed                 |
| `input`        | string          | Original target spec (e.g. `10.0.0.0/24`)  |
| `target`       | string          | Resolved IP address                         |
| `status`       | string          | `up`, `down`, `timeout`, `error`, `unknown` |
| `latency_ms`   | float / null    | Round-trip time in milliseconds             |
| `hostname`     | string / null   | Reverse-DNS hostname (PTR record)           |
| `mac`          | string / null   | MAC address (LAN only, requires root/sudo)  |
| `nmap_version` | string          | nmap version used for this scan             |

---

## Reading the output in other tools

### One-liners

```bash
# Python — print IPs of live hosts
python3 -c "import json; [print(r['target']) for r in map(json.loads, open('results.jsonl')) if r['status'] == 'up']"

# jq — same thing
jq -r 'select(.status == "up") | .target' results.jsonl
```

### Python

```python
import json

results = [json.loads(line) for line in open("results.jsonl")]

# All live hosts
up = [r for r in results if r["status"] == "up"]

# Just the IPs
ips = [r["target"] for r in up]
```

### jq

```bash
# All live hosts
jq 'select(.status == "up")' results.jsonl

# Live IPs as plain text (feed into another tool)
jq -r 'select(.status == "up") | .target' results.jsonl

# Live hosts with hostname and latency
jq -r 'select(.status == "up") | [.target, .hostname, .latency_ms] | @tsv' results.jsonl

# Count by status
jq -s 'group_by(.status) | map({status: .[0].status, count: length})' results.jsonl

# Hosts with MAC addresses (LAN, requires root)
jq 'select(.mac != null)' results.jsonl
```

### Shell

```bash
# Pipe live IPs directly into ip2location
jq -r 'select(.status == "up") | .target' results.jsonl \
  | xargs -I{} python ../ip2location/ip2location.py {}

# Quick count
grep -c '"status":"up"' results.jsonl
```

---

## Notes

- **Root / sudo**: the default scan uses raw TCP/UDP packets and requires root (or nmap's setuid bit) on Linux. `--light` (ICMP + ARP) works without root on macOS and most Linux distros.
- **`scan_mode` field**: every JSONL record includes `"scan_mode": "default"` or `"scan_mode": "light"` so downstream tools know which probe set was used.
- **Results are unordered**: threads complete in parallel; `[X/N]` shows completion order, not input order. The original spec is preserved in the `input` field.
- **Interrupted scans**: the output file is written and flushed incrementally — it is valid JSONL even if the scan is stopped early with Ctrl-C.
- **Non-TTY mode**: when stdout is a pipe or file, the live display is replaced with plain line-by-line output and no cursor movement.
