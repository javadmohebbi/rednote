# fastcheck

Rapid host-discovery scanner using `nmap -sn` (ping scan).  
Handles single IPs, CIDRs, ranges, and multi-million-target files with flat memory usage.  
Results stream live inside a fixed terminal view — the screen never scrolls.

## Quick start

```bash
# Default scan (high-accuracy) — requires root/sudo for TCP/UDP probes
sudo python fastcheck.py 8.8.8.8
sudo python fastcheck.py 192.168.1.0/24 -o results.jsonl

# Light scan — ICMP + ARP only, no root required, faster but less thorough
python fastcheck.py 8.8.8.8 --light
python fastcheck.py 192.168.1.0/24 --light -o results.jsonl

# Large-scale scan — increase workers and use --light for speed
python fastcheck.py 10.0.0.0/8 --light -w 100 -o results.jsonl

# File of targets (any mix of IPs, CIDRs, ranges)
sudo python fastcheck.py -f targets.txt -o results.jsonl --up-only
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

All formats are supported on the command line and inside target files.  
Spaces around the dash are optional.

| Input                   | Expands to                    |
|-------------------------|-------------------------------|
| `8.8.8.8`               | single IP                     |
| `10.0.0.0/24`           | 10.0.0.1 … 10.0.0.254 (254)  |
| `10.0.0.0/8`            | 10.0.0.1 … 10.255.255.254 (16 M) |
| `10.0.0.1-10.0.0.50`    | 10.0.0.1 … 10.0.0.50  (50)   |
| `10.0.0.1 - 10.0.0.50`  | same, spaces around dash OK   |
| `10.0.0.1-50`           | shorthand: 10.0.0.1 … 10.0.0.50 |
| `10.0.0.1 - 50`         | same, with spaces             |
| `example.com`           | hostname (passed to nmap as-is) |

### Target file format

```
# corporate ranges
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# specific ranges
10.10.5.1 - 10.10.5.100
10.10.6.1-50

# individual hosts
8.8.8.8
example.com
```

---

## Scan modes

### Default — high-accuracy (recommended)

```bash
sudo python fastcheck.py 192.168.1.0/24 -o results.jsonl
```

Uses five probe types simultaneously. A host is marked **up** if *any* probe gets a
response — so firewalled and filtered hosts are far less likely to be missed.

| Flag | Probe | Why it helps |
|------|-------|--------------|
| `-PS22,80,443` | TCP SYN to ports 22, 80, 443 | Discovers hosts that answer SSH / HTTP / HTTPS even when ICMP is blocked |
| `-PA80,443` | TCP ACK to ports 80, 443 | Bypasses stateful firewalls that silently drop SYN packets |
| `-PU161` | UDP to port 161 (SNMP) | Discovers network devices, printers, and routers that speak UDP only |
| `-PE` | ICMP echo request | Classic ping — works on most unfiltered hosts |
| `-PP` | ICMP timestamp request | Fallback for hosts that block echo but allow timestamp replies |

**Requires root / sudo** — raw TCP/UDP packets need elevated socket privileges.  
Default timeout: **10 s** per host.

### Light mode (`--light`)

```bash
python fastcheck.py 192.168.1.0/24 --light -o results.jsonl
```

Uses nmap's built-in default probes: ICMP echo + ARP (LAN only).  
No root required. Faster per host, but misses anything that blocks ICMP.  
Default timeout: **5 s** per host.

---

## High-volume scanning

fastcheck is designed to stay memory-flat for any number of targets.

### How it works

| Concern | Naive approach | fastcheck |
|---------|---------------|-----------|
| Target list | Expand all IPs into a Python list | Generator — yields one IP at a time |
| Count | `len(list(net.hosts()))` — allocates everything | Integer arithmetic on `net.num_addresses` — O(1) |
| Task queue | Submit all futures at once | Sliding window of `workers × 4` futures max |
| Output file | Write at end | Flush after every result — readable mid-scan |

A `/8` CIDR (16.7 M hosts) uses a few MB regardless. A flat list would need ~2–3 GB.

### Tuning workers for large scans

`-w` controls how many nmap processes run in parallel. Each nmap process
takes ~5–20 MB RSS, so balance against available RAM.

| Target count | Recommended `-w` | Notes |
|---|---|---|
| < 1 000 | `10` (default) | No tuning needed |
| 1 000 – 100 000 | `50–100` | Check RAM: `workers × 20 MB` |
| 100 000 – 1 M | `100–200` | Use `--light` to reduce per-host time |
| 1 M+ | `200–500` | `--light --up-only`, solid-state output path |

```bash
# 10 M targets — light mode, 200 workers, write only live hosts
python fastcheck.py 10.0.0.0/8 --light -w 200 --up-only -o live.jsonl

# Estimate wall-clock time:
#   hosts / workers × timeout  =  16_777_214 / 200 × 5s  ≈  115 hours worst-case
#   (most hosts reply or timeout quickly; real time is usually much less)
```

### Throughput tips

- **`--up-only`** skips writing down/timeout hosts — much smaller output file
- **`--timeout 2`** with `--light` reduces the per-host wait on dead IPs
- **`-w 500`** is a practical ceiling on most systems (OS open-file limits, RAM)
- Run on a machine close to the targets to reduce network latency
- For truly massive scans, split the CIDR into chunks and run in parallel across machines:

```bash
# Split a /8 into 256 /16 blocks and scan concurrently on different hosts
for i in $(seq 0 255); do
  echo "10.$i.0.0/16" >> chunk_$i.txt
done
# On each scan host:
python fastcheck.py -f chunk_N.txt --light -w 100 --up-only -o results_N.jsonl
```

---

## Live display

When run in an interactive terminal the screen is split into three fixed zones.
Only the IP list scrolls — the header and progress bar never move.  
For large scans the counter keeps updating smoothly regardless of target count.

```
──────────────────────────────────────────────────────────────────
  fastcheck  ·  nmap 7.99  ·  default (high-accuracy)
  Targets: 16777214  Workers: 200  Timeout: 10s  →  results.jsonl
──────────────────────────────────────────────────────────────────
  [  6721/16777214]  10.0.26.65    up    0.31ms    host.example.com   ▲
  [  6722/16777214]  10.0.26.70    down                                │
  [  6723/16777214]  10.0.26.71    up    1.02ms                        │  scroll
  [  6724/16777214]  10.0.26.80    up    0.88ms    nas.local           │  region
  [  6725/16777214]  10.0.26.81    down                                │
  [  6726/16777214]  10.0.26.84    up    0.54ms                        ▼
──────────────────────────────────────────────────────────────────
  Up: 312    Down: 6414    [████░░░░░░░░░░░░░░░░░░░░░░░░░░]  6726/16777214
──────────────────────────────────────────────────────────────────
```

When output is piped or redirected (non-TTY), results are printed line-by-line.

---

## Output format (JSONL)

One JSON object per line, flushed after every result.  
The file is valid and readable even if the scan is interrupted mid-way.

```jsonl
{"timestamp":"2026-05-08T10:00:01.234Z","input":"10.0.0.0/8","target":"10.0.0.1","status":"up","latency_ms":0.42,"hostname":"router.local","mac":"AA:BB:CC:DD:EE:FF","scan_mode":"default","nmap_version":"7.99"}
{"timestamp":"2026-05-08T10:00:01.891Z","input":"10.0.0.0/8","target":"10.0.0.2","status":"down","latency_ms":null,"hostname":null,"mac":null,"scan_mode":"default","nmap_version":"7.99"}
```

### Fields

| Field          | Type            | Description                                   |
|----------------|-----------------|-----------------------------------------------|
| `timestamp`    | ISO-8601 string | UTC time the scan completed                   |
| `input`        | string          | Original target spec (e.g. `10.0.0.0/8`)     |
| `target`       | string          | Resolved IP address                           |
| `status`       | string          | `up`, `down`, `timeout`, `error`, `unknown`   |
| `latency_ms`   | float / null    | Round-trip time in milliseconds               |
| `hostname`     | string / null   | Reverse-DNS hostname (PTR record)             |
| `mac`          | string / null   | MAC address (LAN only, requires root/sudo)    |
| `scan_mode`    | string          | `default` or `light`                          |
| `nmap_version` | string          | nmap version used for this scan               |

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

# Memory-efficient for large files — reads one line at a time
with open("results.jsonl") as fh:
    for line in fh:
        r = json.loads(line)
        if r["status"] == "up":
            print(r["target"], r.get("hostname") or "")
```

### jq

```bash
# Live IPs as plain text
jq -r 'select(.status == "up") | .target' results.jsonl

# Tab-separated: IP, hostname, latency
jq -r 'select(.status == "up") | [.target, (.hostname // ""), (.latency_ms | tostring)] | @tsv' results.jsonl

# Count by status
jq -s 'group_by(.status) | map({status: .[0].status, count: length})' results.jsonl

# Only results from the default (high-accuracy) scan
jq 'select(.scan_mode == "default" and .status == "up")' results.jsonl
```

### Shell

```bash
# Pipe live IPs into ip2location
jq -r 'select(.status == "up") | .target' results.jsonl \
  | xargs -I{} python ../ip2location/ip2location.py {}

# Quick count
grep -c '"status":"up"' results.jsonl
```

---

## Notes

- **Root / sudo**: the default scan uses raw TCP/UDP packets and requires root (or nmap's setuid bit) on Linux. `--light` works without root on macOS and most Linux distros.
- **Memory**: target expansion is fully lazy — a `/8` (16 M hosts) uses the same few MB of RAM as a single IP.
- **Task queue**: at most `workers × 4` nmap processes are queued at once. The rest wait in the generator, consuming no memory.
- **Results are unordered**: threads complete in parallel; `[X/N]` shows completion order, not input order. Input order is preserved in the `input` field.
- **Interrupted scans**: the output file is flushed after every result — valid JSONL even if stopped early with Ctrl-C.
- **Non-TTY mode**: when stdout is a pipe or file, the live TUI is replaced with plain line-by-line output and no cursor movement.
