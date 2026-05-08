# fastcheck

Rapid host-discovery scanner using `nmap -sn` (ping scan).  
Checks each target individually so CIDR blocks and ranges are handled IP by IP.  
Results stream live to the terminal and are written to a structured `.jsonl` file.

## Quick start

```bash
# Single host
python fastcheck.py 8.8.8.8

# CIDR block (each IP checked individually)
python fastcheck.py 192.168.1.0/24 -o results.jsonl

# IP range shorthand
python fastcheck.py 10.0.0.1-50 -o results.jsonl

# File of targets
python fastcheck.py -f targets.txt -o results.jsonl

# Only write live hosts to the output file
python fastcheck.py -f targets.txt -o up_hosts.jsonl --up-only
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
  --timeout SEC       Per-host nmap timeout in seconds (default: 5)
  --up-only           Only write 'up' hosts to the output file
```

### Target formats

| Input              | Expands to                     |
|--------------------|-------------------------------|
| `8.8.8.8`          | single IP                     |
| `10.0.0.0/24`      | 10.0.0.1 … 10.0.0.254 (254)  |
| `10.0.0.1-10.0.0.5`| 10.0.0.1 … 10.0.0.5  (5)    |
| `10.0.0.1-5`       | 10.0.0.1 … 10.0.0.5  (5)    |
| `example.com`      | hostname (as-is)              |

### Target file format

```
# my network
192.168.1.0/24
10.0.0.1-20
8.8.8.8
example.com
```

---

## Live output

Results are printed immediately as each scan completes (not in input order):

```
──────────────────────────────────────────────────────────────
  fastcheck  ·  nmap 7.94
  Targets  : 254
  Workers  : 10
  Timeout  : 5s / host
  Output   : results.jsonl
──────────────────────────────────────────────────────────────

[  1/254]  192.168.1.1          up    0.42ms    router.local
[  2/254]  192.168.1.5          down
[  3/254]  192.168.1.10         up    1.10ms    myhost.local
...

──────────────────────────────────────────────────────────────
  Summary
  Up     : 12
  Down   : 242
  Output : results.jsonl  (18,432 bytes, 254 records)
──────────────────────────────────────────────────────────────
```

---

## Output format (JSONL)

One JSON object per line, written as each result arrives.  
File is valid even if the scan is interrupted mid-way.

```jsonl
{"timestamp":"2026-05-08T10:00:01.234Z","input":"192.168.1.0/24","target":"192.168.1.1","status":"up","latency_ms":0.42,"hostname":"router.local","mac":"AA:BB:CC:DD:EE:FF","nmap_version":"7.94"}
{"timestamp":"2026-05-08T10:00:01.891Z","input":"192.168.1.0/24","target":"192.168.1.2","status":"down","latency_ms":null,"hostname":null,"mac":null,"nmap_version":"7.94"}
```

### Fields

| Field          | Type            | Description                                      |
|----------------|-----------------|--------------------------------------------------|
| `timestamp`    | ISO-8601 string | UTC time the scan completed                      |
| `input`        | string          | Original target spec (e.g. `10.0.0.0/24`)       |
| `target`       | string          | Resolved IP address                              |
| `status`       | string          | `up`, `down`, `timeout`, `error`, `unknown`      |
| `latency_ms`   | float / null    | Round-trip time in milliseconds                  |
| `hostname`     | string / null   | Reverse-DNS hostname (PTR record)                |
| `mac`          | string / null   | MAC address (LAN only, requires root/sudo)       |
| `nmap_version` | string          | nmap version used for this scan                  |

---

## Reading the output in other tools

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

# Live hosts with hostname
jq -r 'select(.status == "up") | [.target, .hostname, .latency_ms] | @tsv' results.jsonl

# Count by status
jq -s 'group_by(.status) | map({status: .[0].status, count: length})' results.jsonl

# Hosts with MAC addresses (LAN, requires root)
jq 'select(.mac != null)' results.jsonl
```

### Shell

```bash
# Pass live IPs directly to another scanner
jq -r 'select(.status == "up") | .target' results.jsonl | xargs -I{} python ../ip2location/ip2location.py {}

# Quick grep
grep '"status":"up"' results.jsonl | wc -l
```

---

## Notes

- **Root / sudo**: ARP-based discovery and MAC resolution require root on Linux. ICMP echo works without root on macOS and most Linux distros with nmap's setuid bit.
- **Results are unordered**: threads complete in parallel; the `[X/N]` counter shows completion order, not input order. Input order is preserved in the `input` field.
- **Interrupted scans**: the output file is written incrementally and is readable even if the scan is stopped early.
