# vault

Central recon intelligence database.  
Validates target IPs against a country code (local IP2Location + online ipinfo.io), scans each host with **nmap** (OS, services, open ports, vulnerabilities, CVEs), optionally cross-references findings with **searchsploit**, and stores everything in a **shared SQLite database** designed to be extended by other tools in the pipeline.

Supports **pause**, **resume from pause**, **resume after being stopped**, and **proxychains4**.

---

## Quick start

```bash
# Scan targets from a fastcheck/ipdb JSONL, enforce US country
python vault.py -f targets.jsonl --country US

# Read clean IPs directly from an ipdb database
python vault.py --from-ipdb ipdb.sqlite --country US

# 3 concurrent targets, slower nmap timing, custom port range
python vault.py -f targets.jsonl --country US -w 3 --nmap-args "-p 1-10000 -T3"

# Include searchsploit CVE lookup for found services
python vault.py -f targets.jsonl --country US --searchsploit

# Run through proxychains4 — all subprocesses (nmap, curl) are auto-proxied
proxychains4 -q python vault.py -f targets.jsonl --country US

# Resume a stopped run — re-run the same command
python vault.py -f targets.jsonl --country US
# Output: Resume: 120 already done, 380 remaining.
```

---

## Prerequisites

```bash
pip install IP2Location IP2Proxy python-dotenv requests

# Kali / Debian
apt install nmap curl

# Optional — for --searchsploit
apt install exploitdb

# Optional — for proxychains support
apt install proxychains4
```

IP2Location binary databases must be downloaded first:

```bash
python ../ipinfo/ipinfo.py --update
```

**OS detection (`-O`) requires root** — run vault.py as root or with sudo for full results. Without root, OS detection is automatically skipped.

---

## Usage

### vault.py — scanner

```
python vault.py -f JSONL [options]
python vault.py --from-ipdb SQLITE [options]

Source (one required):
  -f, --file JSONL         fastcheck / plain .jsonl input (target or ip field)
  --from-ipdb SQLITE       read clean IPs (flagged=0) from an ipdb database

Options:
  --db FILE                vault SQLite path (default: vault.sqlite next to this script)
  --country CC             Two-letter country code to enforce (e.g. US, DE, IR)
                           Both local and online sources must confirm it.
                           Mismatched IPs are stored as skipped — not scanned.
  -w, --workers N          Concurrent targets (default: 5)
  --nmap-args ARGS         Extra nmap arguments as a quoted string
                           (e.g. --nmap-args "-p- -T3")
  --timeout SEC            Per-host nmap timeout in seconds (default: 600)
  --online-delay SEC       Minimum seconds between ipinfo.io requests (default: 1.5)
  --searchsploit           Cross-reference found services with searchsploit
  --all                    Process all hosts in JSONL, not only status='up' ones
  --proxychains            Force proxychains4 mode (auto-detected when launched
                           via proxychains4; switches nmap to -sT, drops -O)
```

### vreport.py — reporter

```
python vreport.py --by GROUP [options]
python vreport.py --ip IP

Groups:
  --by os                  Hosts grouped by operating system
  --by port                Open ports ranked by host count
  --by service             Services / products ranked by host count
  --by severity            Vulnerability counts by severity level
  --by cve                 All CVEs with affected hosts
  --by host                Per-host summary (OS, ports, top vulns)

  --ip IP                  Full details for one IP (ports, vulns, scan log)

Options:
  --db FILE                vault SQLite path (default: vault.sqlite)
  --min-severity SEV       Filter to this severity and above: critical|high|medium|low|info
  --port PORT              Filter to a specific port number (for --by port)
  --country CC             Filter hosts by country code (for --by host/os)
```

---

## Workflow

```bash
# Step 1 — discover live hosts
python ../fastcheck/fastcheck.py 10.0.0.0/8 --light -w 200 --up-only -o live.jsonl

# Step 2 — geo-verify and build IP intelligence
python ../ipdb/ipdb.py -f live.jsonl --country US --db ipdb.sqlite

# Step 3 — deep scan and build central intelligence db
python vault.py --from-ipdb ipdb.sqlite --country US --db vault.sqlite

# Step 4 — query findings
python vreport.py --by cve --min-severity high
python vreport.py --by port
python vreport.py --by os
python vreport.py --ip 192.168.1.5
```

---

## Country validation

When `--country CC` is provided, each IP is checked against both sources before scanning:

| Local result | Online result | Action |
|---|---|---|
| CC | CC | proceed to scan |
| CC | different | skip (COUNTRY_MISMATCH) |
| different | CC | skip (COUNTRY_MISMATCH) |
| error / unavailable | anything | skip (VERIFICATION_INCOMPLETE) |
| anything | rate_limited | auto-pause + skip |

Skipped IPs are stored in the database with `scan_status='skipped'` and `flagged=1`.

---

## Pause and resume

### Manual pause

Press **Ctrl+C**. Workers finish their current target, then wait.  
The footer shows `⏸ PAUSED  ↵ resume  ·  Ctrl+C quit`.

Press **Enter** to resume. Press **Ctrl+C** again to quit.

### Auto-pause on rate limit

When ipinfo.io returns a 429, the tool pauses itself automatically. Press **Enter** to resume after the quota window resets.

### Resume after stopping

Re-run the **exact same command**. Hosts with `scan_status='done'` are skipped:

```bash
python vault.py -f targets.jsonl --country US
# Resume: 120 already done, 380 remaining.
```

---

## Live display

A fixed worker-status panel shows what every concurrent slot is doing in real time. Elapsed time on the `nmap` and `sploit` stages updates every second.

```
──────────────────────────────────────────────────────────────────
  vault  ·  recon intelligence database  filter: US  [proxychains]
  Targets: 500  Workers: 5  →  vault.sqlite
──────────────────────────────────────────────────────────────────
  ●  104.21.18.7       [ nmap    ]  02:14
  ●  198.41.0.1        [ verify  ]
  ●  10.0.0.5          [ nmap    ]  00:33
  ●  172.16.0.3        [ sploit  ]  04:01
  ○  —                 [ idle    ]
──────────────────────────────────────────────────────────────────
  [  1/500]  104.21.18.9    SKIP  L:US  O:DE  COUNTRY_MISMATCH    ▲
  [  2/500]  10.0.0.1       SCAN  8 port(s)  3 vuln(s)  [Linux]   ▼
──────────────────────────────────────────────────────────────────
  Scanned: 2    Skipped: 1    Errors: 0    [█░░░░░░░░░░░]  3/500
──────────────────────────────────────────────────────────────────
```

Worker stages: `verify` → `nmap` → `sploit` (if `--searchsploit`) → `store` → `idle`.  
`[proxychains]` appears in the header when proxychains4 mode is active.

---

## SQLite schema

The vault database is the **central shared store** for the entire rednote pipeline. Other tools add their own tables without breaking existing ones.

```sql
-- Core host record
hosts (
    ip              PRIMARY KEY
    hostname
    mac
    status          -- nmap host status: 'up' | 'down' | 'unknown'
    os              -- e.g. 'Linux 4.15'
    os_version      -- e.g. 'Linux 4.X'
    os_accuracy     -- 0-100
    country_code    -- detected country
    country_filter  -- --country value used when this record was written
    flagged         -- 1 = skipped (country mismatch)
    flag_reason     -- COUNTRY_MISMATCH | VERIFICATION_INCOMPLETE | NULL
    first_seen      -- UTC ISO-8601; never updated on re-scan
    last_scanned    -- UTC ISO-8601
    scan_status     -- 'pending' | 'scanning' | 'skipped' | 'done' | 'error'
    scan_error      -- nmap error message, if any
)

-- Open ports and services
ports (
    id          AUTOINCREMENT
    ip
    port
    protocol    -- 'tcp' | 'udp'
    state       -- 'open' | 'closed' | 'filtered'
    service     -- e.g. 'http'
    product     -- e.g. 'Apache httpd'
    version     -- e.g. '2.4.41'
    extra_info
    banner
    scanned_at
    UNIQUE(ip, port, protocol)
)

-- Vulnerabilities and CVEs
vulns (
    id
    ip
    port
    protocol
    cve         -- e.g. 'CVE-2021-44228'
    cvss        -- CVSS score (float)
    severity    -- 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'
    title
    description
    solution
    refs        -- JSON array of URLs
    tool        -- e.g. 'nmap:vulners' | 'searchsploit'
    scanned_at
)

-- Scan history
scan_log (
    id
    ip
    tool        -- 'nmap'
    command     -- exact command run
    exit_code
    started_at
    finished_at
    notes
)

-- Extension point for other tools
meta (
    key   PRIMARY KEY
    value
)
```

Future tools add their own tables (e.g. `dirs`, `web_findings`, `screenshots`) and can query the existing `hosts`, `ports`, `vulns` tables without conflict.

---

## Querying the database

### sqlite3

```bash
sqlite3 vault.sqlite

-- All IPs with open port 80
SELECT DISTINCT ip FROM ports WHERE port = 80 AND state = 'open';

-- Critical / high CVEs and affected hosts
SELECT cve, severity, ip FROM vulns
  WHERE severity IN ('critical', 'high')
  ORDER BY severity, cve;

-- All open ports on a specific host
SELECT port, protocol, service, product, version
  FROM ports WHERE ip = '1.2.3.4' AND state = 'open';

-- OS distribution
SELECT os, COUNT(*) AS n FROM hosts
  WHERE scan_status = 'done'
  GROUP BY os ORDER BY n DESC;

-- Hosts running Apache
SELECT DISTINCT ip, version FROM ports
  WHERE product LIKE 'Apache%' AND state = 'open';

-- Services with known CVEs
SELECT DISTINCT p.ip, p.product, p.version, v.cve, v.severity
  FROM ports p JOIN vulns v ON p.ip = v.ip AND p.port = v.port
  WHERE v.cve IS NOT NULL
  ORDER BY v.severity;
```

---

## proxychains4

vault auto-detects proxychains by inspecting `LD_PRELOAD` / `PROXYCHAINS_CONF_FILE` at startup — no flag needed when launched as `proxychains4 -q python vault.py`. Use `--proxychains` to force it on manually.

When proxychains mode is active:

| What changes | Why |
|---|---|
| `proxychains4 -q` prepended to every `nmap`, `curl`, `searchsploit` call | nmap is often setuid root; setuid binaries ignore `LD_PRELOAD` inheritance, so explicit prefixing is required |
| nmap switches to `-sT` (TCP connect scan) | Default `-sS` (SYN scan) uses raw sockets that proxychains cannot intercept |
| nmap drops `-O` (OS detection) | OS detection also relies on raw sockets |
| `[proxychains]` shown in the live display header | Confirms the mode is active |

```bash
# Auto-detected — no extra flag needed
proxychains4 -q python vault.py -f targets.jsonl --country US

# Force manually (e.g. when wrapping with a custom proxy script)
python vault.py -f targets.jsonl --country US --proxychains
```

---

## Notes

- **Workers = concurrent nmap processes**: each worker runs a full `nmap -sV [-O] --script=vuln` against one host. 5 concurrent nmap processes is the default; reduce with `-w` on underpowered hardware.
- **OS detection needs root**: the `-O` flag is automatically included when running as root/sudo, skipped otherwise, and always skipped in proxychains mode (raw sockets bypass the proxy).
- **nmap vuln scripts**: the `vuln` script category includes ssl-heartbleed, ms17-010 (EternalBlue), smb-vuln-*, http-shellshock, and many more. Install the `vulners` NSE script for CVE-mapped results: `nmap --script-updatedb`.
- **searchsploit**: optional enrichment that cross-references detected service/version strings with the Exploit-DB. Slow for many services; use on targeted scans.
- **Resume**: any host with `scan_status='done'` is skipped on re-run. Hosts interrupted mid-scan (status was `'scanning'`) are reset to `'pending'` and retried.
- **Extensible schema**: `vulns`, `ports`, and `hosts` tables are stable — other tools write their findings to their own tables in the same SQLite file and join against `hosts.ip` as needed.
- **WAL mode**: safe for concurrent reads by reporting tools while a scan is in progress.
