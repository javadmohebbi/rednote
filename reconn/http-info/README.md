# http-info

Web service reconnaissance using Kali Linux pre-installed tools.  
Fingerprints technologies, detects WAFs, finds CVEs, and suggests Metasploit modules.  
Handles single hosts, target files, and scantop100 / fastcheck JSONL output.  
Designed for large-scale engagements (thousands of targets) with pause, resume, and live display.

---

## Quick start

```bash
# Single host — scans ports 80 and 443 by default
python http-info.py 192.168.1.1

# Specific port(s)
python http-info.py 192.168.1.1:8080
python http-info.py 192.168.1.1:80,443,8443

# Feed scantop100 results (HTTP ports extracted automatically)
python http-info.py -f scantop100_results.jsonl -o results/

# Feed fastcheck results (up hosts → scan ports 80 and 443)
python http-info.py -f fastcheck_results.jsonl -o results/

# Plain target file
python http-info.py -f targets.txt -o results/ -w 10

# Enable nikto for deeper vuln scanning (slow — use with low worker count)
python http-info.py -f targets.txt --nikto -w 3 -o results/

# Quick fingerprint only (curl + whatweb, ~10s per host)
python http-info.py -f targets.txt --fast -w 20 -o results/
```

---

## Prerequisites

```bash
# Required
apt install curl nmap

# Optional — pre-installed on Kali
apt install whatweb wafw00f nikto sslscan gobuster

# Highly recommended — install separately
apt install nuclei
# or: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

No Python packages required — stdlib only.

---

## Usage

```
python http-info.py [options] [TARGET]

Target:
  TARGET              host, host:port, or host:port1,port2,port3
  -f, --file FILE     Plain text file, scantop100 .jsonl, or fastcheck .jsonl

Output:
  -o, --output DIR    Output directory (default: http-info-results/)

Scan:
  -w, --workers N     Parallel scans (default: 5)
  -p, --ports PORTS   Default ports for hosts with no port spec (default: 80,443)
  --timeout SEC       Per-tool timeout in seconds (default: 60)
  --nikto             Enable nikto vulnerability scanner (opt-in — slow)
  --gobuster          Enable gobuster directory enumeration (opt-in — slow)
  --no-nmap           Skip nmap HTTP/SSL NSE scripts
  --fast              curl + whatweb only (~10s per host; use for large batches)
```

### Target formats

| Input | Scans |
|---|---|
| `192.168.1.1` | ports 80 and 443 |
| `192.168.1.1:8080` | port 8080 |
| `192.168.1.1:80,443,8443` | three ports |
| `http://192.168.1.1` | port 80, HTTP |
| `https://192.168.1.1` | port 443, HTTPS |
| `https://192.168.1.1:8443` | port 8443, HTTPS |
| `example.com:443` | hostname, port 443 |

### Target file format

```
# web servers
192.168.1.1
192.168.1.5:8080
https://192.168.1.10:8443
example.com
```

### Auto-detection of JSONL input

| Source file | How ports are selected |
|---|---|
| **scantop100** `.jsonl` | Extracts all ports with HTTP-related service names or common HTTP port numbers |
| **fastcheck** `.jsonl` | Extracts `"status": "up"` hosts; scans the default ports (`-p`) |

---

## Workflow: fastcheck → scantop100 → http-info

```bash
# Step 1 — discover live hosts
python ../fastcheck/fastcheck.py 10.0.0.0/24 --light -o live.jsonl

# Step 2 — find open ports
python ../scantop100/scantop100.py -f live.jsonl -o ports.jsonl --open-only

# Step 3 — web recon on HTTP services
python http-info.py -f ports.jsonl -o web-recon/ -w 10
```

---

## Pause and resume

### Pause during a scan

Press **Ctrl+C**. The footer immediately shows:

```
Done: 42/400  CVEs: 7  MSF: 3  ⏸ PAUSED  ↵ resume  ·  Ctrl+C quit
```

Workers finish their current host before stopping. Press **Enter** to resume.  
Press **Ctrl+C** again to quit.

### Resume after stopping

Re-run the **exact same command**. The output directory is scanned for completed JSON files, and those host:port pairs are skipped:

```bash
# First run — stopped at 150/400
python http-info.py -f targets.txt -o results/

# Re-run — continues from 151/400
python http-info.py -f targets.txt -o results/
# Resume: 150 already scanned, 250 remaining.
```

---

## Tools used and what each does

| Tool | Purpose | Default? |
|---|---|---|
| **curl** | HTTP headers, status code, title, redirect chain | always |
| **nmap** (http-* scripts) | Methods, robots.txt, PHP/ASP version, auth, CORS, cookie flags, directory enum, shellshock | yes |
| **nmap** (vulners script) | CVE lookup against detected service versions | yes |
| **nmap** (ssl-* scripts) | Heartbleed, POODLE, DH params, cipher suites, cert info | yes (HTTPS only) |
| **whatweb** | CMS, framework, server technology fingerprinting | yes |
| **wafw00f** | WAF / CDN detection | yes |
| **sslscan** | TLS protocol versions, weak ciphers, certificate validity | yes (HTTPS only) |
| **nikto** | Web vulnerability scanner (200+ checks) | `--nikto` |
| **gobuster** | Directory/file brute-force enumeration | `--gobuster` |

### Suggested additional tool

**nuclei** (`apt install nuclei`) — template-based scanner with thousands of CVE/misconfiguration checks. After this scan, run:

```bash
# Feed all scanned URLs into nuclei
jq -r '.url' results/_summary.jsonl | nuclei -l - -o nuclei_findings.txt
```

---

## Live display

Fixed header, scrolling results, fixed footer — the screen never scrolls.

```
──────────────────────────────────────────────────────────────────
  http-info  ·  nmap 7.99
  Targets: 400  Workers: 10  Output: results/
──────────────────────────────────────────────────────────────────
  [ 40/400]  10.0.0.40:80    ok    Apache/2.4.57  WordPress                ▲
  [ 41/400]  10.0.0.41:443   ok    nginx/1.24.0   3 CVEs  →2 MSF           │
  [ 42/400]  10.0.0.42:8080  ok    Tomcat/9.0.65                            │ scroll
  [ 43/400]  10.0.0.43:80    tout                                            │ region
  [ 44/400]  10.0.0.44:443   ok    IIS/10.0       1 CVE   →1 MSF            ▼
──────────────────────────────────────────────────────────────────
  Done: 44/400  CVEs: 12  MSF: 8  [████░░░░░░░░░░░░░░░░░░░░]  Ctrl+C pause
──────────────────────────────────────────────────────────────────
```

---

## Output format

### Per-host JSON file

One file per host:port in the output directory: `{host}_{port}.json`

```json
{
  "timestamp": "2026-05-08T10:01:15Z",
  "target": "10.0.0.1",
  "port": 443,
  "url": "https://10.0.0.1:443",
  "ssl": true,
  "status": "ok",
  "http_status": 200,
  "redirect": null,
  "title": "Company Portal",
  "server": "Apache/2.4.57 (Debian)",
  "headers": {
    "content-type": "text/html",
    "x-powered-by": "PHP/8.1.0",
    "x-frame-options": "SAMEORIGIN"
  },
  "technologies": [
    {"name": "Apache",    "version": "2.4.57"},
    {"name": "PHP",       "version": "8.1.0"},
    {"name": "WordPress", "version": "6.4.0"}
  ],
  "waf": {"detected": false, "name": null},
  "ssl_info": {
    "protocols": {"TLS 1.2": true, "TLS 1.3": true, "SSL 3": false},
    "issues": [],
    "certificate": {
      "subject": "CN=10.0.0.1",
      "issuer":  "CN=Let's Encrypt",
      "expires": "2026-08-01"
    }
  },
  "cves": [
    {"id": "CVE-2021-41773", "score": 9.8, "source": "nmap/vulners"},
    {"id": "CVE-2021-42013", "score": 9.8, "source": "nmap/vulners"}
  ],
  "msf_modules": [
    {
      "module":      "exploit/multi/http/apache_normalize_path_rce",
      "description": "Apache 2.4.49/50 Path Traversal RCE",
      "reason":      "CVE-2021-41773 / CVE-2021-42013"
    },
    {
      "module":      "exploit/unix/webapp/wp_admin_shell_upload",
      "description": "WordPress Admin Shell Upload",
      "reason":      "authenticated RCE"
    }
  ],
  "interesting": ["/wp-login.php", "/admin/", "/robots.txt", "/.git/"],
  "scan_duration_s": 48.3,
  "tools_used": ["curl", "whatweb", "wafw00f", "sslscan", "nmap"]
}
```

### Summary JSONL (`_summary.jsonl`)

One compact line per completed scan — used for quick analysis across all hosts:

```jsonl
{"timestamp":"...","target":"10.0.0.1","port":443,"url":"https://10.0.0.1:443","status":"ok","http_status":200,"title":"Company Portal","server":"Apache/2.4.57","technologies":["Apache","PHP","WordPress"],"cve_count":2,"msf_count":2,"waf":null}
```

### Output fields

| Field | Description |
|---|---|
| `target` | IP or hostname |
| `port` | Scanned port |
| `url` | Full URL including scheme |
| `ssl` | true if HTTPS |
| `status` | `ok`, `timeout`, `connection refused`, `error` |
| `http_status` | HTTP response code |
| `title` | Page `<title>` |
| `server` | Server header value |
| `technologies[]` | Detected name + version |
| `waf.detected` | true if WAF/CDN found |
| `waf.name` | WAF product name |
| `ssl_info` | TLS protocols, weak ciphers, certificate |
| `cves[]` | CVE ID, CVSS score, source tool |
| `msf_modules[]` | Metasploit module path + reason |
| `interesting[]` | Notable paths found |
| `tools_used[]` | Which tools ran successfully |

---

## Reading results for the attack phase

### Quick queries

```bash
# Hosts with CVEs — sorted by CVE count
jq -s 'sort_by(-.cve_count) | .[] | select(.cve_count > 0) | [.target, .port, .cve_count, .technologies[0:2]] | @json' \
  results/_summary.jsonl

# All MSF modules suggested across the scan
jq -r '.msf_modules[].module' results/*.json | sort -u

# Hosts running WordPress
jq -r 'select(.technologies[] | contains("WordPress")) | .url' results/_summary.jsonl

# URLs with Metasploit suggestions
jq -r 'select(.msf_count > 0) | .url' results/_summary.jsonl

# Hosts with weak SSL (TLS 1.0/SSL 3.0 enabled)
jq 'select(.ssl_info.issues | length > 0)' results/*.json

# All interesting paths found
jq -r '.url as $u | .interesting[] | "\($u)\(.)"' results/*.json | sort -u
```

### Python

```python
import json
from pathlib import Path

for f in Path("results").glob("*.json"):
    if f.name.startswith("_"):
        continue
    r = json.loads(f.read_text())
    if r["cves"]:
        print(r["url"], [c["id"] for c in r["cves"]])
```

### Attack pipeline example

```bash
# Run http-info
python http-info.py -f ports.jsonl -o results/ -w 10

# Feed WordPress targets to wpscan
jq -r 'select(.technologies[] | contains("WordPress")) | .url' results/_summary.jsonl \
  | while read url; do wpscan --url "$url" --enumerate vp,u; done

# Feed CVE-2021-41773 targets to Metasploit
jq -r 'select(.cves[] | .id == "CVE-2021-41773") | .target' results/_summary.jsonl \
  | while read ip; do
      msfconsole -q -x "use exploit/multi/http/apache_normalize_path_rce; set RHOSTS $ip; run; exit"
    done

# Feed all URLs into nuclei for template-based scanning
jq -r '.url' results/_summary.jsonl | nuclei -l - -severity critical,high -o nuclei.txt
```

---

## Speed vs. thoroughness

| Mode | Tools | ~Time / host | Use for |
|---|---|---|---|
| `--fast` | curl + whatweb | 10 s | Initial recon of 10k+ targets |
| Default | + nmap + wafw00f + sslscan | 60 s | Standard engagement |
| `--gobuster` | + directory enum | 3-10 min | Targeted hosts after initial recon |
| `--nikto` | + nikto | 5-30 min | Deep dive on selected targets |
| `--nikto --gobuster` | all tools | 10-60 min | Full audit of a single host |

```bash
# Typical two-pass workflow
# Pass 1: quick fingerprint everything
python http-info.py -f ports.jsonl --fast -w 50 -o recon-fast/

# Pass 2: full scan on interesting targets (WordPress, Apache, IIS)
jq -r 'select(.technologies | length > 0) | "\(.target):\(.port)"' recon-fast/_summary.jsonl \
  > interesting.txt
python http-info.py -f interesting.txt --nikto -w 5 -o recon-deep/
```

---

## Notes

- **Workers**: each worker runs multiple subprocess tools sequentially. 5 workers × 60s/host = 12 worker-hours for 1000 hosts. Reduce workers if the target network rate-limits.
- **nikto** is disabled by default — it can take 30+ minutes per host and generates significant traffic.
- **gobuster** uses `/usr/share/wordlists/dirb/common.txt` if available.
- **SSL auto-detection**: ports 443, 8443, 3443, 4443, 5443, 7443, 9443 default to HTTPS. All others default to HTTP unless the service hint says `https` or `ssl`.
- **Resume**: the output directory is the state store. Deleting a host's JSON file forces it to be re-scanned.
- **_summary.jsonl**: appended to (never overwritten) so it accumulates across multiple partial runs.
