#!/usr/bin/env python3
"""
http-info.py  —  web service reconnaissance
============================================
Fingerprints and probes HTTP/HTTPS services using Kali Linux tools.
Accepts a single host:port, a target file, or a scantop100 / fastcheck .jsonl.

  python http-info.py 192.168.1.1
  python http-info.py 192.168.1.1:8080
  python http-info.py 192.168.1.1:80,443,8443
  python http-info.py -f scantop100_results.jsonl -o results/
  python http-info.py -f targets.txt -o results/ -w 10

Pause / resume
  Ctrl+C      pause (workers finish their current host, then wait)
  Enter       resume
  Ctrl+C      quit while paused

Resume after stopping
  Re-run the same command — already-scanned host:port combinations are
  detected from the output folder and skipped automatically.

Output
  One JSON file per host:port in the output directory.
  A running _summary.jsonl is also written for quick post-scan analysis.

Tools used (Kali pre-installed unless noted)
  curl          HTTP headers, title, status (required)
  nmap          HTTP/SSL NSE scripts, vulners CVE lookup (required)
  whatweb       Technology fingerprinting
  wafw00f       WAF / CDN detection
  nikto         Vulnerability scanner          (opt-in: --nikto)
  sslscan       SSL/TLS configuration audit
  gobuster      Directory/file enumeration     (opt-in: --gobuster)

Suggest installing
  nuclei        Template-based vulnerability scanner (highly recommended)
    → apt install nuclei   or   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""

import sys
import os
import re
import json
import time
import signal
import shutil
import argparse
import ipaddress
import itertools
import subprocess
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from pathlib import Path
from xml.etree import ElementTree as ET


# ── ANSI codes ────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
MAGENTA= "\033[35m"


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Pause / quit control
# ══════════════════════════════════════════════════════════════════════════════

_pause_event = threading.Event()
_quit_event  = threading.Event()


def _sigint_handler(sig, frame):
    if _pause_event.is_set():
        _quit_event.set()
        _pause_event.clear()
    else:
        _pause_event.set()


def wait_if_paused(display) -> bool:
    """Block caller until resumed or quit. Returns False if quit requested."""
    if not _pause_event.is_set():
        return True
    display.set_paused(True)
    resume_signal = threading.Event()

    def _read_enter():
        try:
            sys.stdin.readline()
        except Exception:
            pass
        resume_signal.set()

    threading.Thread(target=_read_enter, daemon=True).start()
    while _pause_event.is_set() and not _quit_event.is_set():
        if resume_signal.is_set():
            _pause_event.clear()
            break
        time.sleep(0.1)
    display.set_paused(False)
    return not _quit_event.is_set()


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Tool availability
# ══════════════════════════════════════════════════════════════════════════════

# tool → (apt package, pip package or None, is_required)
TOOL_INFO = {
    "curl":     ("curl",     None,                  True),
    "nmap":     ("nmap",     None,                  True),
    "whatweb":  ("whatweb",  None,                  False),
    "wafw00f":  ("wafw00f",  "pip install wafw00f", False),
    "nikto":    ("nikto",    None,                  False),
    "sslscan":  ("sslscan",  None,                  False),
    "gobuster": ("gobuster", None,                  False),
    "nuclei":   ("nuclei",   None,                  False),   # suggest install
}

SUGGEST_INSTALL = ["nuclei"]   # not in default Kali but highly recommended


def check_tools() -> dict:
    """Return {tool: bool} availability map; warn about missing tools."""
    avail = {}
    missing_req = []
    missing_opt = []
    missing_suggest = []

    for tool, (pkg, pip_pkg, required) in TOOL_INFO.items():
        found = shutil.which(tool) is not None
        avail[tool] = found
        if not found:
            if required:
                missing_req.append(tool)
            elif tool in SUGGEST_INSTALL:
                missing_suggest.append((tool, pkg, pip_pkg))
            else:
                missing_opt.append((tool, pkg))

    if missing_req:
        tools_s = ", ".join(missing_req)
        sys.exit(f"[ERROR] Required tools not found: {tools_s}\n"
                 f"        Install:  apt install {' '.join(missing_req)}")

    if missing_opt:
        for tool, pkg in missing_opt:
            print(f"{YELLOW}[WARN]{RESET} {tool} not found — install with: apt install {pkg}",
                  file=sys.stderr)

    if missing_suggest:
        for tool, pkg, pip_pkg in missing_suggest:
            install = pip_pkg or f"apt install {pkg}"
            print(f"{CYAN}[TIP]{RESET}  {tool} is not installed but highly recommended: {install}",
                  file=sys.stderr)

    return avail


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Metasploit module hints database
# ══════════════════════════════════════════════════════════════════════════════
#
# Each entry: regex matched against the combined technology / vulnerability
# string, the MSF module path, a short description, and the matching reason.

MSF_DB = [
    # Apache
    (r"Apache/2\.4\.4[89]",     "exploit/multi/http/apache_normalize_path_rce",
     "Apache 2.4.49/50 Path Traversal RCE",   "CVE-2021-41773 / CVE-2021-42013"),
    (r"Apache/2\.[0-3]\.",      "exploit/multi/http/apache_mod_cgi_bash_env_exec",
     "Apache mod_cgi Shellshock RCE",          "CVE-2014-6271"),
    (r"Apache Tomcat",          "exploit/multi/http/tomcat_mgr_upload",
     "Tomcat Manager Authenticated Upload RCE","CVE-2009-3548"),
    (r"Apache Tomcat/[1-8]\.",  "exploit/multi/http/tomcat_jsp_upload_bypass",
     "Tomcat JSP Upload Bypass",               "CVE-2017-12617"),

    # PHP
    (r"PHP/5\.[0-3]\.",         "exploit/multi/http/php_cgi_arg_injection",
     "PHP CGI Argument Injection RCE",         "CVE-2012-1823"),

    # WordPress
    (r"(?i)WordPress",          "auxiliary/scanner/http/wordpress_xmlrpc_login",
     "WordPress XML-RPC Brute Force",          "credential attack"),
    (r"(?i)WordPress",          "exploit/unix/webapp/wp_admin_shell_upload",
     "WordPress Admin Shell Upload",           "authenticated RCE"),
    (r"(?i)WordPress",          "auxiliary/scanner/http/wordpress_scanner",
     "WordPress Version / Plugin Scanner",     "enumeration"),

    # Joomla
    (r"(?i)Joomla",             "exploit/unix/webapp/joomla_comfields_sqli_rce",
     "Joomla com_fields SQL Injection RCE",    "CVE-2017-8917"),

    # Drupal
    (r"(?i)Drupal [78]\.",      "exploit/unix/webapp/drupal_drupalgeddon2",
     "Drupalgeddon 2 RCE",                     "CVE-2018-7600"),
    (r"(?i)Drupal",             "exploit/unix/webapp/drupal_restws_exec",
     "Drupal RESTful Web Services RCE",        "CVE-2019-6340"),

    # Jenkins
    (r"(?i)Jenkins",            "exploit/multi/http/jenkins_script_console",
     "Jenkins Script Console Groovy RCE",      "authenticated RCE"),
    (r"(?i)Jenkins",            "exploit/multi/http/jenkins_xstream_deserialize",
     "Jenkins XStream Deserialization RCE",    "CVE-2016-0792"),

    # Struts
    (r"(?i)Struts2?",           "exploit/multi/http/struts2_content_type_ognl",
     "Apache Struts2 Content-Type OGNL RCE",   "CVE-2017-5638"),
    (r"(?i)Struts2?",           "exploit/multi/http/struts_code_exec_classloader",
     "Struts2 ClassLoader Manipulation",       "CVE-2014-0094"),

    # Spring
    (r"(?i)Spring Framework|spring-core",
     "exploit/multi/http/spring4shell_exec",
     "Spring4Shell RCE",                       "CVE-2022-22965"),
    (r"(?i)Spring Boot",        "exploit/multi/http/spring_actuator_rce",
     "Spring Boot Actuator RCE",               "CVE-2022-22963"),

    # WebLogic
    (r"(?i)WebLogic",           "exploit/multi/http/oracle_weblogic_wls_wsat",
     "Oracle WebLogic WLS WSAT Deserialization","CVE-2017-10271"),
    (r"(?i)WebLogic",           "exploit/multi/http/weblogic_deserialize_asyncresponseservice",
     "Oracle WebLogic AsyncResponseService RCE","CVE-2019-2725"),

    # IIS
    (r"IIS/[1-6]\.",            "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
     "IIS WebDAV ScStoragePathFromUrl Overflow","CVE-2017-7269"),
    (r"IIS/7\.",                "exploit/windows/iis/iis_webdav_upload_asp",
     "IIS WebDAV Upload ASP",                  "WebDAV enabled"),

    # phpMyAdmin
    (r"(?i)phpMyAdmin",         "exploit/multi/http/phpmyadmin_3522_backdoor",
     "phpMyAdmin Backdoor",                    "CVE-2012-5371"),
    (r"(?i)phpMyAdmin",         "exploit/multi/http/phpmyadmin_lfi_rce",
     "phpMyAdmin LFI RCE",                     "CVE-2018-12613"),

    # ManageEngine
    (r"(?i)ManageEngine",       "exploit/multi/http/manageengine_desktop_central_rce",
     "ManageEngine Desktop Central RCE",       "CVE-2020-10189"),

    # GitLab
    (r"(?i)GitLab",             "exploit/multi/http/gitlab_file_read_rce",
     "GitLab File Read RCE",                   "CVE-2021-22005"),

    # Log4Shell / Log4j
    (r"(?i)log4j|log4shell",    "exploit/multi/misc/log4shell_header_injection",
     "Log4Shell JNDI Injection RCE",           "CVE-2021-44228"),

    # Shellshock (detected by nikto / nmap)
    (r"(?i)shellshock|bash_env",
     "exploit/multi/http/apache_mod_cgi_bash_env_exec",
     "Shellshock Bash Env RCE",                "CVE-2014-6271"),
]


def suggest_msf(tech_string: str, cves: list) -> list:
    """Match technology / CVE strings against the MSF database."""
    combined = tech_string + " " + " ".join(c.get("id", "") for c in cves)
    seen     = set()
    hints    = []
    for pattern, module, desc, reason in MSF_DB:
        if re.search(pattern, combined, re.IGNORECASE) and module not in seen:
            seen.add(module)
            hints.append({"module": module, "description": desc, "reason": reason})
    return hints


# ══════════════════════════════════════════════════════════════════════════════
# 4 — HTTP port / SSL heuristics
# ══════════════════════════════════════════════════════════════════════════════

# Services names that indicate HTTP
HTTP_SERVICES  = {"http", "https", "http-alt", "http-proxy", "ssl/http",
                  "http?", "https?", "www", "web", "webcache"}

# Ports that are almost always HTTPS
HTTPS_PORTS    = {443, 8443, 3443, 4443, 5443, 7443, 9443, 10443}

# Default HTTP ports scanned when no port is specified
DEFAULT_PORTS  = [80, 443]


def port_is_ssl(port: int, service: str = "") -> bool:
    svc = service.lower()
    return "https" in svc or "ssl" in svc or port in HTTPS_PORTS


def service_is_http(port_obj: dict) -> bool:
    """Return True for a scantop100 port object that looks HTTP-ish."""
    svc = port_obj.get("service", "").lower()
    p   = port_obj.get("port", 0)
    return svc in HTTP_SERVICES or "http" in svc or p in {
        80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 3443, 4000,
        4443, 5000, 5443, 7080, 7443, 9000, 9443, 9080, 10080
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Target loading
# ══════════════════════════════════════════════════════════════════════════════

def _is_scantop100_jsonl(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                return "host_status" in obj and "ports" in obj
    except Exception:
        pass
    return False


def _is_fastcheck_jsonl(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                return "status" in obj and "target" in obj and "scan_mode" in obj
    except Exception:
        pass
    return False


def parse_target_spec(spec: str, default_ports: list) -> list:
    """
    Parse one target spec string into a list of (host, port, ssl) tuples.

    Accepted formats
      192.168.1.1                → default ports
      192.168.1.1:80             → single port
      192.168.1.1:80,443,8080    → multiple ports
      http://192.168.1.1         → port 80, no ssl
      https://192.168.1.1        → port 443, ssl
      https://192.168.1.1:8443   → port 8443, ssl
    """
    spec = spec.strip()
    if not spec:
        return []

    # Strip scheme and remember ssl hint
    ssl_from_scheme = None
    for scheme in ("https://", "http://"):
        if spec.startswith(scheme):
            ssl_from_scheme = scheme == "https://"
            spec = spec[len(scheme):]
            break

    # Split host and port section
    # Handle IPv6 like [::1]:80
    if spec.startswith("["):
        bracket_end = spec.find("]")
        host = spec[1:bracket_end]
        rest = spec[bracket_end + 1:]
        ports_s = rest.lstrip(":")
    elif ":" in spec:
        parts = spec.rsplit(":", 1)
        host  = parts[0]
        ports_s = parts[1]
    else:
        host    = spec
        ports_s = ""

    # Parse ports
    if ports_s:
        try:
            ports = [int(p.strip()) for p in ports_s.split(",") if p.strip().isdigit()]
        except ValueError:
            ports = default_ports
    elif ssl_from_scheme is not None:
        ports = [443 if ssl_from_scheme else 80]
    else:
        ports = default_ports

    result = []
    for port in ports:
        ssl = ssl_from_scheme if ssl_from_scheme is not None else port_is_ssl(port)
        result.append((host, port, ssl))
    return result


def _iter_file(path: Path, default_ports: list):
    """Yield (host, port, ssl, source) tuples from a target file (lazy)."""
    if _is_scantop100_jsonl(path):
        # scantop100 output — extract HTTP ports from scan results
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("host_status") not in ("up", "unknown"):
                        continue
                    target = r.get("target", "")
                    for p in r.get("ports", []):
                        if service_is_http(p):
                            ssl = port_is_ssl(p["port"], p.get("service", ""))
                            yield target, p["port"], ssl, str(path)
                except json.JSONDecodeError:
                    pass

    elif _is_fastcheck_jsonl(path):
        # fastcheck output — up hosts only, use default ports
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("status") == "up" and r.get("target"):
                        for port in default_ports:
                            ssl = port_is_ssl(port)
                            yield r["target"], port, ssl, str(path)
                except json.JSONDecodeError:
                    pass

    else:
        # Plain text — one target spec per line
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for host, port, ssl in parse_target_spec(line, default_ports):
                    yield host, port, ssl, line


def _count_file(path: Path, default_ports: list) -> int:
    return sum(1 for _ in _iter_file(path, default_ports))


def resolve_targets(args):
    """Return (total, generator_factory) — lazy, memory-flat."""
    dp = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]

    if args.file:
        fpath = Path(args.file)
        if not fpath.exists():
            sys.exit(f"[ERROR] File not found: {args.file}")
        total  = _count_file(fpath, dp)
        gen_fn = lambda: _iter_file(fpath, dp)
        return total, gen_fn

    if args.target:
        entries = parse_target_spec(args.target, dp)
        if not entries:
            sys.exit(f"[ERROR] Could not parse target: {args.target}")
        return len(entries), lambda: ((h, p, s, args.target) for h, p, s in entries)

    sys.exit("[ERROR] Provide a TARGET or use -f FILE.")


# ══════════════════════════════════════════════════════════════════════════════
# 6 — Resume state
# ══════════════════════════════════════════════════════════════════════════════

def result_path(out_dir: Path, host: str, port: int) -> Path:
    safe = re.sub(r"[^\w.-]", "_", host)
    return out_dir / f"{safe}_{port}.json"


def load_completed(out_dir: Path) -> set:
    """Return set of (host, port) tuples that already have a result file."""
    done = set()
    if not out_dir.exists():
        return done
    for f in out_dir.glob("*.json"):
        if f.name.startswith("_"):
            continue  # skip _summary.jsonl etc.
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            done.add((data["target"], data["port"]))
        except Exception:
            pass
    return done


# ══════════════════════════════════════════════════════════════════════════════
# 7 — Individual probes
# ══════════════════════════════════════════════════════════════════════════════

def _run(cmd: list, timeout: int) -> tuple:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return (p.stdout.decode(errors="replace"),
                p.stderr.decode(errors="replace"),
                p.returncode)
    except subprocess.TimeoutExpired:
        return ("", "TIMEOUT", -1)
    except FileNotFoundError:
        return ("", "NOT_FOUND", -2)
    except Exception as exc:
        return ("", str(exc), -3)


def probe_curl(host: str, port: int, ssl: bool, timeout: int) -> dict:
    """Grab HTTP headers, status code, title, and server banner via curl."""
    scheme = "https" if ssl else "http"
    url    = f"{scheme}://{host}:{port}"
    result = {"url": url, "status_code": None, "redirect": None,
              "server": "", "headers": {}, "title": "", "error": None}

    # ── Headers ───────────────────────────────────────────────────────────────
    stdout, _, rc = _run([
        "curl", "-s", "-I",
        "--max-time", str(timeout),
        "--connect-timeout", "5",
        "-k", "-L",
        "-A", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        url,
    ], timeout + 5)

    if rc == -1:
        result["error"] = "timeout"
        return result
    if rc < 0:
        result["error"] = "connection refused"
        return result

    # Parse response headers from curl -I output
    for line in stdout.splitlines():
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                result["status_code"] = int(parts[1])
        elif ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            result["headers"][k] = v
            if k == "server":
                result["server"] = v
            if k == "location":
                result["redirect"] = v

    # ── Body (title extraction) ───────────────────────────────────────────────
    body_out, _, _ = _run([
        "curl", "-s",
        "--max-time", str(timeout),
        "--connect-timeout", "5",
        "-k", "-L",
        "-A", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        url,
    ], timeout + 5)

    m = re.search(r"<title[^>]*>(.*?)</title>", body_out, re.IGNORECASE | re.DOTALL)
    if m:
        result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    return result


def probe_whatweb(url: str, timeout: int) -> list:
    """Fingerprint web technologies using WhatWeb. Returns list of tech dicts."""
    stdout, _, rc = _run([
        "whatweb", "--no-errors", "-a", "3",
        "--log-json=/dev/stdout", "--quiet", url,
    ], timeout)

    technologies = []
    if rc < 0 or not stdout.strip():
        return technologies

    try:
        for line in stdout.strip().splitlines():
            obj = json.loads(line)
            # WhatWeb JSON is a list with one item per URL
            targets = obj if isinstance(obj, list) else [obj]
            for t in targets:
                for name, info in t.get("plugins", {}).items():
                    versions = info.get("version", info.get("string", []))
                    version  = versions[0] if versions else ""
                    technologies.append({"name": name, "version": str(version)})
    except Exception:
        # Fall back: parse the text output (WhatWeb sometimes outputs non-JSON)
        for m in re.finditer(r"(\w[\w\s/-]+)\[([^\]]*)\]", stdout):
            technologies.append({"name": m.group(1).strip(), "version": m.group(2).strip()})

    return technologies


def probe_wafw00f(url: str, timeout: int) -> dict:
    """Detect WAF/CDN using wafw00f."""
    stdout, _, rc = _run(["wafw00f", "-o", "-", "-f", "json", url], timeout)

    waf = {"detected": False, "name": None}
    if rc < 0 or not stdout.strip():
        return waf

    try:
        data = json.loads(stdout)
        if isinstance(data, list) and data:
            entry = data[0]
        elif isinstance(data, dict):
            entry = data
        else:
            return waf
        detected = entry.get("detected", False)
        waf["detected"] = bool(detected)
        if detected:
            waf["name"] = entry.get("firewall") or entry.get("manufacturer") or "unknown"
    except Exception:
        # Fallback: parse text output
        if "is behind" in stdout.lower():
            m = re.search(r"is behind (.*?) WAF", stdout, re.IGNORECASE)
            if m:
                waf["detected"] = True
                waf["name"]     = m.group(1).strip()

    return waf


def probe_nmap(host: str, port: int, ssl: bool, timeout: int) -> dict:
    """Run HTTP (and optionally SSL) nmap NSE scripts."""
    result = {"scripts": {}, "cves": [], "interesting_paths": []}

    http_scripts = (
        "http-headers,http-title,http-server-header,http-methods,"
        "http-robots.txt,http-generator,http-php-version,http-favicon,"
        "http-security-headers,http-cors,http-cookie-flags,"
        "http-auth-methods,http-enum,http-shellshock,"
        "http-aspnet-version,http-default-accounts,vulners"
    )

    script_args = (
        f"http.useragent=Mozilla/5.0,"
        f"vulners.showall=true"
        + (f",http.usessl=true" if ssl else "")
    )

    cmd = [
        "nmap", "-n", "-p", str(port),
        "--script", http_scripts,
        "--script-args", script_args,
        "--host-timeout", f"{timeout}s",
        "-oX", "-",
        host,
    ]

    stdout, _, rc = _run(cmd, timeout + 15)
    if stdout:
        _parse_nmap_xml(stdout, result, port)

    # SSL scripts (separate pass for HTTPS ports)
    if ssl:
        ssl_scripts = "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection,ssl-date"
        ssl_out, _, _ = _run([
            "nmap", "-n", "-p", str(port),
            "--script", ssl_scripts,
            "--host-timeout", f"{timeout}s",
            "-oX", "-", host,
        ], timeout + 15)
        if ssl_out:
            _parse_nmap_xml(ssl_out, result, port)

    return result


def _parse_nmap_xml(xml: str, result: dict, port: int):
    """Extract script output and CVEs from nmap XML; fills result in-place."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return

    host_el = root.find("host")
    if host_el is None:
        return

    for port_el in host_el.findall(".//port"):
        if int(port_el.get("portid", 0)) != port:
            continue
        for script in port_el.findall("script"):
            sid    = script.get("id", "")
            output = script.get("output", "")
            result["scripts"][sid] = output

            # Extract CVEs from vulners output
            if sid == "vulners":
                for m in re.finditer(r"(CVE-\d{4}-\d+)\s+([\d.]+)", output):
                    result["cves"].append({
                        "id":       m.group(1),
                        "score":    float(m.group(2)),
                        "source":   "nmap/vulners",
                    })

            # Extract interesting paths from http-enum
            if sid == "http-enum":
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("/"):
                        path = line.split(":")[0].strip()
                        result["interesting_paths"].append(path)

            # Extract shellshock indicator
            if sid == "http-shellshock" and "vulnerable" in output.lower():
                result["cves"].append({
                    "id": "CVE-2014-6271", "score": 10.0, "source": "nmap/shellshock"
                })


def probe_sslscan(host: str, port: int, timeout: int) -> dict:
    """Audit SSL/TLS configuration using sslscan."""
    result = {"protocols": {}, "ciphers": [], "certificate": {}, "issues": []}

    stdout, _, rc = _run(
        ["sslscan", "--no-colour", f"--connect-timeout={timeout}", f"{host}:{port}"],
        timeout + 10,
    )

    if rc < 0 or not stdout:
        return result

    # Parse protocol support
    for m in re.finditer(r"(SSL|TLS)\s+([\d.]+)\s+(enabled|disabled)", stdout, re.IGNORECASE):
        proto   = f"{m.group(1)} {m.group(2)}"
        enabled = m.group(3).lower() == "enabled"
        result["protocols"][proto] = enabled
        if enabled and m.group(1).upper() in ("SSL", "TLS") and m.group(2) in ("2", "3", "1.0", "1.1"):
            result["issues"].append(f"Weak protocol enabled: {proto}")

    # Heartbleed
    if re.search(r"heartbleed.*vulnerable", stdout, re.IGNORECASE):
        result["issues"].append("Heartbleed (CVE-2014-0160)")

    # POODLE
    if re.search(r"POODLE|sslv3.*vulnerable", stdout, re.IGNORECASE):
        result["issues"].append("POODLE (CVE-2014-3566)")

    # Certificate info
    for field, pattern in [
        ("subject",  r"Subject:\s*(.+)"),
        ("issuer",   r"Issuer:\s*(.+)"),
        ("expires",  r"Not valid after:\s*(.+)"),
    ]:
        m = re.search(pattern, stdout, re.IGNORECASE)
        if m:
            result["certificate"][field] = m.group(1).strip()

    return result


def probe_nikto(url: str, timeout: int) -> dict:
    """Run nikto and parse JSON output."""
    result = {"vulnerabilities": [], "cves": []}

    # nikto with JSON output to a temp file (nikto -output - is unreliable)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp = tf.name

    try:
        _run([
            "nikto", "-h", url, "-nointeractive",
            "-Cgidirs", "all",
            "-Format", "json",
            "-output", tmp,
        ], timeout)

        if Path(tmp).exists() and Path(tmp).stat().st_size > 0:
            raw = Path(tmp).read_text(errors="replace")
            data = json.loads(raw)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                desc = v.get("description", v.get("msg", ""))
                url_  = v.get("url", "")
                osvdb = v.get("OSVDB", "")
                cve_  = v.get("CVE", "")
                result["vulnerabilities"].append({
                    "description": desc,
                    "url": url_,
                    "osvdb": osvdb,
                })
                if cve_:
                    result["cves"].append({"id": cve_, "score": 0, "source": "nikto"})
    except Exception:
        pass
    finally:
        Path(tmp).unlink(missing_ok=True)

    return result


def probe_gobuster(url: str, timeout: int) -> list:
    """Directory enumeration with gobuster."""
    paths = []
    # Use a small common wordlist if available
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]
    wordlist = next((w for w in wordlists if Path(w).exists()), None)
    if not wordlist:
        return paths

    stdout, _, rc = _run([
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-q", "-o", "-",
        "--no-error",
        "-t", "20",
        "--timeout", f"{min(timeout, 10)}s",
    ], timeout)

    if rc >= 0:
        for line in stdout.splitlines():
            m = re.match(r"(/\S+)", line.strip())
            if m:
                paths.append(m.group(1))

    return paths


# ══════════════════════════════════════════════════════════════════════════════
# 8 — Scan orchestration
# ══════════════════════════════════════════════════════════════════════════════

def scan_one(host: str, port: int, ssl: bool, avail: dict,
             timeout: int, run_nikto: bool, run_gobuster: bool) -> dict:
    """
    Run all enabled probes against one host:port and return a unified result dict.
    """
    t_start = time.monotonic()
    scheme  = "https" if ssl else "http"
    url     = f"{scheme}://{host}:{port}"

    result = {
        "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
        "target":          host,
        "port":            port,
        "url":             url,
        "ssl":             ssl,
        "status":          "ok",
        "http_status":     None,
        "redirect":        None,
        "title":           "",
        "server":          "",
        "headers":         {},
        "technologies":    [],
        "waf":             {"detected": False, "name": None},
        "ssl_info":        None,
        "cves":            [],
        "msf_modules":     [],
        "interesting":     [],
        "scan_duration_s": None,
        "tools_used":      [],
        "errors":          [],
    }

    try:
        # ── curl ──────────────────────────────────────────────────────────────
        curl_r = probe_curl(host, port, ssl, min(timeout, 15))
        result["tools_used"].append("curl")
        if curl_r.get("error"):
            result["status"] = curl_r["error"]
            result["scan_duration_s"] = round(time.monotonic() - t_start, 2)
            return result
        result["http_status"] = curl_r["status_code"]
        result["redirect"]    = curl_r["redirect"]
        result["title"]       = curl_r["title"]
        result["server"]      = curl_r["server"]
        result["headers"]     = curl_r["headers"]

        # ── whatweb ───────────────────────────────────────────────────────────
        if avail.get("whatweb"):
            techs = probe_whatweb(url, min(timeout, 30))
            result["technologies"] = techs
            result["tools_used"].append("whatweb")

        # ── wafw00f ───────────────────────────────────────────────────────────
        if avail.get("wafw00f"):
            result["waf"] = probe_wafw00f(url, min(timeout, 20))
            result["tools_used"].append("wafw00f")

        # ── sslscan ───────────────────────────────────────────────────────────
        if ssl and avail.get("sslscan"):
            result["ssl_info"] = probe_sslscan(host, port, min(timeout, 30))
            result["tools_used"].append("sslscan")
            if result["ssl_info"].get("issues"):
                for issue in result["ssl_info"]["issues"]:
                    result["cves"].append({"id": issue, "score": 0, "source": "sslscan"})

        # ── nmap HTTP scripts ─────────────────────────────────────────────────
        if avail.get("nmap"):
            nmap_r = probe_nmap(host, port, ssl, min(timeout, 60))
            result["tools_used"].append("nmap")
            result["cves"].extend(nmap_r.get("cves", []))
            result["interesting"].extend(nmap_r.get("interesting_paths", []))
            # Enrich technologies from nmap
            for sid, output in nmap_r.get("scripts", {}).items():
                if sid == "http-server-header" and output and not result["server"]:
                    result["server"] = output.strip()
                if sid == "http-generator" and output:
                    result["technologies"].append({"name": output.strip(), "version": ""})
                if sid == "http-php-version" and output:
                    m = re.search(r"([\d.]+)", output)
                    result["technologies"].append({
                        "name": "PHP", "version": m.group(1) if m else output.strip()
                    })

        # ── nikto ─────────────────────────────────────────────────────────────
        if run_nikto and avail.get("nikto"):
            nikto_r = probe_nikto(url, timeout)
            result["tools_used"].append("nikto")
            result["cves"].extend(nikto_r.get("cves", []))
            for v in nikto_r.get("vulnerabilities", []):
                if v.get("url") and v["url"] not in result["interesting"]:
                    result["interesting"].append(v["url"])

        # ── gobuster ──────────────────────────────────────────────────────────
        if run_gobuster and avail.get("gobuster"):
            paths = probe_gobuster(url, timeout)
            result["tools_used"].append("gobuster")
            for p in paths:
                if p not in result["interesting"]:
                    result["interesting"].append(p)

        # ── deduplicate CVEs ──────────────────────────────────────────────────
        seen_cves = set()
        unique_cves = []
        for c in result["cves"]:
            if c["id"] not in seen_cves:
                seen_cves.add(c["id"])
                unique_cves.append(c)
        result["cves"] = sorted(unique_cves, key=lambda x: -x.get("score", 0))

        # ── MSF suggestions ───────────────────────────────────────────────────
        tech_s = " ".join(
            f"{t['name']} {t['version']}" for t in result["technologies"]
        ) + " " + result["server"]
        result["msf_modules"] = suggest_msf(tech_s, result["cves"])

    except Exception as exc:
        result["status"] = "error"
        result["errors"].append(str(exc))

    result["scan_duration_s"] = round(time.monotonic() - t_start, 2)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 9 — Live display
# ══════════════════════════════════════════════════════════════════════════════

class LiveDisplay:
    HEADER = 4
    FOOTER = 3

    def __init__(self, total, workers, out_dir, nmap_ver):
        cols, rows  = shutil.get_terminal_size((80, 24))
        self.total   = total
        self.cols    = cols
        self.rows    = rows
        self.v_start = self.HEADER + 1
        self.v_end   = max(self.v_start + 2, rows - self.FOOTER)
        self.f_sep   = self.v_end + 1
        self.f_stats = self.v_end + 2
        self.lock    = threading.Lock()
        self.done    = 0
        self.counts  = {"ok": 0, "cve": 0, "msf": 0, "err": 0}
        self._paused = False

        o   = sys.stdout
        bar = "─" * cols

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")

        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  http-info  ·  nmap {nmap_ver}{RESET}")
        self._at(3)
        o.write(f"  Targets: {total}  Workers: {workers}  Output: {out_dir}")
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        self._at(self.f_sep); o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()

        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

    def _at(self, row, col=1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _draw_stats(self):
        o    = sys.stdout
        pct  = self.done / self.total if self.total else 0
        bw   = max(10, min(24, self.cols - 62))
        fill = int(bw * pct)
        bar  = f"{'█' * fill}{'░' * (bw - fill)}"

        self._at(self.f_stats)
        o.write("\033[K")
        base = (
            f"  {GREEN}Done: {self.done}/{self.total}{RESET}"
            f"  {RED}CVEs: {self.counts['cve']}{RESET}"
            f"  {YELLOW}MSF: {self.counts['msf']}{RESET}"
            f"  {CYAN}[{bar}]{RESET}"
            f"  {DIM}Ctrl+C pause{RESET}"
        )
        if self._paused:
            base = (
                f"  {GREEN}Done: {self.done}/{self.total}{RESET}"
                f"  {RED}CVEs: {self.counts['cve']}{RESET}"
                f"  {YELLOW}MSF: {self.counts['msf']}{RESET}"
                f"  {YELLOW}{BOLD}⏸ PAUSED{RESET}  ↵ resume  ·  Ctrl+C quit"
            )
        o.write(base)

    def set_paused(self, paused: bool):
        with self.lock:
            self._paused = paused
            self._draw_stats()
            self._at(self.v_end)
            sys.stdout.flush()

    def add_result(self, result: dict):
        target   = result.get("target", "?")
        port     = result.get("port", 0)
        status   = result.get("status", "?")
        title    = result.get("title", "")[:25]
        server   = result.get("server", "")[:20]
        techs    = result.get("technologies", [])
        cves     = result.get("cves", [])
        msf      = result.get("msf_modules", [])
        w        = len(str(self.total))

        tech_s = " ".join(
            f"{t['name']}{(' ' + t['version']) if t.get('version') else ''}"
            for t in techs[:3]
        )[:30]

        if status == "ok":
            st_s   = f"{GREEN}ok  {RESET}"
            info_s = f"{DIM}{server or tech_s or title}{RESET}"
        elif status in ("timeout", "refused", "connection refused"):
            st_s   = f"{YELLOW}tout{RESET}"
            info_s = ""
        else:
            st_s   = f"{RED}err {RESET}"
            info_s = f"{RED}{status[:20]}{RESET}"

        cve_s = f"  {RED}{len(cves)} CVE{'s' if len(cves)!=1 else ''}{RESET}" if cves else ""
        msf_s = f"  {YELLOW}→{len(msf)} MSF{RESET}"                           if msf  else ""

        with self.lock:
            self.done += 1
            if status == "ok":       self.counts["ok"]  += 1
            elif status == "error":  self.counts["err"] += 1
            self.counts["cve"] += len(cves)
            self.counts["msf"] += len(msf)

            counter = f"{CYAN}[{self.done:{w}}/{self.total}]{RESET}"
            line    = f"{counter}  {target}:{port:<6}  {st_s}  {info_s}{cve_s}{msf_s}"

            o = sys.stdout
            self._at(self.v_end, 1)
            o.write("\n")
            o.write("\033[K")
            o.write(line)
            self._draw_stats()
            self._at(self.v_end)
            o.flush()

    def finish(self):
        with self.lock:
            o = sys.stdout
            o.write("\033[r")
            o.write("\033[?7h")
            o.write("\033[?25h")
            self._at(self.rows)
            o.write("\n")
            o.flush()


class SimpleDisplay:
    def __init__(self, total, workers, out_dir, nmap_ver):
        self.total  = total
        self.lock   = threading.Lock()
        self.done   = 0
        self.counts = {"ok": 0, "cve": 0, "msf": 0, "err": 0}
        bar = "─" * 62
        print(f"\n{bar}")
        print(f"  http-info  ·  nmap {nmap_ver}")
        print(f"  Targets: {total}  Workers: {workers}  Output: {out_dir}")
        print(f"{bar}\n")
        print("  Ctrl+C to pause  ·  Enter to resume  ·  Ctrl+C again to quit\n")

    def set_paused(self, paused: bool):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def add_result(self, result: dict):
        target = result.get("target", "?")
        port   = result.get("port", 0)
        server = result.get("server", "")
        cves   = result.get("cves", [])
        msf    = result.get("msf_modules", [])
        w      = len(str(self.total))
        with self.lock:
            self.done += 1
            self.counts["cve"] += len(cves)
            self.counts["msf"] += len(msf)
            cve_s = f"  {len(cves)} CVEs" if cves else ""
            msf_s = f"  →{len(msf)} MSF"  if msf  else ""
            print(f"[{self.done:{w}}/{self.total}]  {target}:{port:<6}  {server}{cve_s}{msf_s}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 10 — Output
# ══════════════════════════════════════════════════════════════════════════════

_file_lock  = threading.Lock()
_summ_lock  = threading.Lock()


def write_result(out_dir: Path, result: dict):
    """Write the full result as a per-host JSON file and append to summary."""
    path = result_path(out_dir, result["target"], result["port"])
    with _file_lock:
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                        encoding="utf-8")

    # Append a compact summary line
    summary_fields = {
        "timestamp":    result["timestamp"],
        "target":       result["target"],
        "port":         result["port"],
        "url":          result["url"],
        "status":       result["status"],
        "http_status":  result["http_status"],
        "title":        result["title"],
        "server":       result["server"],
        "technologies": [t["name"] for t in result.get("technologies", [])],
        "cve_count":    len(result.get("cves", [])),
        "msf_count":    len(result.get("msf_modules", [])),
        "waf":          result.get("waf", {}).get("name"),
    }
    summary_path = out_dir / "_summary.jsonl"
    with _summ_lock:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary_fields, ensure_ascii=False) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# 11 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="http-info",
        description="Web service reconnaissance using Kali Linux tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python http-info.py 192.168.1.1\n"
            "  python http-info.py 192.168.1.1:80,443,8080\n"
            "  python http-info.py -f scantop100_results.jsonl -o results/\n"
            "  python http-info.py -f targets.txt -o results/ -w 10\n"
            "  python http-info.py -f live.jsonl --nikto -w 3\n"
        ),
    )
    parser.add_argument("target",       nargs="?",     metavar="TARGET",
                        help="Host, host:port, or host:port1,port2,port3")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="Target file: plain text, fastcheck .jsonl, or scantop100 .jsonl")
    parser.add_argument("-o", "--output", metavar="DIR",  default="http-info-results",
                        help="Output directory (default: http-info-results/)")
    parser.add_argument("-w", "--workers", type=int,    default=5, metavar="N",
                        help="Parallel scans (default: 5; lower = less noise)")
    parser.add_argument("-p", "--ports",   default="80,443", metavar="PORTS",
                        help="Default ports when none specified (default: 80,443)")
    parser.add_argument("--timeout",    type=int, default=60, metavar="SEC",
                        help="Per-tool timeout in seconds (default: 60)")
    parser.add_argument("--nikto",      action="store_true",
                        help="Enable nikto scanner (slow; adds 5-30 min per host)")
    parser.add_argument("--gobuster",   action="store_true",
                        help="Enable gobuster directory enumeration")
    parser.add_argument("--no-nmap",    action="store_true",
                        help="Skip nmap HTTP/SSL scripts")
    parser.add_argument("--fast",       action="store_true",
                        help="Quick mode: curl + whatweb only (~10s per host)")

    args = parser.parse_args()

    avail = check_tools()

    # Fast mode disables slow tools
    if args.fast:
        args.nikto    = False
        args.gobuster = False
        args.no_nmap  = True

    if args.no_nmap:
        avail["nmap"] = False

    total, gen_fn = resolve_targets(args)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Resume: find already-completed host:port pairs ────────────────────────
    completed = load_completed(out_dir)
    remaining = total - len(completed)
    if completed:
        print(
            f"\n{YELLOW}Resume:{RESET} {len(completed):,} already scanned, "
            f"{remaining:,} remaining."
        )

    # ── nmap version for display ──────────────────────────────────────────────
    nmap_ver = "n/a"
    if avail.get("nmap"):
        out, _, _ = _run(["nmap", "--version"], 5)
        for tok in (out.splitlines()[0] if out else "").split():
            if tok and tok[0].isdigit():
                nmap_ver = tok
                break

    signal.signal(signal.SIGINT, _sigint_handler)

    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(remaining or total, args.workers, out_dir, nmap_ver)

    def run_one(host: str, port: int, ssl: bool, source: str):
        if not wait_if_paused(display):
            return
        if _quit_event.is_set():
            return
        result        = scan_one(host, port, ssl, avail, args.timeout,
                                 args.nikto, args.gobuster)
        result["input"] = source
        display.add_result(result)
        write_result(out_dir, result)

    MAX_PENDING = args.workers * 4

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen     = (
                (h, p, s, src)
                for h, p, s, src in gen_fn()
                if (h, p) not in completed
            )
            pending = set()
            for h, p, s, src in itertools.islice(gen, MAX_PENDING):
                pending.add(pool.submit(run_one, h, p, s, src))

            while pending and not _quit_event.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    f.result()
                if not _quit_event.is_set():
                    for h, p, s, src in itertools.islice(gen, len(done)):
                        pending.add(pool.submit(run_one, h, p, s, src))

    except Exception:
        pass
    finally:
        display.finish()

    # ── Summary ───────────────────────────────────────────────────────────────
    c   = display.counts
    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"  {GREEN}Scanned         : {c['ok']}{RESET}")
    print(f"  {RED}CVEs found      : {c['cve']}{RESET}")
    print(f"  {YELLOW}MSF suggestions : {c['msf']}{RESET}")
    if c["err"]:
        print(f"  {DIM}Errors          : {c['err']}{RESET}")
    print(f"  Output          : {out_dir}/")
    print(f"  Summary file    : {out_dir}/_summary.jsonl")
    if _quit_event.is_set():
        print(f"\n  {YELLOW}Scan stopped — re-run the same command to continue.{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
