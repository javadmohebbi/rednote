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
    """
    Yield (host, port, ssl, source, input_hostname) tuples from a target file (lazy).
    input_hostname is the PTR/reverse-DNS name the upstream tool (fastcheck or
    scantop100) already discovered — carried forward so every result stays
    traceable to the original domain name even when stored by raw IP.
    """
    if _is_scantop100_jsonl(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("host_status") not in ("up", "unknown"):
                        continue
                    target = r.get("target", "")
                    hn     = r.get("input_hostname") or r.get("hostname") or ""
                    for p in r.get("ports", []):
                        if service_is_http(p):
                            ssl = port_is_ssl(p["port"], p.get("service", ""))
                            yield target, p["port"], ssl, str(path), hn
                except json.JSONDecodeError:
                    pass

    elif _is_fastcheck_jsonl(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("status") == "up" and r.get("target"):
                        hn = r.get("hostname") or ""
                        for port in default_ports:
                            ssl = port_is_ssl(port)
                            yield r["target"], port, ssl, str(path), hn
                except json.JSONDecodeError:
                    pass

    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for host, port, ssl in parse_target_spec(line, default_ports):
                    yield host, port, ssl, line, ""


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
        return len(entries), lambda: ((h, p, s, args.target, "") for h, p, s in entries)

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
             timeout: int, run_nikto: bool, run_gobuster: bool,
             progress_cb=None) -> dict:
    """
    Run all enabled probes against one host:port and return a unified result dict.
    progress_cb(tool_name) is called just before each tool starts so the display
    can show what is currently running.
    """
    def _prog(tool):
        if progress_cb:
            progress_cb(tool)

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
        _prog("curl")
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
            _prog("whatweb")
            techs = probe_whatweb(url, min(timeout, 30))
            result["technologies"] = techs
            result["tools_used"].append("whatweb")

        # ── wafw00f ───────────────────────────────────────────────────────────
        if avail.get("wafw00f"):
            _prog("wafw00f")
            result["waf"] = probe_wafw00f(url, min(timeout, 20))
            result["tools_used"].append("wafw00f")

        # ── sslscan ───────────────────────────────────────────────────────────
        if ssl and avail.get("sslscan"):
            _prog("sslscan")
            result["ssl_info"] = probe_sslscan(host, port, min(timeout, 30))
            result["tools_used"].append("sslscan")
            if result["ssl_info"].get("issues"):
                for issue in result["ssl_info"]["issues"]:
                    result["cves"].append({"id": issue, "score": 0, "source": "sslscan"})

        # ── nmap HTTP scripts ─────────────────────────────────────────────────
        if avail.get("nmap"):
            _prog("nmap")
            nmap_r = probe_nmap(host, port, ssl, min(timeout, 60))
            result["tools_used"].append("nmap")
            result["cves"].extend(nmap_r.get("cves", []))
            result["interesting"].extend(nmap_r.get("interesting_paths", []))
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
            _prog("nikto")
            nikto_r = probe_nikto(url, timeout)
            result["tools_used"].append("nikto")
            result["cves"].extend(nikto_r.get("cves", []))
            for v in nikto_r.get("vulnerabilities", []):
                if v.get("url") and v["url"] not in result["interesting"]:
                    result["interesting"].append(v["url"])

        # ── gobuster ──────────────────────────────────────────────────────────
        if run_gobuster and avail.get("gobuster"):
            _prog("gobuster")
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
#
# Layout
#
#   Row 1          ─── CYAN bar ───────────────────────────────────────────
#   Row 2          http-info · nmap X.XX
#   Row 3          Targets: N  Workers: W  Output: dir
#   Row 4          ─── CYAN bar ───────────────────────────────────────────
#   Row 5          Active scans:
#   Rows 6..5+W    One row per worker — shows current host:port and tool
#   Row 6+W        ─── DIM thin separator ─────────────────────────────────
#   Rows 7+W..vend SCROLL REGION — completed results scroll upward
#   Row vend+1     ─── DIM separator ──────────────────────────────────────
#   Row vend+2     Done: N/N  CVEs: N  MSF: N  [████░░]  Ctrl+C pause
#
# Each worker uses its own fixed row (thread → slot mapping).
# A background ticker redraws elapsed times every 2 s.

class LiveDisplay:
    HEADER = 4   # rows 1-4
    FOOTER = 3   # bottom 3 rows

    def __init__(self, total, workers, out_dir, nmap_ver):
        cols, rows  = shutil.get_terminal_size((80, 24))
        self.total   = total
        self.cols    = cols
        self.rows    = rows
        self.lock    = threading.RLock()   # RLock: internal methods call each other
        self.done    = 0
        self.counts  = {"ok": 0, "cve": 0, "msf": 0, "err": 0}
        self._paused = False
        self._stopped = False

        # How many worker rows to show (leave at least 3 scroll rows)
        self.w_shown = min(workers, max(1, rows - self.HEADER - self.FOOTER - 4))

        # Row numbers (1-indexed)
        self._r_active_label = self.HEADER + 1                   # "Active scans:"
        self._r_worker_first = self.HEADER + 2                   # first worker row
        self._r_worker_last  = self.HEADER + 1 + self.w_shown    # last worker row
        self._r_worker_sep   = self.HEADER + 2 + self.w_shown    # thin separator
        self.v_start         = self.HEADER + 3 + self.w_shown    # scroll start
        self.v_end           = max(self.v_start + 1, rows - self.FOOTER)
        self.f_sep           = self.v_end + 1
        self.f_stats         = self.v_end + 2

        # Worker slot state: slot_index → {host, port, tool, t_start}
        self._slots       = {}   # slot_index → dict
        self._tid_to_slot = {}   # thread_id  → slot_index

        o   = sys.stdout
        bar = "─" * cols

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")

        # Header
        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  http-info  ·  nmap {nmap_ver}{RESET}")
        self._at(3); o.write(f"  Targets: {total}  Workers: {workers}  Output: {out_dir}")
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        # Active section label
        self._at(self._r_active_label)
        o.write(f"  {DIM}Active scans:{RESET}")

        # Empty worker slots
        for i in range(self.w_shown):
            self._at(self._r_worker_first + i)
            o.write(f"  {DIM}w{i:<2}  ─{RESET}")

        # Footer
        self._at(self._r_worker_sep); o.write(f"{DIM}{bar}{RESET}")
        self._at(self.f_sep);         o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()

        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

        # Background ticker — redraws elapsed times every 2 s
        threading.Thread(target=self._ticker, daemon=True).start()

    # ── Internal helpers (called with lock held) ──────────────────────────────

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
        if self._paused:
            o.write(
                f"  {GREEN}Done: {self.done}/{self.total}{RESET}"
                f"  {RED}CVEs: {self.counts['cve']}{RESET}"
                f"  {YELLOW}MSF: {self.counts['msf']}{RESET}"
                f"  {YELLOW}{BOLD}⏸ PAUSED{RESET}  ↵ resume  ·  Ctrl+C quit"
            )
        else:
            o.write(
                f"  {GREEN}Done: {self.done}/{self.total}{RESET}"
                f"  {RED}CVEs: {self.counts['cve']}{RESET}"
                f"  {YELLOW}MSF: {self.counts['msf']}{RESET}"
                f"  {CYAN}[{bar}]{RESET}"
                f"  {DIM}Ctrl+C pause{RESET}"
            )

    def _redraw_slot(self, idx: int):
        """Redraw one worker row (call with lock held)."""
        row = self._r_worker_first + idx
        if row > self._r_worker_last:
            return
        o = sys.stdout
        self._at(row, 1)
        o.write("\033[K")
        slot = self._slots.get(idx)
        if slot:
            elapsed = int(time.monotonic() - slot["t"])
            tool    = slot.get("tool", "…")
            target  = f"{slot['host']}:{slot['port']}"
            o.write(
                f"  {CYAN}w{idx:<2}{RESET}  "
                f"{YELLOW}{target:<22}{RESET}  "
                f"{DIM}→ {tool:<12}  {elapsed}s{RESET}"
            )
        else:
            o.write(f"  {DIM}w{idx:<2}  ─{RESET}")

    def _ticker(self):
        """Background thread: refresh elapsed times every 2 s."""
        while not self._stopped:
            time.sleep(2)
            with self.lock:
                if self._stopped:
                    break
                for idx in list(self._slots):
                    self._redraw_slot(idx)
                self._at(self.v_end)
                sys.stdout.flush()

    # ── Public slot API ───────────────────────────────────────────────────────

    def claim_slot(self, host: str, port: int):
        """Called at the start of each worker task."""
        tid = threading.get_ident()
        with self.lock:
            used = set(self._slots)
            idx  = next((i for i in range(self.w_shown) if i not in used), 0)
            self._slots[idx]      = {"host": host, "port": port, "tool": "…", "t": time.monotonic()}
            self._tid_to_slot[tid] = idx
            self._redraw_slot(idx)
            self._at(self.v_end)
            sys.stdout.flush()

    def update_slot(self, tool: str):
        """Called just before each tool runs."""
        tid = threading.get_ident()
        with self.lock:
            idx = self._tid_to_slot.get(tid)
            if idx is not None and idx in self._slots:
                self._slots[idx]["tool"] = tool
                self._redraw_slot(idx)
                self._at(self.v_end)
                sys.stdout.flush()

    def release_slot(self):
        """Called after the worker task finishes."""
        tid = threading.get_ident()
        with self.lock:
            idx = self._tid_to_slot.pop(tid, None)
            if idx is not None:
                self._slots.pop(idx, None)
                self._redraw_slot(idx)
                self._at(self.v_end)
                sys.stdout.flush()

    # ── Public display API ────────────────────────────────────────────────────

    def set_paused(self, paused: bool):
        with self.lock:
            self._paused = paused
            self._draw_stats()
            self._at(self.v_end)
            sys.stdout.flush()

    def add_result(self, result: dict):
        target = result.get("target", "?")
        port   = result.get("port", 0)
        status = result.get("status", "?")
        server = result.get("server", "")[:22]
        techs  = result.get("technologies", [])
        cves   = result.get("cves", [])
        msf    = result.get("msf_modules", [])
        w      = len(str(self.total))

        tech_s = " ".join(
            f"{t['name']}{(' ' + t['version']) if t.get('version') else ''}"
            for t in techs[:3]
        )[:28]

        if status == "ok":
            st_s   = f"{GREEN}ok  {RESET}"
            info_s = f"{DIM}{server or tech_s}{RESET}"
        elif status in ("timeout", "refused", "connection refused"):
            st_s   = f"{YELLOW}tout{RESET}"
            info_s = ""
        else:
            st_s   = f"{RED}err {RESET}"
            info_s = f"{RED}{status[:22]}{RESET}"

        cve_s = f"  {RED}{len(cves)}▲{RESET}"   if cves else ""
        msf_s = f"  {YELLOW}→{len(msf)}⚡{RESET}" if msf  else ""

        with self.lock:
            self.done += 1
            if status == "ok":      self.counts["ok"]  += 1
            elif status == "error": self.counts["err"] += 1
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
        self._stopped = True
        with self.lock:
            o = sys.stdout
            o.write("\033[r")
            o.write("\033[?7h")
            o.write("\033[?25h")
            self._at(self.rows)
            o.write("\n")
            o.flush()


class SimpleDisplay:
    """Fallback for non-TTY — plain line-by-line output."""

    def __init__(self, total, workers, out_dir, nmap_ver):
        self.total  = total
        self.lock   = threading.Lock()
        self.done   = 0
        self.counts = {"ok": 0, "cve": 0, "msf": 0, "err": 0}
        bar = "─" * 62
        print(f"\n{bar}")
        print(f"  http-info  ·  nmap {nmap_ver}")
        print(f"  Targets: {total}  Workers: {workers}  Output: {out_dir}")
        print(f"{bar}")
        print("  Ctrl+C pause  ·  Enter resume  ·  Ctrl+C quit\n")

    def set_paused(self, paused: bool):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def claim_slot(self, host: str, port: int):
        with self.lock:
            print(f"  → {host}:{port}  starting…")

    def update_slot(self, tool: str):
        pass   # too noisy on plain text

    def release_slot(self):
        pass

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
        "timestamp":      result["timestamp"],
        "target":         result["target"],
        "input_hostname": result.get("input_hostname") or "",
        "port":           result["port"],
        "url":            result["url"],
        "status":         result["status"],
        "http_status":    result["http_status"],
        "title":          result["title"],
        "server":         result["server"],
        "technologies":   [t["name"] for t in result.get("technologies", [])],
        "cve_count":      len(result.get("cves", [])),
        "msf_count":      len(result.get("msf_modules", [])),
        "waf":            result.get("waf", {}).get("name"),
    }
    summary_path = out_dir / "_summary.jsonl"
    with _summ_lock:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary_fields, ensure_ascii=False) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# 11 — Analysis / report
# ══════════════════════════════════════════════════════════════════════════════

def analyze_dir(path: Path, group_by: str = "host"):
    """
    Read all per-host JSON files from an output directory and print a report.
    Designed for  | less  or  | less -R  (colours on TTY, plain text when piped).

    group_by  host     — per-host summary with ports, CVEs, MSF (default)
              port     — all hosts grouped by port number
              cve      — all affected hosts grouped by CVE ID
              service  — all hosts grouped by detected technology
              msf      — all applicable hosts grouped by MSF module
              headers  — security header gaps across all hosts
              all      — all of the above in sequence
    """
    if not path.exists():
        sys.exit(f"[ERROR] Directory not found: {path}")

    records = []
    for f in sorted(path.glob("*.json")):
        if f.name.startswith("_"):
            continue
        try:
            records.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass

    if not records:
        sys.exit(f"[ERROR] No result files found in {path}")

    tty  = sys.stdout.isatty()
    def _c(code, text): return f"{code}{text}{RESET}" if tty else str(text)

    wide  = "═" * 64
    thin  = "─" * 64
    dthin = "┄" * 64

    # ── Shared sort key ───────────────────────────────────────────────────────
    def _ip_sort(r):
        try:
            return (0, int(ipaddress.ip_address(r.get("target", ""))), r.get("port", 0))
        except ValueError:
            return (1, r.get("target", ""), r.get("port", 0))

    # ── Summary header ────────────────────────────────────────────────────────
    total_cves = sum(len(r.get("cves", [])) for r in records)
    total_msf  = sum(len(r.get("msf_modules", [])) for r in records)
    with_cves  = [r for r in records if r.get("cves")]
    with_msf   = [r for r in records if r.get("msf_modules")]
    ok_hosts   = [r for r in records if r.get("status") == "ok"]
    errors     = [r for r in records if r.get("status") not in ("ok",)]

    all_svcs : dict = {}
    for r in records:
        for t in r.get("technologies", []):
            n = t.get("name", "")
            if n:
                all_svcs[n] = all_svcs.get(n, 0) + 1
    top_svcs = sorted(all_svcs.items(), key=lambda x: -x[1])[:6]

    print()
    print(_c(BOLD + CYAN, wide))
    print(_c(BOLD,         f"  {path}"))
    print(_c(BOLD + CYAN, wide))
    print(f"  Scanned          : {len(records)}  ({len(ok_hosts)} ok,  {len(errors)} errors)")
    print(f"  With CVEs        : {_c(RED,    len(with_cves))}  ({total_cves} total)")
    print(f"  With MSF modules : {_c(YELLOW, len(with_msf))}  ({total_msf} total)")
    if top_svcs:
        svc_s = "  ".join(f"{s}({n})" for s, n in top_svcs)
        print(f"  Top technologies : {_c(CYAN, svc_s)}")
    print(_c(BOLD + CYAN, wide))
    print()

    views = [group_by] if group_by != "all" else ["host","port","cve","service","msf","headers"]

    for view in views:

        # ── By host ───────────────────────────────────────────────────────────
        if view == "host":
            print(_c(BOLD, f"  ▶ By host"))
            print(_c(DIM, thin))
            for r in sorted(records, key=_ip_sort):
                target = r.get("target", "?")
                port   = r.get("port", 0)
                url    = r.get("url", f"{target}:{port}")
                server = r.get("server", "")
                techs  = [t["name"] + (" " + t.get("version","") if t.get("version") else "")
                          for t in r.get("technologies", [])]
                cves   = r.get("cves", [])
                msf    = r.get("msf_modules", [])
                status = r.get("status", "?")
                dur    = r.get("scan_duration_s")
                waf    = r.get("waf", {})

                # Host line
                st_c  = GREEN if status == "ok" else RED
                dur_s = f"  {DIM}({dur:.0f}s){RESET}" if tty and dur else (f"  ({dur:.0f}s)" if dur else "")
                waf_s = f"  {YELLOW}[WAF: {waf['name']}]{RESET}" if waf.get("detected") else ""
                print(_c(BOLD, f"  {url}") + dur_s + waf_s)

                if server:
                    print(f"    {_c(DIM, 'Server:'):<18}  {_c(CYAN, server)}")
                if techs:
                    print(f"    {_c(DIM, 'Technologies:'):<18}  {', '.join(techs[:6])}")
                if cves:
                    top = cves[:5]
                    cve_s = "  ".join(
                        f"{_c(RED, c['id'])} ({c.get('score',0):.1f})" for c in top
                    )
                    more  = f"  {DIM}+{len(cves)-5} more{RESET}" if len(cves) > 5 else ""
                    print(f"    {_c(DIM, 'CVEs:'):<18}  {cve_s}{more}")
                if msf:
                    for m in msf[:3]:
                        print(f"    {_c(YELLOW, '→ ' + m['module'])}")
                print()

        # ── By port ───────────────────────────────────────────────────────────
        elif view == "port":
            port_map: dict = {}
            for r in records:
                port_map.setdefault(r.get("port", 0), []).append(r)

            print(_c(BOLD, "  ▶ By port"))
            print(_c(DIM, thin))
            for port in sorted(port_map):
                hosts = port_map[port]
                n     = len(hosts)
                print(_c(BOLD, f"  Port {port}  ")
                      + _c(DIM, f"({n} host{'s' if n!=1 else ''})"))
                for r in sorted(hosts, key=_ip_sort):
                    target = r.get("target", "?")
                    server = r.get("server", "")
                    cves   = r.get("cves", [])
                    hn     = r.get("title", "")[:30]
                    cve_s  = f"  {_c(RED, str(len(cves)) + ' CVE')}" if cves else ""
                    info   = server or hn
                    print(f"    {_c(CYAN, target):<24}  {_c(DIM, info)}{cve_s}")
                print()

        # ── By CVE ────────────────────────────────────────────────────────────
        elif view == "cve":
            cve_map: dict = {}
            for r in records:
                for c in r.get("cves", []):
                    cve_map.setdefault(c["id"], {"score": c.get("score",0), "hosts": []})["hosts"].append(r)

            if not cve_map:
                print(_c(DIM, "  ▶ By CVE — no CVEs found\n"))
            else:
                print(_c(BOLD, "  ▶ By CVE  ") + _c(DIM, f"({len(cve_map)} unique CVEs)"))
                print(_c(DIM, thin))
                for cve_id, data in sorted(cve_map.items(), key=lambda x: -x[1]["score"]):
                    hosts = data["hosts"]
                    score = data["score"]
                    score_col = RED if score >= 7 else YELLOW if score >= 4 else DIM
                    print(
                        _c(BOLD, f"  {cve_id}")
                        + f"  {_c(score_col, f'CVSS {score:.1f}')}"
                        + _c(DIM, f"  ({len(hosts)} host{'s' if len(hosts)!=1 else ''})")
                    )
                    for r in sorted(hosts, key=_ip_sort):
                        url = r.get("url", r.get("target"))
                        print(f"    {_c(CYAN, url)}")
                    print()

        # ── By service / technology ───────────────────────────────────────────
        elif view == "service":
            svc_map: dict = {}
            for r in records:
                seen = set()
                for t in r.get("technologies", []):
                    name = t.get("name", "")
                    if name and name not in seen:
                        seen.add(name)
                        svc_map.setdefault(name, []).append(
                            (r, t.get("version", ""))
                        )

            if not svc_map:
                print(_c(DIM, "  ▶ By service — no technologies detected\n"))
            else:
                print(_c(BOLD, "  ▶ By service / technology"))
                print(_c(DIM, thin))
                for name, entries in sorted(svc_map.items(), key=lambda x: -len(x[1])):
                    n = len(entries)
                    print(_c(BOLD, f"  {name}  ") + _c(DIM, f"({n} host{'s' if n!=1 else ''})"))
                    for r, ver in sorted(entries, key=lambda e: _ip_sort(e[0])):
                        url   = r.get("url", r.get("target"))
                        cves  = r.get("cves", [])
                        ver_s = f"  {DIM}{ver}{RESET}" if ver else ""
                        cve_s = f"  {_c(RED, str(len(cves)) + ' CVE')}" if cves else ""
                        print(f"    {_c(CYAN, url)}{ver_s}{cve_s}")
                    print()

        # ── By MSF module ─────────────────────────────────────────────────────
        elif view == "msf":
            msf_map: dict = {}
            for r in records:
                for m in r.get("msf_modules", []):
                    mod = m["module"]
                    msf_map.setdefault(mod, {"desc": m.get("description",""), "reason": m.get("reason",""), "hosts": []})["hosts"].append(r)

            if not msf_map:
                print(_c(DIM, "  ▶ By MSF module — no modules suggested\n"))
            else:
                print(_c(BOLD, "  ▶ By Metasploit module"))
                print(_c(DIM, thin))
                for mod, data in sorted(msf_map.items(), key=lambda x: -len(x[1]["hosts"])):
                    hosts = data["hosts"]
                    print(
                        _c(YELLOW, f"  {mod}")
                        + _c(DIM, f"  ({len(hosts)} host{'s' if len(hosts)!=1 else ''})")
                    )
                    if data["desc"]:
                        print(f"    {_c(DIM, data['desc'])}  {_c(DIM, data['reason'])}")
                    for r in sorted(hosts, key=_ip_sort):
                        url = r.get("url", r.get("target"))
                        print(f"    {_c(CYAN, url)}")
                    print()

        # ── Security headers ──────────────────────────────────────────────────
        elif view == "headers":
            SECURITY_HEADERS = [
                ("strict-transport-security", "HSTS",              True),  # True = HTTPS only
                ("content-security-policy",   "CSP",               False),
                ("x-frame-options",           "X-Frame-Options",   False),
                ("x-content-type-options",    "X-Content-Type",    False),
                ("permissions-policy",        "Permissions-Policy",False),
                ("referrer-policy",           "Referrer-Policy",   False),
                ("x-xss-protection",          "X-XSS-Protection",  False),
            ]

            print(_c(BOLD, "  ▶ Security header gaps"))
            print(_c(DIM, thin))

            https_hosts = [r for r in records if r.get("ssl")]
            all_ok = [r for r in records if r.get("status") == "ok"]

            for header, label, https_only in SECURITY_HEADERS:
                pool = https_hosts if https_only else all_ok
                missing = [r for r in pool
                           if header not in {k.lower() for k in r.get("headers", {})}]
                if not missing:
                    print(f"  {_c(GREEN, '✓')}  {label:<28}  present on all hosts")
                else:
                    pct = int(100 * len(missing) / len(pool)) if pool else 0
                    print(
                        f"  {_c(RED, '✗')}  {label:<28}  "
                        f"{_c(RED, f'missing on {len(missing)}/{len(pool)} hosts ({pct}%)')}"
                    )
                    for r in sorted(missing, key=_ip_sort)[:8]:
                        print(f"       {_c(DIM, r.get('url', r.get('target')))}")
                    if len(missing) > 8:
                        print(f"       {_c(DIM, f'... and {len(missing)-8} more')}")
            print()

        # ── Footer ────────────────────────────────────────────────────────────
    if errors:
        print(_c(DIM, dthin))
        print(_c(DIM, f"  Errors / not reachable ({len(errors)}):"))
        for r in sorted(errors, key=_ip_sort):
            st = r.get("status", "?")
            print(_c(DIM, f"    {r.get('url', r.get('target'))}  ({st})"))
        print()


# ══════════════════════════════════════════════════════════════════════════════
# 12 — CLI
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
    parser.add_argument("--analyze",    metavar="DIR",
                        help="Analyze an existing results directory instead of scanning.")
    parser.add_argument("--group-by",   metavar="MODE", default="host",
                        choices=["host","port","cve","service","msf","headers","all"],
                        help="Analysis grouping: host(default) port cve service msf headers all")

    args = parser.parse_args()

    # ── Analysis mode ─────────────────────────────────────────────────────────
    if args.analyze:
        analyze_dir(Path(args.analyze), group_by=args.group_by)
        sys.exit(0)

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

    def run_one(host: str, port: int, ssl: bool, source: str, input_hostname: str):
        if not wait_if_paused(display):
            return
        if _quit_event.is_set():
            return
        display.claim_slot(host, port)
        try:
            result = scan_one(host, port, ssl, avail, args.timeout,
                              args.nikto, args.gobuster,
                              progress_cb=display.update_slot)
            result["input"]          = source
            result["input_hostname"] = input_hostname   # PTR from upstream tool
        finally:
            display.release_slot()
        display.add_result(result)
        write_result(out_dir, result)

    MAX_PENDING = args.workers * 4

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen     = (
                (h, p, s, src, hn)
                for h, p, s, src, hn in gen_fn()
                if (h, p) not in completed
            )
            pending = set()
            for h, p, s, src, hn in itertools.islice(gen, MAX_PENDING):
                pending.add(pool.submit(run_one, h, p, s, src, hn))

            while pending and not _quit_event.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    f.result()
                if not _quit_event.is_set():
                    for h, p, s, src, hn in itertools.islice(gen, len(done)):
                        pending.add(pool.submit(run_one, h, p, s, src, hn))

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
