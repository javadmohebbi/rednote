#!/usr/bin/env python3
"""
vault.py  —  central recon intelligence database
=================================================
Validates target IPs against a country code (local IP2Location + online
ipinfo.io), scans each host with nmap (OS, services, open ports,
vulnerabilities / CVEs), optionally cross-references findings with
searchsploit, and stores everything in a shared SQLite database that other
tools in the pipeline can read from and write to.

Sources / tools
  Validation  — IP2Location DB11 (local)  +  curl ipinfo.io/<ip>  (online)
  Port/OS     — nmap  -sV -O -T4 --script=vuln
  CVE lookup  — nmap vuln scripts  +  searchsploit (optional, --searchsploit)

Pause / resume
  Ctrl+C once  →  pause (workers finish current IP, then wait)
  Enter        →  resume
  Ctrl+C again →  quit
  Re-run       →  already-scanned ('done') IPs are skipped automatically

Usage
  python vault.py -f targets.jsonl --country US
  python vault.py -f targets.jsonl --country US -w 3
  python vault.py -f targets.jsonl --country US --nmap-args "-p- -T3"
  python vault.py -f targets.jsonl --country US --searchsploit
  python vault.py --from-ipdb ipdb.sqlite --country US
  python vault.py -f targets.jsonl             # no country filter
"""

import os
import re
import sys
import json
import time
import shlex
import signal
import shutil
import sqlite3
import argparse
import subprocess
import threading
import itertools
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait as fut_wait
from pathlib import Path

# ── Import ipinfo from sibling directory ─────────────────────────────────────
_IPINFO_DIR = Path(__file__).resolve().parent.parent / "ipinfo"
if str(_IPINFO_DIR) not in sys.path:
    sys.path.insert(0, str(_IPINFO_DIR))

try:
    import ipinfo as _ipinfo_mod
except ImportError as e:
    sys.exit(
        f"[ERROR] Cannot import ipinfo module from {_IPINFO_DIR}\n"
        f"        {e}\n"
        f"        Install dependencies: pip install IP2Location python-dotenv requests"
    )

# ── ANSI ─────────────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[32m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"

_IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else True


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Pause / quit  (same pattern as ipdb / fastcheck)
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
# 2 — Rate limiter  (for ipinfo.io country validation)
# ══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, delay: float):
        self._delay        = delay
        self._lock         = threading.Lock()
        self._next_allowed = 0.0

    def wait(self):
        if self._delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now >= self._next_allowed:
                self._next_allowed = now + self._delay
                return
            sleep_until        = self._next_allowed
            self._next_allowed += self._delay
        remaining = sleep_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Central SQLite schema
# ══════════════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip              TEXT    PRIMARY KEY,
    hostname        TEXT,
    mac             TEXT,
    status          TEXT,
    os              TEXT,
    os_version      TEXT,
    os_accuracy     INTEGER,
    country_code    TEXT,
    country_filter  TEXT,
    flagged         INTEGER NOT NULL DEFAULT 0,
    flag_reason     TEXT,
    first_seen      TEXT    NOT NULL,
    last_scanned    TEXT,
    scan_status     TEXT    NOT NULL DEFAULT 'pending',
    scan_error      TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp',
    state       TEXT,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    extra_info  TEXT,
    banner      TEXT,
    scanned_at  TEXT,
    UNIQUE(ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    port        INTEGER,
    protocol    TEXT,
    cve         TEXT,
    cvss        REAL,
    severity    TEXT,
    title       TEXT,
    description TEXT,
    solution    TEXT,
    refs        TEXT,
    tool        TEXT,
    scanned_at  TEXT
);

CREATE TABLE IF NOT EXISTS scan_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    tool        TEXT,
    command     TEXT,
    exit_code   INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key     TEXT PRIMARY KEY,
    value   TEXT
);

CREATE INDEX IF NOT EXISTS idx_ports_ip       ON ports (ip);
CREATE INDEX IF NOT EXISTS idx_ports_port     ON ports (port, state);
CREATE INDEX IF NOT EXISTS idx_vulns_ip       ON vulns (ip);
CREATE INDEX IF NOT EXISTS idx_vulns_cve      ON vulns (cve);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns (severity);
CREATE INDEX IF NOT EXISTS idx_hosts_status   ON hosts (scan_status);
CREATE INDEX IF NOT EXISTS idx_hosts_os       ON hosts (os);
CREATE INDEX IF NOT EXISTS idx_hosts_country  ON hosts (country_code);
"""

_db_lock = threading.Lock()


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    # Any host stuck as 'scanning' from a previous interrupted run gets retried.
    conn.execute("UPDATE hosts SET scan_status = 'pending' WHERE scan_status = 'scanning'")
    conn.commit()
    return conn


def load_done(conn: sqlite3.Connection) -> set:
    return {r[0] for r in conn.execute("SELECT ip FROM hosts WHERE scan_status = 'done'")}


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Country validation
# ══════════════════════════════════════════════════════════════════════════════

def _clean(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s not in ("", "-", "N/A", "0.000000", "0") else None


def _local_cc(ip: str) -> str | None:
    db = _ipinfo_mod._load_db11()
    if not db:
        return None
    try:
        rec = db.get_all(ip)
        return _clean(_ipinfo_mod._safe(rec.country_short))
    except Exception:
        return None


def _online_cc(ip: str, rl: RateLimiter) -> str | None:
    rl.wait()
    if _quit_event.is_set():
        return None
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "10", f"ipinfo.io/{ip}"],
            capture_output=True, timeout=15,
        )
        raw = proc.stdout.decode(errors="replace").strip()
        if not raw:
            return None
        data = json.loads(raw)
        if data.get("bogon"):
            return None
        err = str(data.get("error", "")).lower()
        if data.get("status") == "429" or "rate limit" in err or "too many" in err:
            _pause_event.set()   # auto-pause on quota exhaustion
            return None
        return _clean(data.get("country"))
    except Exception:
        return None


def validate_country(
    ip: str, cf: str, rl: RateLimiter
) -> tuple[bool, str | None, str | None]:
    """Return (ok, local_cc, online_cc). ok only when both confirm cf."""
    lcc = _local_cc(ip)
    occ = _online_cc(ip, rl)
    ok  = (lcc == cf.upper() and occ == cf.upper())
    return ok, lcc, occ


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Tool checker
# ══════════════════════════════════════════════════════════════════════════════

def check_tools(use_searchsploit: bool):
    required = ["nmap", "curl"]
    if use_searchsploit:
        required.append("searchsploit")
    missing = []
    for t in required:
        try:
            subprocess.run([t, "--version"], capture_output=True, timeout=5)
        except FileNotFoundError:
            missing.append(t)
    if missing:
        for t in missing:
            print(f"[ERROR] missing tool: {t}", file=sys.stderr)
        print("[ERROR] Install with: apt install nmap exploitdb curl", file=sys.stderr)
        sys.exit(1)
    if not _IS_ROOT:
        print(
            f"{YELLOW}[WARN]{RESET} Not running as root — OS detection (-O) will be skipped.\n"
            f"       Re-run with sudo for full results.",
            file=sys.stderr,
        )


# ══════════════════════════════════════════════════════════════════════════════
# 6 — nmap runner + XML parser
# ══════════════════════════════════════════════════════════════════════════════

def _cvss_to_severity(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    if s >= 0.1: return "low"
    return "info"


_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _vulns_from_script(script_elem, port: int | None, proto: str | None) -> list:
    sid   = script_elem.get("id", "")
    sout  = script_elem.get("output", "").strip()
    vulns = []
    seen  = set()

    # Structured CVE tables (vulners.nse, vulscan.nse, etc.)
    for table in script_elem.findall(".//table"):
        key = table.get("key", "")
        if not _CVE_RE.match(key):
            continue
        cve = key.upper()
        if cve in seen:
            continue
        seen.add(cve)

        cvss_e = table.find(".//elem[@key='cvss']")
        cvss   = None
        if cvss_e is not None and cvss_e.text:
            try:
                cvss = float(cvss_e.text)
            except ValueError:
                pass

        desc_e = table.find(".//elem[@key='description']")
        desc   = (desc_e.text or "").strip() if desc_e is not None else ""
        href_e = table.find(".//elem[@key='href']")
        refs   = [href_e.text] if (href_e is not None and href_e.text) else []

        vulns.append({
            "port":        port,
            "protocol":    proto,
            "cve":         cve,
            "cvss":        cvss,
            "severity":    _cvss_to_severity(cvss),
            "title":       cve,
            "description": desc or sout[:400],
            "refs":        refs,
            "tool":        f"nmap:{sid}",
        })

    # Inline CVE mentions in script text output
    if not seen and sout:
        for cve in _CVE_RE.findall(sout):
            cve = cve.upper()
            if cve in seen:
                continue
            seen.add(cve)
            vulns.append({
                "port":        port,
                "protocol":    proto,
                "cve":         cve,
                "cvss":        None,
                "severity":    "unknown",
                "title":       cve,
                "description": sout[:400],
                "refs":        [],
                "tool":        f"nmap:{sid}",
            })

    # Non-CVE findings from known vuln-category scripts
    if not seen and sout:
        keywords = ("vulnerable", "exploit", "heartbleed", "eternalblue",
                    "shellshock", "weak cipher", "misconfigured")
        if any(kw in sout.lower() for kw in keywords):
            vulns.append({
                "port":        port,
                "protocol":    proto,
                "cve":         None,
                "cvss":        None,
                "severity":    "high" if "vulnerable" in sout.lower() else "medium",
                "title":       sid,
                "description": sout[:600],
                "refs":        [],
                "tool":        f"nmap:{sid}",
            })

    return vulns


def parse_nmap_xml(xml_bytes: bytes) -> dict:
    result = {
        "status":      "unknown",
        "hostname":    None,
        "os":          None,
        "os_version":  None,
        "os_accuracy": None,
        "ports":       [],
        "vulns":       [],
        "error":       None,
    }

    xml_str = (xml_bytes.decode(errors="replace") if isinstance(xml_bytes, bytes)
               else xml_bytes).strip()
    if not xml_str:
        result["error"] = "empty nmap output"
        return result

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        result["error"] = f"XML parse: {e}"
        return result

    host = root.find("host")
    if host is None:
        result["status"] = "down"
        return result

    st = host.find("status")
    if st is not None:
        result["status"] = st.get("state", "unknown")

    for hn in host.findall(".//hostname"):
        result["hostname"] = hn.get("name")
        break

    best_acc = -1
    for om in host.findall(".//osmatch"):
        acc = int(om.get("accuracy", 0))
        if acc > best_acc:
            best_acc          = acc
            result["os"]          = om.get("name")
            result["os_accuracy"] = acc
            oc = om.find("osclass")
            if oc is not None:
                fam = oc.get("osfamily", "")
                gen = oc.get("osgen", "")
                result["os_version"] = f"{fam} {gen}".strip() or None

    for pe in host.findall(".//port"):
        port_num = int(pe.get("portid", 0))
        proto    = pe.get("protocol", "tcp")
        st_e     = pe.find("state")
        state    = st_e.get("state", "unknown") if st_e is not None else "unknown"
        svc      = pe.find("service")
        service  = product = version = extra = None
        if svc is not None:
            service = svc.get("name")
            product = svc.get("product")
            version = svc.get("version")
            extra   = svc.get("extrainfo")

        result["ports"].append({
            "port":       port_num,
            "protocol":   proto,
            "state":      state,
            "service":    service,
            "product":    product,
            "version":    version,
            "extra_info": extra,
        })

        for script in pe.findall("script"):
            result["vulns"].extend(_vulns_from_script(script, port_num, proto))

    for script in host.findall("hostscript/script"):
        result["vulns"].extend(_vulns_from_script(script, None, None))

    return result


def run_nmap(ip: str, extra_args: list, timeout_sec: int) -> tuple[dict, str]:
    os_flag = ["-O"] if _IS_ROOT else []
    cmd     = (["nmap", "-sV"] + os_flag +
               ["--script=vuln", "-T4", "--open", "-oX", "-"] +
               extra_args + [ip])
    cmd_str = " ".join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout_sec)
        return parse_nmap_xml(proc.stdout), cmd_str
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out ({timeout_sec}s)",
                "ports": [], "vulns": [], "status": "unknown"}, cmd_str
    except FileNotFoundError:
        sys.exit("[ERROR] nmap not found — install: apt install nmap")
    except Exception as e:
        return {"error": str(e), "ports": [], "vulns": [], "status": "unknown"}, cmd_str


# ══════════════════════════════════════════════════════════════════════════════
# 7 — searchsploit  (optional enrichment)
# ══════════════════════════════════════════════════════════════════════════════

def run_searchsploit(product: str, version: str | None) -> list:
    if not product:
        return []
    query = f"{product} {version}".strip() if version else product
    try:
        proc = subprocess.run(
            ["searchsploit", "--id", query],
            capture_output=True, timeout=30,
        )
        out   = proc.stdout.decode(errors="replace")
        found = []
        for line in out.splitlines():
            if "|" not in line or line.startswith("-") or "Path" in line:
                continue
            title, eid = (line.split("|", 1) + [""])[:2]
            title = title.strip()
            eid   = eid.strip()
            cves  = _CVE_RE.findall(title)
            found.append({
                "cve":         cves[0].upper() if cves else None,
                "cvss":        None,
                "severity":    "unknown",
                "title":       title,
                "description": f"{query}: {title}",
                "refs":        ([f"https://www.exploit-db.com/exploits/{eid}"]
                                if eid.isdigit() else []),
                "tool":        "searchsploit",
            })
        return found
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# 8 — DB write helpers
# ══════════════════════════════════════════════════════════════════════════════

def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def ensure_host(conn: sqlite3.Connection, ip: str):
    with _db_lock:
        conn.execute(
            "INSERT OR IGNORE INTO hosts (ip, first_seen, scan_status) VALUES (?, ?, 'pending')",
            (ip, _now()),
        )
        conn.commit()


def _set_scan_status(conn: sqlite3.Connection, ip: str, status: str, error: str | None = None):
    with _db_lock:
        conn.execute(
            "UPDATE hosts SET scan_status = ?, scan_error = ?, last_scanned = ? WHERE ip = ?",
            (status, error, _now(), ip),
        )
        conn.commit()


def store_results(
    conn: sqlite3.Connection,
    ip: str,
    scan: dict,
    country_cc: str | None,
    country_filter: str | None,
    flagged: int,
    flag_reason: str | None,
    cmd: str,
    started_at: str,
):
    now        = _now()
    scan_error = scan.get("error")
    scan_done  = "error" if scan_error else "done"

    with _db_lock:
        conn.execute(
            """
            UPDATE hosts SET
                hostname       = COALESCE(?, hostname),
                status         = ?,
                os             = ?,
                os_version     = ?,
                os_accuracy    = ?,
                country_code   = ?,
                country_filter = ?,
                flagged        = ?,
                flag_reason    = ?,
                last_scanned   = ?,
                scan_status    = ?,
                scan_error     = ?
            WHERE ip = ?
            """,
            (
                scan.get("hostname"),
                scan.get("status", "unknown"),
                scan.get("os"),
                scan.get("os_version"),
                scan.get("os_accuracy"),
                country_cc,
                country_filter,
                flagged,
                flag_reason,
                now,
                scan_done,
                scan_error,
                ip,
            ),
        )

        for p in scan.get("ports", []):
            conn.execute(
                """
                INSERT INTO ports
                    (ip, port, protocol, state, service, product, version, extra_info, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    state      = excluded.state,
                    service    = excluded.service,
                    product    = excluded.product,
                    version    = excluded.version,
                    extra_info = excluded.extra_info,
                    scanned_at = excluded.scanned_at
                """,
                (
                    ip, p["port"], p["protocol"], p["state"],
                    p.get("service"), p.get("product"), p.get("version"),
                    p.get("extra_info"), now,
                ),
            )

        for v in scan.get("vulns", []):
            conn.execute(
                """
                INSERT INTO vulns
                    (ip, port, protocol, cve, cvss, severity,
                     title, description, refs, tool, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip, v.get("port"), v.get("protocol"),
                    v.get("cve"), v.get("cvss"), v.get("severity"),
                    v.get("title"), v.get("description"),
                    json.dumps(v.get("refs", [])),
                    v.get("tool"), now,
                ),
            )

        conn.execute(
            """
            INSERT INTO scan_log (ip, tool, command, started_at, finished_at)
            VALUES (?, 'nmap', ?, ?, ?)
            """,
            (ip, cmd, started_at, now),
        )
        conn.commit()


def store_skipped(
    conn: sqlite3.Connection,
    ip: str,
    country_cc: str | None,
    country_filter: str | None,
    flagged: int,
    flag_reason: str | None,
):
    with _db_lock:
        conn.execute(
            """
            UPDATE hosts SET
                country_code   = ?,
                country_filter = ?,
                flagged        = ?,
                flag_reason    = ?,
                scan_status    = 'skipped',
                last_scanned   = ?
            WHERE ip = ?
            """,
            (country_cc, country_filter, flagged, flag_reason, _now(), ip),
        )
        conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 9 — Input readers
# ══════════════════════════════════════════════════════════════════════════════

def iter_jsonl(path: Path):
    """Yield (ip, raw_record) from a fastcheck-style .jsonl file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = (rec.get("target") or rec.get("ip") or "").strip()
            if ip:
                yield ip, rec


def iter_ipdb(db_path: Path):
    """Yield (ip, meta_dict) for clean IPs (flagged=0) from an ipdb SQLite."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ip, fc_hostname, fc_mac, local_country_code FROM hosts WHERE flagged = 0"
    ).fetchall()
    conn.close()
    for row in rows:
        yield row["ip"], dict(row)


def count_source(source_iter) -> tuple[list, int]:
    """Materialise the source so we can show a total count."""
    items = list(source_iter)
    return items, len(items)


# ══════════════════════════════════════════════════════════════════════════════
# 10 — Display
# ══════════════════════════════════════════════════════════════════════════════

# Stage label + color (fixed width so columns stay aligned)
_STAGE_FMT = {
    "validate":    (DIM,     "verify  "),
    "scan":        (CYAN,    "nmap    "),
    "sploit":      (MAGENTA, "sploit  "),
    "store":       (DIM,     "store   "),
    "idle":        (DIM,     "idle    "),
}


class LiveDisplay:
    HEADER = 4   # rows 1-4: title bar
    FOOTER = 2   # rows -1,-2: stats + separator

    def __init__(self, total: int, workers: int, db_path: Path,
                 country_filter: str | None):
        cols, rows      = shutil.get_terminal_size((80, 24))
        self.total      = total
        self.cols       = cols
        self.rows       = rows
        self.n_workers  = workers
        # Worker panel sits between header and scroll area
        self._w_start   = self.HEADER + 1          # first worker row
        self._w_sep     = self._w_start + workers  # separator below workers
        self.v_start    = self._w_sep + 1           # scroll area top
        self.v_end      = max(self.v_start + 2, rows - self.FOOTER)
        self.f_sep      = self.v_end + 1
        self.f_stats    = self.v_end + 2

        self.lock           = threading.Lock()
        self.done           = 0
        self.n_ok           = 0
        self.n_skip         = 0
        self.n_err          = 0
        self._paused        = False
        self._thread_slots: dict[int, int] = {}   # thread_id → slot index
        self._workers:      dict[int, dict] = {}  # slot → {ip, stage, t0}
        self._ticker_stop   = threading.Event()

        o   = sys.stdout
        bar = "─" * cols
        cf_s = f"  filter: {YELLOW}{country_filter}{RESET}" if country_filter else ""

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")
        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  vault  ·  recon intelligence database{cf_s}{RESET}")
        self._at(3); o.write(f"  Targets: {total}  Workers: {workers}  →  {db_path}")
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        # Draw initial idle worker lines
        for slot in range(workers):
            self._draw_worker_line(slot)
        self._at(self._w_sep); o.write(f"{DIM}{bar}{RESET}")

        self._at(self.f_sep);  o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()
        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

        self._start_ticker()

    # ── internal helpers ──────────────────────────────────────────────────────

    def _at(self, row: int, col: int = 1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _draw_worker_line(self, slot: int):
        """Draw one worker-status line in place. Caller must hold self.lock."""
        w   = self._workers.get(slot)
        row = self._w_start + slot
        o   = sys.stdout
        self._at(row)
        o.write("\033[K")

        if w is None:
            color, label = _STAGE_FMT["idle"]
            o.write(f"  {DIM}○  {'—':<18}  {color}[ {label}]{RESET}")
        else:
            ip      = w["ip"]
            stage   = w["stage"]
            elapsed = time.monotonic() - w["t0"]
            mins    = int(elapsed) // 60
            secs    = int(elapsed) % 60
            color, label = _STAGE_FMT.get(stage, (DIM, stage[:8].ljust(8)))
            el_s = f"  {DIM}{mins:02d}:{secs:02d}{RESET}" if stage in ("scan", "sploit") else ""
            o.write(f"  {CYAN}●{RESET}  {ip:<18}  {color}[ {label}]{RESET}{el_s}")

    def _draw_stats(self):
        o    = sys.stdout
        pct  = self.done / self.total if self.total else 0
        bw   = max(10, min(28, self.cols - 62))
        fill = int(bw * pct)
        prog = f"{'█' * fill}{'░' * (bw - fill)}"
        self._at(self.f_stats)
        o.write("\033[K")
        base = (
            f"  {GREEN}Scanned: {self.n_ok:<6}{RESET}"
            f"  {YELLOW}Skipped: {self.n_skip:<6}{RESET}"
            f"  {RED}Errors: {self.n_err:<6}{RESET}"
            f"  {CYAN}[{prog}]{RESET}  {self.done}/{self.total}"
        )
        if self._paused:
            o.write(base + f"  {YELLOW}{BOLD}⏸ PAUSED{RESET}  ↵ resume  ·  Ctrl+C quit")
        else:
            o.write(base)

    def _start_ticker(self):
        """Background thread that refreshes worker elapsed times every second."""
        def _tick():
            while not self._ticker_stop.wait(1.0):
                with self.lock:
                    for slot in list(self._workers):
                        self._draw_worker_line(slot)
                    self._at(self.v_end)
                    sys.stdout.flush()
        threading.Thread(target=_tick, daemon=True).start()

    # ── public API ────────────────────────────────────────────────────────────

    def update_worker(self, ip: str, stage: str):
        """Update the status panel for the calling worker thread."""
        tid = threading.get_ident()
        now = time.monotonic()
        with self.lock:
            if tid not in self._thread_slots:
                self._thread_slots[tid] = len(self._thread_slots)
            slot = self._thread_slots[tid]

            if stage == "idle":
                self._workers.pop(slot, None)
            else:
                prev = self._workers.get(slot, {})
                if prev.get("ip") != ip or prev.get("stage") != stage:
                    self._workers[slot] = {"ip": ip, "stage": stage, "t0": now}

            self._draw_worker_line(slot)
            self._at(self.v_end)
            sys.stdout.flush()

    def set_paused(self, paused: bool):
        with self.lock:
            self._paused = paused
            self._draw_stats()
            self._at(self.v_end)
            sys.stdout.flush()

    def add_result(self, ip: str, outcome: str, detail: str):
        with self.lock:
            self.done += 1
            if outcome == "ok":
                self.n_ok += 1
                st_s = f"{GREEN}SCAN {RESET}"
            elif outcome == "skip":
                self.n_skip += 1
                st_s = f"{YELLOW}SKIP {RESET}"
            else:
                self.n_err += 1
                st_s = f"{RED}ERR  {RESET}"

            w       = len(str(self.total))
            counter = f"{CYAN}[{self.done:{w}}/{self.total}]{RESET}"
            line    = f"{counter}  {ip:<18}  {st_s}  {DIM}{detail}{RESET}"

            o = sys.stdout
            self._at(self.v_end, 1)
            o.write("\n\033[K")
            o.write(line)
            self._draw_stats()
            self._at(self.v_end)
            o.flush()

    def finish(self):
        self._ticker_stop.set()
        with self.lock:
            o = sys.stdout
            o.write("\033[r\033[?7h\033[?25h")
            self._at(self.rows)
            o.write("\n")
            o.flush()


class SimpleDisplay:
    _STAGE_LABELS = {
        "validate": "checking country ...",
        "scan":     "nmap scan started   ",
        "sploit":   "searchsploit ...    ",
        "store":    "storing results     ",
        "idle":     None,
    }

    def __init__(self, total: int, workers: int, db_path: Path,
                 country_filter: str | None):
        self.total  = total
        self.lock   = threading.Lock()
        self.done   = 0
        self.n_ok   = 0
        self.n_skip = 0
        self.n_err  = 0
        cf_s = f"  filter: {country_filter}" if country_filter else ""
        bar  = "─" * 62
        print(f"\n{bar}")
        print(f"  vault  ·  recon intelligence database{cf_s}")
        print(f"  Targets: {total}  Workers: {workers}  →  {db_path}")
        print(f"{bar}\n")

    def update_worker(self, ip: str, stage: str):
        label = self._STAGE_LABELS.get(stage)
        if label:
            print(f"         {ip:<18}  {label}")

    def set_paused(self, paused: bool):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def add_result(self, ip: str, outcome: str, detail: str):
        with self.lock:
            self.done += 1
            if outcome == "ok":
                self.n_ok += 1; st = "SCAN"
            elif outcome == "skip":
                self.n_skip += 1; st = "SKIP"
            else:
                self.n_err += 1; st = "ERR"
            w = len(str(self.total))
            print(f"[{self.done:{w}}/{self.total}]  {ip:<18}  {st:<5}  {detail}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 11 — Per-IP task
# ══════════════════════════════════════════════════════════════════════════════

def process_ip(
    ip: str,
    conn: sqlite3.Connection,
    country_filter: str | None,
    rl: RateLimiter,
    nmap_extra: list,
    nmap_timeout: int,
    use_searchsploit: bool,
    display,
) -> None:
    if not wait_if_paused(display):
        return
    if _quit_event.is_set():
        return

    ensure_host(conn, ip)

    # ── Country validation ────────────────────────────────────────────────────
    flagged     = 0
    flag_reason = None
    country_cc  = None

    if country_filter:
        display.update_worker(ip, "validate")
        ok, lcc, occ = validate_country(ip, country_filter, rl)
        country_cc   = lcc or occ
        if not ok:
            flagged     = 1
            flag_reason = ("COUNTRY_MISMATCH"
                           if (lcc and occ) else "VERIFICATION_INCOMPLETE")
            store_skipped(conn, ip, country_cc, country_filter, flagged, flag_reason)
            display.update_worker(ip, "idle")
            display.add_result(
                ip, "skip",
                f"L:{lcc or '?'}  O:{occ or '?'}  {flag_reason}",
            )
            return
        country_cc = lcc
    else:
        country_cc = _local_cc(ip)

    if not wait_if_paused(display):
        return
    if _quit_event.is_set():
        return

    # ── Nmap scan ─────────────────────────────────────────────────────────────
    display.update_worker(ip, "scan")
    _set_scan_status(conn, ip, "scanning")
    started_at = _now()
    scan, cmd  = run_nmap(ip, nmap_extra, nmap_timeout)

    # ── searchsploit enrichment ───────────────────────────────────────────────
    if use_searchsploit and not scan.get("error"):
        display.update_worker(ip, "sploit")
        seen_products: set = set()
        extra_vulns: list  = []
        for p in scan.get("ports", []):
            product = p.get("product")
            version = p.get("version")
            if product and product not in seen_products:
                seen_products.add(product)
                for v in run_searchsploit(product, version):
                    v["port"]     = p["port"]
                    v["protocol"] = p["protocol"]
                    extra_vulns.append(v)
        scan.setdefault("vulns", []).extend(extra_vulns)

    display.update_worker(ip, "store")
    store_results(
        conn, ip, scan, country_cc, country_filter,
        flagged, flag_reason, cmd, started_at,
    )

    n_ports = len(scan.get("ports", []))
    n_vulns = len(scan.get("vulns", []))
    os_s    = (scan.get("os") or "")[:24]
    err     = scan.get("error")

    display.update_worker(ip, "idle")
    if err:
        display.add_result(ip, "error", f"nmap: {err[:55]}")
    else:
        detail = f"{n_ports} port(s)  {n_vulns} vuln(s)"
        if os_s:
            detail += f"  [{os_s}]"
        display.add_result(ip, "ok", detail)


# ══════════════════════════════════════════════════════════════════════════════
# 12 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Central recon intelligence database — scan, store, share.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python vault.py -f targets.jsonl --country US\n"
            "  python vault.py -f targets.jsonl --country US -w 3\n"
            "  python vault.py -f targets.jsonl --country US --searchsploit\n"
            "  python vault.py -f targets.jsonl --country US --nmap-args \"-p- -T3\"\n"
            "  python vault.py --from-ipdb ipdb.sqlite --country US\n"
            "  python vault.py -f targets.jsonl              # no country filter\n"
            "\n"
            "Reporting:\n"
            "  python vreport.py --by port\n"
            "  python vreport.py --by cve\n"
            "  python vreport.py --by os\n"
        ),
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file", metavar="JSONL",
        help="fastcheck / plain .jsonl input file (target or ip field per line)")
    src.add_argument("--from-ipdb", metavar="SQLITE",
        help="Read clean IPs (flagged=0) directly from an ipdb SQLite database")

    parser.add_argument("--db", metavar="FILE", default=None,
        help="vault SQLite path (default: vault.sqlite next to this script)")
    parser.add_argument("--country", metavar="CC",
        help="Two-letter country code to enforce. Both local and online must confirm.")
    parser.add_argument("-w", "--workers", type=int, default=5, metavar="N",
        help="Concurrent targets (default: 5)")
    parser.add_argument("--nmap-args", metavar="ARGS", default="",
        help='Extra nmap arguments in one quoted string (e.g. "--nmap-args \"-p- -T3\"")')
    parser.add_argument("--timeout", type=int, default=600, metavar="SEC",
        help="Per-host nmap timeout in seconds (default: 600)")
    parser.add_argument("--online-delay", type=float, default=1.5, metavar="SEC",
        help="Minimum seconds between ipinfo.io requests (default: 1.5)")
    parser.add_argument("--searchsploit", action="store_true",
        help="Cross-reference found services with searchsploit for additional CVEs")
    parser.add_argument("--all", action="store_true",
        help="Process all hosts in JSONL, not only those with status='up'")

    args = parser.parse_args()

    check_tools(args.searchsploit)

    db_path        = (Path(args.db) if args.db
                      else Path(__file__).resolve().parent / "vault.sqlite")
    country_filter = args.country.strip().upper() if args.country else None
    nmap_extra     = shlex.split(args.nmap_args) if args.nmap_args else []

    conn = open_db(db_path)
    done = load_done(conn)

    # Build source list
    if args.from_ipdb:
        raw_source = list(iter_ipdb(Path(args.from_ipdb)))
    else:
        src_path = Path(args.file)
        if not src_path.exists():
            conn.close()
            sys.exit(f"[ERROR] File not found: {src_path}")
        up_only = not args.all
        raw_source = [
            (ip, rec)
            for ip, rec in iter_jsonl(src_path)
            if (not up_only or rec.get("status") == "up")
        ]

    pending = [(ip, rec) for ip, rec in raw_source if ip not in done]

    if not raw_source:
        conn.close()
        sys.exit("[ERROR] No targets found. Check the input file or add --all.")

    if done:
        print(f"  Resume: {len(done):,} already done, {len(pending):,} remaining.")

    if not pending:
        print("  Nothing to do — all targets already scanned.")
        conn.close()
        return

    rl = RateLimiter(args.online_delay)
    signal.signal(signal.SIGINT, _sigint_handler)

    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(len(pending), args.workers, db_path, country_filter)

    MAX_PENDING = args.workers * 4

    def _task(ip, rec):
        process_ip(
            ip, conn, country_filter, rl,
            nmap_extra, args.timeout, args.searchsploit, display,
        )

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen     = iter(pending)
            futures = set()
            for ip, rec in itertools.islice(gen, MAX_PENDING):
                futures.add(pool.submit(_task, ip, rec))

            while futures and not _quit_event.is_set():
                done_futs, futures = fut_wait(futures, return_when=FIRST_COMPLETED)
                for f in done_futs:
                    f.result()
                if not _quit_event.is_set():
                    for ip, rec in itertools.islice(gen, len(done_futs)):
                        futures.add(pool.submit(_task, ip, rec))

    except Exception:
        pass
    finally:
        display.finish()
        conn.close()

    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  vault summary{RESET}")
    print(f"  {GREEN}Scanned : {display.n_ok}{RESET}")
    print(f"  {YELLOW}Skipped : {display.n_skip}{RESET}  (country mismatch / incomplete)")
    print(f"  {RED}Errors  : {display.n_err}{RESET}  (nmap failed)")
    print(f"  Total   : {display.done}")
    if country_filter:
        print(f"  Filter  : --country {country_filter}")
    print(f"  DB      : {db_path}")
    if _quit_event.is_set():
        print(f"\n  {YELLOW}Stopped — re-run the same command to continue.{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
