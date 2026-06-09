#!/usr/bin/env python3
"""
ipdb.py  —  IP intelligence database builder
============================================
Reads fastcheck .jsonl output, enriches every 'up' host with geo data from
two independent sources, cross-validates them, and stores all results in a
SQLite database for downstream recon and attack tooling.

Sources
  local   — IP2Location binary databases via the project's ipinfo module
             (zero network traffic; fast)
  online  — curl ipinfo.io/<ip>
             (rate-limited — see --online-delay; free tier: ~50k req/month)

Flagging  (stored as  flagged=1  in the database)
  With --country CC
    Either source is unavailable                  →  VERIFICATION_INCOMPLETE
    Either source reports a country code != CC    →  COUNTRY_MISMATCH
    Flagged IPs must not be used for further recon / attacks.
  Without --country
    Either source is unavailable                  →  VERIFICATION_INCOMPLETE
    Both available but codes disagree             →  COUNTRY_MISMATCH

Usage
  python ipdb.py -f fastcheck.jsonl
  python ipdb.py -f fastcheck.jsonl --country US
  python ipdb.py -f fastcheck.jsonl --country US --db targets.sqlite
  python ipdb.py -f fastcheck.jsonl -w 8 --online-delay 2.0
  python ipdb.py -f fastcheck.jsonl --all     # include down hosts too

Pause / resume
  Ctrl+C      pause  (workers finish their current IP, then wait)
  Enter       resume
  Ctrl+C      quit while paused
  Re-run      already-processed IPs are skipped (SQLite is the checkpoint)
"""

import sys
import json
import time
import signal
import shutil
import sqlite3
import argparse
import subprocess
import threading
import itertools
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait as fut_wait
from pathlib import Path

# ── Import ipinfo from the sibling directory ──────────────────────────────────
# This script lives at  reconn/ipdb/ipdb.py
# ipinfo.py lives at    reconn/ipinfo/ipinfo.py
_IPINFO_DIR = Path(__file__).resolve().parent.parent / "ipinfo"
if str(_IPINFO_DIR) not in sys.path:
    sys.path.insert(0, str(_IPINFO_DIR))

try:
    import ipinfo as _ipinfo_mod
except ImportError as e:
    sys.exit(
        f"[ERROR] Cannot import ipinfo module from {_IPINFO_DIR}\n"
        f"        {e}\n"
        f"        Install dependencies:  pip install IP2Location IP2Proxy python-dotenv requests"
    )

# ── ANSI ──────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Pause / quit  (same pattern as fastcheck / scantop100)
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
# 2 — Rate limiter for ipinfo.io requests
# ══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """
    Enforces a minimum gap between online requests.
    Each caller books a time slot under the lock (fast), then sleeps outside
    it — so all N workers can book their slots concurrently without blocking
    each other during the sleep phase.
    """

    def __init__(self, delay: float):
        self._delay        = delay
        self._lock         = threading.Lock()
        self._next_allowed = 0.0   # monotonic timestamp of next open slot

    def wait(self):
        if self._delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now >= self._next_allowed:
                self._next_allowed = now + self._delay
                return                   # slot is now — go immediately
            sleep_until        = self._next_allowed
            self._next_allowed += self._delay
        remaining = sleep_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — SQLite
# ══════════════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip                  TEXT    PRIMARY KEY,
    first_seen          TEXT    NOT NULL,
    last_updated        TEXT    NOT NULL,

    -- fastcheck source metadata
    fc_status           TEXT,
    fc_latency_ms       REAL,
    fc_hostname         TEXT,
    fc_mac              TEXT,
    fc_source           TEXT,

    -- local IP2Location lookup
    local_country_code  TEXT,
    local_country       TEXT,
    local_region        TEXT,
    local_city          TEXT,
    local_lat           TEXT,
    local_lon           TEXT,
    local_isp           TEXT,
    local_asn           TEXT,
    local_asn_name      TEXT,
    local_error         TEXT,

    -- online ipinfo.io lookup
    online_country_code TEXT,
    online_country      TEXT,
    online_region       TEXT,
    online_city         TEXT,
    online_lat          TEXT,
    online_lon          TEXT,
    online_org          TEXT,
    online_hostname     TEXT,
    online_timezone     TEXT,
    online_status       TEXT,
    online_error        TEXT,

    -- cross-validation result
    flagged             INTEGER NOT NULL DEFAULT 0,
    flag_reason         TEXT,
    country_filter      TEXT,

    -- future: port / OS / vuln data  (filled by future tools)
    ports_json          TEXT,
    os_detected         TEXT,
    vulns_json          TEXT,
    last_port_scan      TEXT,
    last_vuln_scan      TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_flagged   ON hosts (flagged);
CREATE INDEX IF NOT EXISTS idx_country   ON hosts (local_country_code, online_country_code);
CREATE INDEX IF NOT EXISTS idx_fc_status ON hosts (fc_status);
"""

# Columns updated on conflict — excludes ip (PK) and first_seen (preserved).
_UPDATE_COLS = [
    "last_updated",
    "fc_status", "fc_latency_ms", "fc_hostname", "fc_mac", "fc_source",
    "local_country_code", "local_country", "local_region", "local_city",
    "local_lat", "local_lon", "local_isp", "local_asn", "local_asn_name",
    "local_error",
    "online_country_code", "online_country", "online_region", "online_city",
    "online_lat", "online_lon", "online_org", "online_hostname",
    "online_timezone", "online_status", "online_error",
    "flagged", "flag_reason", "country_filter",
]

_INSERT_COLS = ["ip", "first_seen"] + _UPDATE_COLS

_db_lock = threading.Lock()


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def load_processed(conn: sqlite3.Connection) -> set:
    return {r[0] for r in conn.execute("SELECT ip FROM hosts")}


def upsert_host(conn: sqlite3.Connection, record: dict):
    """Insert or update, preserving first_seen on conflict."""
    placeholders  = ", ".join(["?"] * len(_INSERT_COLS))
    update_clause = ", ".join(f"{c} = excluded.{c}" for c in _UPDATE_COLS)
    sql = (
        f"INSERT INTO hosts ({', '.join(_INSERT_COLS)}) VALUES ({placeholders})\n"
        f"ON CONFLICT(ip) DO UPDATE SET {update_clause}"
    )
    vals = [record.get(c) for c in _INSERT_COLS]
    with _db_lock:
        conn.execute(sql, vals)
        conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 4 — fastcheck JSONL reader
# ══════════════════════════════════════════════════════════════════════════════

def iter_fastcheck(path: Path, up_only: bool = True):
    """Yield (ip, record) from a fastcheck .jsonl; skips non-up hosts by default."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = rec.get("target", "").strip()
            if not ip:
                continue
            if up_only and rec.get("status") != "up":
                continue
            yield ip, rec


def count_fastcheck(path: Path, up_only: bool = True) -> int:
    return sum(1 for _ in iter_fastcheck(path, up_only=up_only))


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Geo lookups
# ══════════════════════════════════════════════════════════════════════════════

def _clean(v) -> str | None:
    """Normalise IP2Location / ipinfo.io "no data" sentinel values to None."""
    if v is None:
        return None
    s = str(v).strip()
    return s if s not in ("", "-", "N/A", "0.000000", "0") else None


def local_lookup(ip: str) -> dict:
    """Query geo (DB11) and ASN databases only — proxy DB is not used."""

    def s(v) -> str | None:
        return _clean(_ipinfo_mod._safe(v))

    # ── Geo (DB11) ────────────────────────────────────────────────────────────
    cc = country = region = city = lat = lon = isp = error = None
    db = _ipinfo_mod._load_db11()
    if db:
        try:
            rec     = db.get_all(ip)
            cc      = s(rec.country_short)
            country = s(rec.country_long)
            region  = s(rec.region)
            city    = s(rec.city)
            lat     = s(rec.latitude)
            lon     = s(rec.longitude)
            isp     = s(rec.isp)
        except Exception as e:
            error = str(e)
    else:
        error = "DB11 not loaded — run: python ipinfo.py --update"

    # ── ASN ───────────────────────────────────────────────────────────────────
    asn = asn_name = None
    adb = _ipinfo_mod._load_asn()
    if adb:
        try:
            arec     = adb.get_all(ip)
            as_name  = (arec.as_name if hasattr(arec, "as_name")
                        else getattr(arec, "asn", None))
            asn      = s(arec.asn)
            asn_name = s(as_name)
        except Exception:
            pass    # ASN is supplementary; don't block on it

    return {
        "country_code": cc,
        "country":      country,
        "region":       region,
        "city":         city,
        "lat":          lat,
        "lon":          lon,
        "isp":          isp,
        "asn":          asn,
        "asn_name":     asn_name,
        "error":        error,
    }


def online_lookup(ip: str, rate_limiter: RateLimiter) -> dict:
    """Fetch geo data from ipinfo.io via curl; enforces rate limit before calling."""
    rate_limiter.wait()
    if _quit_event.is_set():
        return {"status": "aborted", "error": "quit requested"}
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", "10", f"ipinfo.io/{ip}"],
            capture_output=True, timeout=15,
        )
        raw = proc.stdout.decode(errors="replace").strip()
        if not raw:
            return {"status": "empty", "error": "empty response from ipinfo.io"}

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "error", "error": f"non-JSON response ({len(raw)} bytes)"}

        # Bogon / private IP — no geo data available
        if data.get("bogon"):
            return {"status": "bogon", "error": "bogon/private IP", "country_code": None}

        # Rate-limit response: {"status":"429","error":"..."}
        err_str = str(data.get("error", "")).lower()
        if data.get("status") == "429" or "rate limit" in err_str or "too many" in err_str:
            return {"status": "rate_limited", "error": data.get("error", "rate limit exceeded")}

        # Any other error field (e.g. {"error":"invalid IP"})
        if "error" in data and "country" not in data:
            return {"status": "error", "error": str(data["error"])}

        # Parse "loc": "lat,lon"
        loc = data.get("loc", "")
        lat = lon = None
        if loc and "," in loc:
            parts = loc.split(",", 1)
            lat, lon = _clean(parts[0]), _clean(parts[1])

        return {
            "status":       "ok",
            "country_code": _clean(data.get("country")),
            "country":      None,           # ipinfo.io free tier: CC only, no full name
            "region":       _clean(data.get("region")),
            "city":         _clean(data.get("city")),
            "lat":          lat,
            "lon":          lon,
            "org":          _clean(data.get("org")),
            "hostname":     _clean(data.get("hostname")),
            "timezone":     _clean(data.get("timezone")),
            "error":        None,
        }

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "curl timed out"}
    except FileNotFoundError:
        sys.exit("[ERROR] curl not found — install it: brew install curl / apt install curl")
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# 6 — Flagging logic
# ══════════════════════════════════════════════════════════════════════════════

def _verify(
    local: dict,
    online: dict,
    country_filter: str | None,
) -> tuple[int, str | None]:
    """
    Return (flagged: 0|1, flag_reason: str|None).

    With --country CC:
      Either source unavailable or disagrees with CC  →  flagged
    Without --country:
      Either source unavailable                       →  VERIFICATION_INCOMPLETE
      Both available but country codes differ         →  COUNTRY_MISMATCH
    """
    local_cc  = (local.get("country_code") or "").strip().upper()
    online_cc = (online.get("country_code") or "").strip().upper()
    local_ok  = not local.get("error") and bool(local_cc)
    online_ok = online.get("status") == "ok" and bool(online_cc)

    if not local_ok or not online_ok:
        return 1, "VERIFICATION_INCOMPLETE"

    cf = (country_filter or "").strip().upper()
    if cf:
        if local_cc != cf or online_cc != cf:
            return 1, "COUNTRY_MISMATCH"
        return 0, None

    if local_cc != online_cc:
        return 1, "COUNTRY_MISMATCH"
    return 0, None


# ══════════════════════════════════════════════════════════════════════════════
# 7 — Display
# ══════════════════════════════════════════════════════════════════════════════

class LiveDisplay:
    HEADER = 4
    FOOTER = 3

    def __init__(self, total: int, workers: int, online_delay: float,
                 db_path: Path, country_filter: str | None):
        cols, rows = shutil.get_terminal_size((80, 24))
        self.total     = total
        self.cols      = cols
        self.rows      = rows
        self.v_start   = self.HEADER + 1
        self.v_end     = max(self.v_start + 2, rows - self.FOOTER)
        self.f_sep     = self.v_end + 1
        self.f_stats   = self.v_end + 2
        self.lock      = threading.Lock()
        self.done      = 0
        self.n_clean   = 0
        self.n_flagged = 0
        self._paused   = False

        o   = sys.stdout
        bar = "─" * cols
        cf_s = f"  filter: {YELLOW}{country_filter}{RESET}" if country_filter else ""

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")

        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  ipdb  ·  IP intelligence database builder{cf_s}{RESET}")
        self._at(3)
        o.write(f"  Targets: {total}  Workers: {workers}  "
                f"Online delay: {online_delay}s  →  {db_path}")
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        self._at(self.f_sep);  o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()
        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

    def _at(self, row: int, col: int = 1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _draw_stats(self):
        o    = sys.stdout
        pct  = self.done / self.total if self.total else 0
        bw   = max(10, min(30, self.cols - 60))
        fill = int(bw * pct)
        prog = f"{'█' * fill}{'░' * (bw - fill)}"
        self._at(self.f_stats)
        o.write("\033[K")
        base = (
            f"  {GREEN}Clean: {self.n_clean:<6}{RESET}"
            f"  {RED}Flagged: {self.n_flagged:<6}{RESET}"
            f"  {CYAN}[{prog}]{RESET}"
            f"  {self.done}/{self.total}"
        )
        if self._paused:
            o.write(base + f"  {YELLOW}{BOLD}⏸ PAUSED{RESET}  ↵ resume  ·  Ctrl+C quit")
        else:
            o.write(base)

    def set_paused(self, paused: bool):
        with self.lock:
            self._paused = paused
            self._draw_stats()
            self._at(self.v_end)
            sys.stdout.flush()

    def add_result(self, ip: str, flagged: int, flag_reason: str | None,
                   local_cc: str, online_cc: str):
        with self.lock:
            self.done += 1
            if flagged:
                self.n_flagged += 1
            else:
                self.n_clean += 1

            w       = len(str(self.total))
            counter = f"{CYAN}[{self.done:{w}}/{self.total}]{RESET}"

            if flagged:
                st_s  = f"{RED}{BOLD}FLAG{RESET}"
                extra = f"  {RED}{flag_reason}{RESET}"
            else:
                st_s  = f"{GREEN}OK  {RESET}"
                extra = ""

            cc_s = f"{DIM}L:{local_cc or '?':2}  O:{online_cc or '?':2}{RESET}"
            line = f"{counter}  {ip:<18}  {st_s}  {cc_s}{extra}"

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
    def __init__(self, total: int, workers: int, online_delay: float,
                 db_path: Path, country_filter: str | None):
        self.total     = total
        self.lock      = threading.Lock()
        self.done      = 0
        self.n_clean   = 0
        self.n_flagged = 0
        cf_s = f"  filter: {country_filter}" if country_filter else ""
        bar  = "─" * 62
        print(f"\n{bar}")
        print(f"  ipdb  ·  IP intelligence database builder{cf_s}")
        print(f"  Targets: {total}  Workers: {workers}  "
              f"Online delay: {online_delay}s  →  {db_path}")
        print(f"{bar}\n")

    def set_paused(self, paused: bool):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def add_result(self, ip: str, flagged: int, flag_reason: str | None,
                   local_cc: str, online_cc: str):
        with self.lock:
            self.done += 1
            if flagged:
                self.n_flagged += 1
            else:
                self.n_clean += 1
            w      = len(str(self.total))
            status = f"FLAG({flag_reason})" if flagged else "OK"
            print(f"[{self.done:{w}}/{self.total}]  {ip:<18}  {status:<35}  "
                  f"L:{local_cc or '?':2}  O:{online_cc or '?':2}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 8 — Per-IP processing task
# ══════════════════════════════════════════════════════════════════════════════

def process_ip(
    ip: str,
    fc_rec: dict,
    conn: sqlite3.Connection,
    rate_limiter: RateLimiter,
    country_filter: str | None,
    source_name: str,
    display,
) -> None:
    if not wait_if_paused(display):
        return
    if _quit_event.is_set():
        return

    now = datetime.now(tz=timezone.utc).isoformat()

    local  = local_lookup(ip)
    online = online_lookup(ip, rate_limiter)

    flagged, flag_reason = _verify(local, online, country_filter)

    record = {
        "ip":           ip,
        "first_seen":   now,
        "last_updated": now,

        "fc_status":     fc_rec.get("status"),
        "fc_latency_ms": fc_rec.get("latency_ms"),
        "fc_hostname":   fc_rec.get("hostname"),
        "fc_mac":        fc_rec.get("mac"),
        "fc_source":     source_name,

        "local_country_code": local.get("country_code"),
        "local_country":      local.get("country"),
        "local_region":       local.get("region"),
        "local_city":         local.get("city"),
        "local_lat":          local.get("lat"),
        "local_lon":          local.get("lon"),
        "local_isp":          local.get("isp"),
        "local_asn":          local.get("asn"),
        "local_asn_name":     local.get("asn_name"),
        "local_error":        local.get("error"),

        "online_country_code": online.get("country_code"),
        "online_country":      online.get("country"),
        "online_region":       online.get("region"),
        "online_city":         online.get("city"),
        "online_lat":          online.get("lat"),
        "online_lon":          online.get("lon"),
        "online_org":          online.get("org"),
        "online_hostname":     online.get("hostname"),
        "online_timezone":     online.get("timezone"),
        "online_status":       online.get("status"),
        "online_error":        online.get("error"),

        "flagged":        flagged,
        "flag_reason":    flag_reason,
        "country_filter": country_filter,
    }

    upsert_host(conn, record)
    display.add_result(
        ip, flagged, flag_reason,
        local.get("country_code") or "",
        online.get("country_code") or "",
    )


# ══════════════════════════════════════════════════════════════════════════════
# 9 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def _check_curl():
    try:
        subprocess.run(["curl", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        sys.exit("[ERROR] curl not found — install it: brew install curl / apt install curl")


def main():
    parser = argparse.ArgumentParser(
        prog="ipdb",
        description="Build an IP intelligence SQLite database from fastcheck results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ipdb.py -f fastcheck.jsonl\n"
            "  python ipdb.py -f fastcheck.jsonl --country US\n"
            "  python ipdb.py -f fastcheck.jsonl --country US --db targets.sqlite\n"
            "  python ipdb.py -f fastcheck.jsonl -w 8 --online-delay 2.0\n"
            "  python ipdb.py -f fastcheck.jsonl --all\n"
        ),
    )
    parser.add_argument(
        "-f", "--file", required=True, metavar="JSONL",
        help="fastcheck .jsonl input file.",
    )
    parser.add_argument(
        "--db", metavar="FILE", default=None,
        help="SQLite output path (default: ipdb.sqlite next to this script).",
    )
    parser.add_argument(
        "--country", metavar="CC",
        help=(
            "Two-letter country code to enforce (e.g. US, DE, CN). "
            "Both sources must confirm this code for flagged=0. "
            "Any disagreement — or unavailable source — sets flagged=1."
        ),
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=5, metavar="N",
        help=(
            "Worker threads (default: 5). "
            "Online requests share a rate-limited slot, so throughput is "
            "1 / --online-delay req/s regardless of worker count. "
            "More workers help parallelise local lookups and DB writes."
        ),
    )
    parser.add_argument(
        "--online-delay", type=float, default=1.5, metavar="SEC",
        help=(
            "Minimum seconds between ipinfo.io requests (default: 1.5). "
            "Set to 0 to disable the delay (risk: 429 rate limiting). "
            "Rate-limited responses are stored as online_status=rate_limited "
            "and flagged=1 so they can be retried on the next run."
        ),
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Process all hosts in the JSONL, not only 'up' ones (default: up only).",
    )

    args = parser.parse_args()

    _check_curl()

    src_path = Path(args.file)
    if not src_path.exists():
        sys.exit(f"[ERROR] File not found: {src_path}")

    db_path        = Path(args.db) if args.db else Path(__file__).resolve().parent / "ipdb.sqlite"
    country_filter = args.country.strip().upper() if args.country else None
    up_only        = not args.all

    # ── Count ─────────────────────────────────────────────────────────────────
    print(f"  Scanning {src_path} …", end="", flush=True)
    total = count_fastcheck(src_path, up_only=up_only)
    print(f" {total:,} hosts")

    if total == 0:
        sys.exit("[ERROR] No hosts found. Check the input file or add --all.")

    # ── Open DB and detect already-processed IPs (resume) ────────────────────
    conn      = open_db(db_path)
    processed = load_processed(conn)
    remaining = total - len(processed)

    if processed:
        print(f"  Resume: {len(processed):,} already in DB, {remaining:,} remaining.")

    if remaining == 0:
        print("  Nothing to do — all hosts already in the database.")
        conn.close()
        return

    # ── Kick off ──────────────────────────────────────────────────────────────
    rate_limiter = RateLimiter(args.online_delay)
    signal.signal(signal.SIGINT, _sigint_handler)

    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(remaining, args.workers, args.online_delay, db_path, country_filter)

    source_name = src_path.name
    MAX_PENDING = args.workers * 4

    def _task(ip, fc_rec):
        process_ip(ip, fc_rec, conn, rate_limiter, country_filter, source_name, display)

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen = (
                (ip, rec)
                for ip, rec in iter_fastcheck(src_path, up_only=up_only)
                if ip not in processed
            )
            pending = set()
            for ip, rec in itertools.islice(gen, MAX_PENDING):
                pending.add(pool.submit(_task, ip, rec))

            while pending and not _quit_event.is_set():
                done_futs, pending = fut_wait(pending, return_when=FIRST_COMPLETED)
                for f in done_futs:
                    f.result()
                if not _quit_event.is_set():
                    for ip, rec in itertools.islice(gen, len(done_futs)):
                        pending.add(pool.submit(_task, ip, rec))

    except Exception:
        pass
    finally:
        display.finish()
        conn.close()

    # ── Summary ───────────────────────────────────────────────────────────────
    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  ipdb summary{RESET}")
    print(f"  {GREEN}Clean   : {display.n_clean}{RESET}")
    print(f"  {RED}Flagged : {display.n_flagged}{RESET}")
    print(f"  Total   : {display.done}")
    if country_filter:
        print(f"  Filter  : --country {country_filter}")
    print(f"  DB      : {db_path}")
    if _quit_event.is_set():
        print(f"\n  {YELLOW}Stopped — re-run the same command to resume.{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
