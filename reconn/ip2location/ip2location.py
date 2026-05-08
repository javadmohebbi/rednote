#!/usr/bin/env python3
"""
ip2location.py  —  query any IP2Location LITE database
=======================================================
Download a database once; all lookups run offline against local .BIN files.

  python ip2location.py --list                      # see what's available / downloaded
  python ip2location.py --download DB11 ASN PX7     # download databases
  python ip2location.py 8.8.8.8                     # query (uses all downloaded DBs)
  python ip2location.py --db PX7 8.8.8.8 1.1.1.1   # query a specific database
  python ip2location.py --json 8.8.8.8              # JSON output

Prerequisites
  pip install IP2Location IP2Proxy python-dotenv requests

.env file (same folder as this script)
  IP2LOCATION_TOKEN=<your token>          # required for --download / --update
  # IP2LOCATION_DB_DIR=/opt/databases    # optional: override where .BIN files live
"""

import sys
import os
import io
import csv
import json
import socket
import zipfile
import argparse
from pathlib import Path
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit("[ERROR] Run:  pip install python-dotenv")

try:
    import requests
except ImportError:
    sys.exit("[ERROR] Run:  pip install requests")


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Configuration
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env", override=False)

DOWNLOAD_TOKEN    = os.environ.get("IP2LOCATION_TOKEN", "")
DB_DIR            = Path(os.environ.get("IP2LOCATION_DB_DIR", str(SCRIPT_DIR)))
DOWNLOAD_BASE_URL = "https://www.ip2location.com/download"
STALE_DAYS        = 35   # warn when a local database hasn't been refreshed this many days

# ANSI colour codes — defined early because every section below uses them.
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Database catalog
# ══════════════════════════════════════════════════════════════════════════════
#
# key      — short name used on the CLI  (e.g. "DB11", "PX7")
# code     — "file=" parameter in the IP2Location download URL
# zip_name — filename of the .BIN file inside the downloaded ZIP
# kind     — "geo" → use IP2Location library  /  "proxy" → use IP2Proxy library
# desc     — one-line summary; each level is cumulative over the level above it
# fields   — canonical field names this database can populate

CATALOG: dict = {
    # ── Geolocation  (IPv6-capable BIN editions) ──────────────────────────────
    # Each level is a strict superset of the previous one.
    "DB1":  dict(code="DB1LITEBINIPV6",   zip_name="IP2LOCATION-LITE-DB1.IPV6.BIN",
                 kind="geo",
                 desc="Country",
                 fields=["country_code", "country_name"]),

    "DB3":  dict(code="DB3LITEBINIPV6",   zip_name="IP2LOCATION-LITE-DB3.IPV6.BIN",
                 kind="geo",
                 desc="Country  +  Region, City",
                 fields=["country_code", "country_name", "region", "city"]),

    "DB5":  dict(code="DB5LITEBINIPV6",   zip_name="IP2LOCATION-LITE-DB5.IPV6.BIN",
                 kind="geo",
                 desc="DB3  +  Latitude, Longitude",
                 fields=["country_code", "country_name", "region", "city",
                         "latitude", "longitude"]),

    "DB9":  dict(code="DB9LITEBINIPV6",   zip_name="IP2LOCATION-LITE-DB9.IPV6.BIN",
                 kind="geo",
                 desc="DB5  +  ZIP, Timezone",
                 fields=["country_code", "country_name", "region", "city",
                         "latitude", "longitude", "zip", "timezone"]),

    "DB11": dict(code="DB11LITEBINIPV6",  zip_name="IP2LOCATION-LITE-DB11.IPV6.BIN",
                 kind="geo",
                 desc="DB9  +  ISP, Domain, Usage type  ★",
                 fields=["country_code", "country_name", "region", "city",
                         "latitude", "longitude", "zip", "timezone",
                         "isp", "domain", "usage_type"]),

    "ASN":  dict(code="DBASNLITEBINIPV6", zip_name="IP2LOCATION-LITE-ASN.IPV6.BIN",
                 kind="geo",
                 desc="Autonomous System number, name, CIDR prefix",
                 fields=["asn", "as_name", "cidr"]),

    # ── Proxy / VPN detection ─────────────────────────────────────────────────
    # Each level is a strict superset of the previous one.
    "PX1":  dict(code="PX1LITEBIN",   zip_name="IP2PROXY-LITE-PX1.BIN",
                 kind="proxy",
                 desc="Is-proxy flag  +  Country",
                 fields=["is_proxy", "country_code", "country_name"]),

    "PX2":  dict(code="PX2LITEBIN",   zip_name="IP2PROXY-LITE-PX2.BIN",
                 kind="proxy",
                 desc="PX1  +  Proxy type  (VPN / Tor / DCH …)",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name"]),

    "PX3":  dict(code="PX3LITEBIN",   zip_name="IP2PROXY-LITE-PX3.BIN",
                 kind="proxy",
                 desc="PX2  +  ISP",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp"]),

    "PX4":  dict(code="PX4LITEBIN",   zip_name="IP2PROXY-LITE-PX4.BIN",
                 kind="proxy",
                 desc="PX3  +  Domain",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain"]),

    "PX5":  dict(code="PX5LITEBIN",   zip_name="IP2PROXY-LITE-PX5.BIN",
                 kind="proxy",
                 desc="PX4  +  Usage type",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type"]),

    "PX6":  dict(code="PX6LITEBIN",   zip_name="IP2PROXY-LITE-PX6.BIN",
                 kind="proxy",
                 desc="PX5  +  ASN",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type", "asn", "as_name"]),

    "PX7":  dict(code="PX7LITEBIN",   zip_name="IP2PROXY-LITE-PX7.BIN",
                 kind="proxy",
                 desc="PX6  +  Threat category",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type", "asn", "as_name", "threat"]),

    "PX8":  dict(code="PX8LITEBIN",   zip_name="IP2PROXY-LITE-PX8.BIN",
                 kind="proxy",
                 desc="PX7  +  Provider name",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type", "asn", "as_name",
                         "threat", "provider"]),

    "PX9":  dict(code="PX9LITEBIN",   zip_name="IP2PROXY-LITE-PX9.BIN",
                 kind="proxy",
                 desc="PX8  +  Fraud score (0–100)",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type", "asn", "as_name",
                         "threat", "provider", "fraud_score"]),

    "PX11": dict(code="PX11LITEBIN",  zip_name="IP2PROXY-LITE-PX11.BIN",
                 kind="proxy",
                 desc="PX9  +  Last seen  (days since last detected)  ★",
                 fields=["is_proxy", "proxy_type", "country_code", "country_name",
                         "isp", "domain", "usage_type", "asn", "as_name",
                         "threat", "provider", "fraud_score", "last_seen"]),

    # ── CIDR CSV editions  (used for reverse lookup: country/city → IP ranges) ─
    # These are CSV files with one CIDR range per row — ideal for filtering by
    # country or city without scanning a binary index.
    "DB1CIDR": dict(code="DB1LITECIDR", zip_name="IP2LOCATION-LITE-DB1.CIDR",
                    kind="cidr",
                    desc="Country CIDR ranges  (fastest for --reverse-country)",
                    fields=["cidr", "country_code", "country_name"]),

    "DB3CIDR": dict(code="DB3LITECIDR", zip_name="IP2LOCATION-LITE-DB3.CIDR",
                    kind="cidr",
                    desc="Country + Region + City CIDR ranges  (for --reverse-city)",
                    fields=["cidr", "country_code", "country_name", "region", "city"]),
}

# When no --db is given, auto-mode picks the richest available DB from each group.
_GEO_PREF   = ["DB11", "DB9", "DB5", "DB3", "DB1"]
_PROXY_PREF = ["PX11", "PX9", "PX8", "PX7", "PX6",
               "PX5",  "PX4", "PX3", "PX2", "PX1"]

# IP2Proxy returns a numeric is_proxy code; map it to a readable string.
_IS_PROXY_LABEL = {
     0: "No",
     1: "Yes (forward proxy)",
     2: "Yes (reverse proxy / CDN)",
    -1: "Unknown",
}

# IP2Proxy returns short uppercase proxy-type codes; expand them.
_PROXY_TYPE_LABEL = {
    "VPN": "VPN / Anonymizer",
    "TOR": "Tor Exit Node",
    "DCH": "Data Center / Hosting",
    "PUB": "Public Proxy",
    "WEB": "Web Proxy",
    "SES": "Search Engine Spider",
    "RES": "Residential Proxy",
    "CPN": "Consumer Privacy Network",
    "EPN": "Enterprise Private Network",
}


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Local file helpers
# ══════════════════════════════════════════════════════════════════════════════

def _db_path(name: str) -> Path:
    return DB_DIR / CATALOG[name]["zip_name"]

def _downloaded(name: str) -> bool:
    return _db_path(name).exists()

def _age_days(path: Path) -> float:
    """Return how many days old a file is, or ∞ if it doesn't exist."""
    if not path.exists():
        return float("inf")
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(tz=timezone.utc) - mtime).total_seconds() / 86400

def _best(pref: list) -> str | None:
    """Return the first (richest) downloaded database from a preference list."""
    return next((n for n in pref if _downloaded(n)), None)


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Download
# ══════════════════════════════════════════════════════════════════════════════

def download(names: list, force: bool = False) -> bool:
    """Download and unzip the named databases. Returns True if all succeeded."""
    if not DOWNLOAD_TOKEN:
        print(
            "[ERROR] No download token found.\n"
            "        Add  IP2LOCATION_TOKEN=<token>  to your .env file.\n"
            "        Get a free token at  https://lite.ip2location.com",
            file=sys.stderr,
        )
        return False

    DB_DIR.mkdir(parents=True, exist_ok=True)
    all_ok = True

    for raw_name in names:
        name = raw_name.upper()
        if name not in CATALOG:
            print(f"  [ERR]  '{name}' not in catalog — run --list to see options",
                  file=sys.stderr)
            all_ok = False
            continue

        cfg  = CATALOG[name]
        dest = DB_DIR / cfg["zip_name"]
        age  = _age_days(dest)

        if not force and age < STALE_DAYS:
            print(f"  [SKIP] {name:<6}  already fresh ({age:.0f} days old)")
            continue

        url = f"{DOWNLOAD_BASE_URL}?token={DOWNLOAD_TOKEN}&file={cfg['code']}"
        print(f"  [DL]   {name:<6}  {cfg['zip_name']}")

        try:
            resp = requests.get(url, stream=True, allow_redirects=True,
                                timeout=(10, 120))
            resp.raise_for_status()

            # Read response body in 64 KB chunks to handle large files.
            raw_bytes = b"".join(resp.iter_content(65536))

            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                # The .BIN file may be inside a subfolder within the archive.
                target = next(
                    (m for m in zf.namelist() if cfg["zip_name"] in m), None
                )
                if target is None:
                    print(
                        f"  [ERR]  {name}  '{cfg['zip_name']}' not found in ZIP\n"
                        f"         ZIP contains: {zf.namelist()}",
                        file=sys.stderr,
                    )
                    all_ok = False
                    continue
                dest.write_bytes(zf.read(target))

            print(f"  [OK]   {name:<6}  {dest.stat().st_size:,} bytes → {dest}")

        except requests.HTTPError as e:
            print(f"  [ERR]  {name}  HTTP error: {e}", file=sys.stderr)
            all_ok = False
        except requests.RequestException as e:
            print(f"  [ERR]  {name}  Network error: {e}", file=sys.stderr)
            all_ok = False
        except zipfile.BadZipFile:
            print(
                f"  [ERR]  {name}  Downloaded file is not a valid ZIP.\n"
                "         Check your IP2LOCATION_TOKEN.",
                file=sys.stderr,
            )
            all_ok = False

    return all_ok


# ══════════════════════════════════════════════════════════════════════════════
# 5 — List databases
# ══════════════════════════════════════════════════════════════════════════════

def list_databases():
    """Print a compact overview of all databases with their download status."""

    def _line(name: str):
        cfg   = CATALOG[name]
        check = f"{GREEN}✓{RESET}" if _downloaded(name) else " "
        age_s = ""
        if _downloaded(name):
            age = _age_days(_db_path(name))
            if age > STALE_DAYS:
                age_s = f"  {YELLOW}({age:.0f}d — stale){RESET}"
            else:
                age_s = f"  {DIM}({age:.0f}d old){RESET}"
        print(f"  {check}  {BOLD}{name:<6}{RESET}  {cfg['desc']}{age_s}")

    print(f"\n{BOLD}Geolocation{RESET}  (IPv6-capable BIN, each level is cumulative)")
    for n in ["DB1", "DB3", "DB5", "DB9", "DB11", "ASN"]:
        _line(n)

    print(f"\n{BOLD}Proxy / VPN detection{RESET}  (each level is cumulative)")
    for n in ["PX1", "PX2", "PX3", "PX4", "PX5",
              "PX6", "PX7", "PX8", "PX9", "PX11"]:
        _line(n)

    print(f"\n{BOLD}CIDR CSV databases{RESET}  (needed for --reverse-country / --reverse-city)")
    for n in ["DB1CIDR", "DB3CIDR"]:
        _line(n)

    total = sum(1 for n in CATALOG if _downloaded(n))
    print(f"\n  {DIM}{total}/{len(CATALOG)} downloaded  ·  {DB_DIR}{RESET}")
    if total == 0:
        print(f"  Example:  python ip2location.py --download DB11 ASN PX7")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# 6 — Lazy database handles
# ══════════════════════════════════════════════════════════════════════════════

_handles: dict = {}   # cache: db_name → opened handle (or None on failure)


def _open(name: str):
    """Open and cache a database handle. Returns the handle or None on failure."""
    if name in _handles:
        return _handles[name]

    path = _db_path(name)
    if not path.exists():
        print(
            f"[WARN] {name} not downloaded"
            f" — run: python ip2location.py --download {name}",
            file=sys.stderr,
        )
        _handles[name] = None
        return None

    try:
        if CATALOG[name]["kind"] == "geo":
            import IP2Location
            _handles[name] = IP2Location.IP2Location(str(path))
        else:  # proxy
            import IP2Proxy
            db = IP2Proxy.IP2Proxy()
            db.open(str(path))
            _handles[name] = db
    except Exception as e:
        print(f"[WARN] Cannot open {name} ({path}): {e}", file=sys.stderr)
        _handles[name] = None

    return _handles[name]


# ══════════════════════════════════════════════════════════════════════════════
# 7 — Lookup
# ══════════════════════════════════════════════════════════════════════════════

# Values returned by the libraries when a field is not populated in this DB level.
_EMPTY_VALUES = {"", "N/A", "-", "0.000000", "0", "0.0"}

def _clean(v) -> str | None:
    """Return a cleaned string, or None if the value is a no-data sentinel."""
    s = str(v).strip() if v is not None else ""
    return None if s in _EMPTY_VALUES else s


def _query_geo(name: str, ip: str) -> dict:
    """Query an IP2Location (geo or ASN) database and return a flat result dict."""
    db = _open(name)
    if db is None:
        return {}

    try:
        rec = db.get_all(ip)
    except Exception as e:
        return {"_error": str(e)}

    # Map library record attribute names → canonical field names used throughout this tool.
    result = {}
    for attr, canon in [
        ("country_short", "country_code"), ("country_long",  "country_name"),
        ("region",        "region"),        ("city",          "city"),
        ("latitude",      "latitude"),      ("longitude",     "longitude"),
        ("zipcode",       "zip"),           ("timezone",      "timezone"),
        ("isp",           "isp"),           ("domain",        "domain"),
        ("usage_type",    "usage_type"),
        ("asn",           "asn"),           ("as_name",       "as_name"),
        ("cidr",          "cidr"),
    ]:
        v = _clean(getattr(rec, attr, None))
        if v is not None:
            result[canon] = v
    return result


def _query_proxy(name: str, ip: str) -> dict:
    """Query an IP2Proxy database and return a flat result dict."""
    db = _open(name)
    if db is None:
        return {}

    try:
        raw = db.get_all(ip)
    except Exception as e:
        return {"_error": str(e)}

    # get_all() may return a dict or an object depending on the library version.
    if not isinstance(raw, dict):
        raw = vars(raw)

    result = {}

    # is_proxy is a numeric code; convert to a readable label.
    try:
        is_proxy_int = int(raw.get("is_proxy", -1))
    except (ValueError, TypeError):
        is_proxy_int = -1
    result["is_proxy"] = _IS_PROXY_LABEL.get(is_proxy_int, "Unknown")

    # proxy_type is a short uppercase code; expand to a readable label.
    ptype = str(raw.get("proxy_type") or "").upper()
    result["proxy_type"] = _PROXY_TYPE_LABEL.get(ptype, _clean(ptype) or "-")

    for key, canon in [
        ("country_short", "country_code"), ("country_long", "country_name"),
        ("region",        "region"),       ("city",         "city"),
        ("isp",           "isp"),          ("domain",       "domain"),
        ("usage_type",    "usage_type"),
        ("asn",           "asn"),          ("as_name",      "as_name"),
        ("threat",        "threat"),       ("provider",     "provider"),
        ("fraud_score",   "fraud_score"),  ("last_seen",    "last_seen"),
    ]:
        v = _clean(raw.get(key))
        if v is not None:
            result[canon] = v

    return result


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def lookup(ip: str, db_name: str | None = None) -> dict:
    """
    Look up *ip* and return a flat result dict.

    Single-DB mode  (db_name given): query only that database.
    Auto mode       (db_name=None):  merge the richest available geo + ASN + proxy DBs.
    """
    result: dict = {"ip": ip, "hostname": _rdns(ip)}
    sources: list = []

    if db_name:
        name = db_name.upper()
        if name not in CATALOG:
            result["_error"] = f"Unknown database '{name}' — run --list"
            result["_sources"] = []
            return result

        kind   = CATALOG[name]["kind"]
        fields = _query_geo(name, ip) if kind == "geo" else _query_proxy(name, ip)
        if "_error" not in fields:
            result.update(fields)
            sources.append(name)
        else:
            result["_error"] = fields.get("_error", "lookup failed")

    else:
        # Geo: use richest available geo database.
        geo = _best(_GEO_PREF)
        if geo:
            f = _query_geo(geo, ip)
            if "_error" not in f:
                result.update(f)
                sources.append(geo)

        # ASN: merge without overwriting fields already set by geo.
        if _downloaded("ASN"):
            f = _query_geo("ASN", ip)
            if "_error" not in f:
                for k, v in f.items():
                    result.setdefault(k, v)
                sources.append("ASN")

        # Proxy: merge without overwriting geo fields like country_code.
        proxy = _best(_PROXY_PREF)
        if proxy:
            f = _query_proxy(proxy, ip)
            if "_error" not in f:
                for k, v in f.items():
                    result.setdefault(k, v)
                sources.append(proxy)

    result["_sources"] = sources
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 8 — Reverse lookup  (country code or city → CIDR ranges)
# ══════════════════════════════════════════════════════════════════════════════

def reverse_lookup(country_code: str | None = None,
                   city: str | None = None,
                   limit: int = 20) -> list:
    """
    Scan a CIDR CSV database and return rows matching *country_code* or *city*.

    Requires DB1CIDR (country-only, ~15 MB) or DB3CIDR (+ region/city, ~232 MB).
    Download with:  python ip2location.py --download DB1CIDR
                    python ip2location.py --download DB3CIDR
    """
    # Choose the smallest sufficient CSV for the query.
    if city:
        csv_name = "DB3CIDR"
    else:
        # DB1CIDR is enough for country-only; fall back to DB3CIDR if that's what's available.
        csv_name = "DB1CIDR" if _downloaded("DB1CIDR") else \
                   "DB3CIDR" if _downloaded("DB3CIDR") else None

    if csv_name is None or not _downloaded(csv_name):
        needed = "DB3CIDR" if city else "DB1CIDR"
        print(
            f"[ERROR] {needed} not downloaded.\n"
            f"        Run: python ip2location.py --download {needed}",
            file=sys.stderr,
        )
        return []

    path  = _db_path(csv_name)
    cols  = CATALOG[csv_name]["fields"]   # ["cidr", "country_code", ...]
    cc    = country_code.upper()          if country_code else None
    city_lc = city.lower()               if city         else None
    results = []

    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)

            # Sniff the first row; skip it if it looks like a header.
            first = next(reader, None)
            if first and not any("/" in v for v in first):
                pass   # it was a header row — already consumed, continue below
            elif first:
                # First row is data — process it now before the loop.
                row_dict = dict(zip(cols, first))
                if _rev_match(row_dict, cc, city_lc):
                    results.append(row_dict)

            for row in reader:
                if len(row) < len(cols):
                    continue
                row_dict = dict(zip(cols, row))
                if _rev_match(row_dict, cc, city_lc):
                    results.append(row_dict)
                    if limit and len(results) >= limit:
                        break

    except Exception as e:
        print(f"[ERROR] Could not read {path}: {e}", file=sys.stderr)
        return []

    return results


def _rev_match(row: dict, cc: str | None, city_lc: str | None) -> bool:
    """Return True if the row matches the given country code and/or city filter."""
    if cc and row.get("country_code", "").strip('"').upper() != cc:
        return False
    if city_lc and city_lc not in row.get("city", "").strip('"').lower():
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 9 — Display
# ══════════════════════════════════════════════════════════════════════════════

# Fields in preferred display order.  country_name and longitude are handled
# inline (printed on the same line as country_code and latitude respectively).
_FIELD_ORDER = [
    ("country_code",  "Country"),
    ("region",        "Region"),
    ("city",          "City"),
    ("latitude",      "Lat / Lon"),
    ("zip",           "ZIP"),
    ("timezone",      "Timezone"),
    ("isp",           "ISP"),
    ("domain",        "Domain"),
    ("usage_type",    "Usage type"),
    ("asn",           "ASN"),
    ("as_name",       "AS name"),
    ("cidr",          "CIDR"),
    ("is_proxy",      "Is proxy"),
    ("proxy_type",    "Proxy type"),
    ("threat",        "Threat"),
    ("provider",      "Provider"),
    ("fraud_score",   "Fraud score"),
    ("last_seen",     "Last seen (days)"),
]


def _hdr(title: str):
    bar = "─" * 56
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}")


def _row(label: str, value: str, color: str = ""):
    print(f"{DIM}  {label:<22}{RESET}{color}{value}{RESET}")


def print_result(data: dict):
    """Render a single lookup result as a coloured detail block."""
    sources = data.get("_sources", [])
    src_tag = f"  [{', '.join(sources)}]" if sources else ""
    _hdr(data.get("ip", "?") + src_tag)
    _row("Hostname", data.get("hostname", "-"), YELLOW)

    # Country code + name on one line.
    cc = data.get("country_code")
    cn = data.get("country_name")
    if cc or cn:
        _row("Country", f"{cc or ''}  {cn or ''}".strip())

    # Lat/Lon on one line.
    lat = data.get("latitude")
    lon = data.get("longitude")
    if lat and lon:
        _row("Lat / Lon", f"{lat}, {lon}")

    # All other fields — skip the ones already printed above.
    _already = {"country_code", "country_name", "latitude", "longitude"}
    for field, label in _FIELD_ORDER:
        if field in _already:
            continue
        v = data.get(field)
        if not v:
            continue
        if field in ("asn", "as_name"):
            color = GREEN
        elif field == "is_proxy":
            color = RED if str(v).startswith("Yes") else GREEN
        else:
            color = ""
        _row(label, v, color)

    if "_error" in data:
        print(f"\n  {RED}Error: {data['_error']}{RESET}")

    print(f"\n{DIM}{'─' * 56}{RESET}\n")


def print_table(results: list):
    """Print multiple lookup results as an aligned summary table."""

    def _v(d, *keys):
        for k in keys:
            v = d.get(k)
            if v and v not in ("-", ""):
                return str(v)
        return "-"

    def _trunc(s: str, w: int) -> str:
        return s if len(s) <= w else s[: w - 1] + "…"

    # Only show ASN / proxy columns when at least one result has that data.
    has_asn   = any(r.get("asn")      for r in results)
    has_proxy = any(r.get("is_proxy") for r in results)

    cols = [("IP", 15), ("Hostname", 22), ("CC", 4), ("City", 15), ("ISP", 20)]
    if has_asn:
        cols.append(("ASN", 9))
    if has_proxy:
        cols.append(("Proxy", 28))

    def _row_vals(d):
        vals = [_v(d, "ip"), _v(d, "hostname"), _v(d, "country_code"),
                _v(d, "city"), _v(d, "isp")]
        if has_asn:
            vals.append(_v(d, "asn"))
        if has_proxy:
            vals.append(_v(d, "is_proxy"))
        return vals

    header = "  ".join(f"{h:<{w}}" for h, w in cols)
    sep    = "  ".join("─" * w       for _, w in cols)
    print(f"\n{BOLD}{header}{RESET}")
    print(f"{DIM}{sep}{RESET}")

    for data in results:
        vals  = _row_vals(data)
        parts = []
        for i, ((_, w), val) in enumerate(zip(cols, vals)):
            padded = f"{_trunc(val, w):<{w}}"
            if has_proxy and i == len(cols) - 1:   # colour proxy column
                color = RED if val.startswith("Yes") else GREEN
                parts.append(f"{color}{padded}{RESET}")
            else:
                parts.append(padded)
        print("  ".join(parts))

    print()


def print_reverse(rows: list, label: str, total_hint: str = ""):
    """Display reverse-lookup results (list of CIDR row dicts)."""
    if not rows:
        print(f"  No results found for {label}")
        return

    hint = f"  {DIM}(showing {len(rows)}{total_hint}){RESET}" if total_hint else ""
    print(f"\n{BOLD}CIDR ranges for {label}{RESET}{hint}\n")

    has_city = any(r.get("city") for r in rows)

    if has_city:
        # Wide table: CIDR | country | region | city
        cols = [("CIDR", 20), ("CC", 4), ("Region", 18), ("City", 22)]
        header = "  ".join(f"{h:<{w}}" for h, w in cols)
        sep    = "  ".join("─" * w       for _, w in cols)
        print(f"{BOLD}{header}{RESET}")
        print(f"{DIM}{sep}{RESET}")

        def _trunc(s, w):
            return s if len(s) <= w else s[: w - 1] + "…"

        for r in rows:
            cidr   = r.get("cidr", "-").strip('"')
            cc     = r.get("country_code", "-").strip('"')
            region = r.get("region", "-").strip('"')
            city   = r.get("city", "-").strip('"')
            vals   = [cidr, cc, region, city]
            print("  ".join(f"{_trunc(v, w):<{w}}" for v, (_, w) in zip(vals, cols)))
    else:
        # Compact two-column list: CIDR | country
        for r in rows:
            cidr = r.get("cidr", "-").strip('"')
            cc   = r.get("country_code", "-").strip('"')
            cn   = r.get("country_name", "").strip('"')
            print(f"  {cidr:<22}  {DIM}{cc}  {cn}{RESET}")

    print()


def print_csv(rows: list):
    """Write rows as RFC-4180 CSV to stdout, deriving the header from all keys present."""
    if not rows:
        return

    # Collect every key that appears across all rows, in a stable display order.
    # _prefixed keys are internal and excluded.
    known_order = [
        "ip", "hostname",
        "country_code", "country_name", "region", "city",
        "latitude", "longitude", "zip", "timezone",
        "isp", "domain", "usage_type",
        "asn", "as_name", "cidr",
        "is_proxy", "proxy_type", "threat", "provider", "fraud_score", "last_seen",
    ]
    all_keys = {k for r in rows for k in r if not k.startswith("_")}
    # Preserve known order first, then any extra keys alphabetically.
    fieldnames = [k for k in known_order if k in all_keys] + \
                 sorted(all_keys - set(known_order))

    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=fieldnames,
        extrasaction="ignore",   # silently drop _sources, _error etc.
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})


# ══════════════════════════════════════════════════════════════════════════════
# 10 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="ip2location",
        description="Query any IP2Location LITE database for IP information.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ip2location.py --list\n"
            "  python ip2location.py --download DB11 ASN PX7\n"
            "  python ip2location.py 8.8.8.8\n"
            "  python ip2location.py --db PX7 8.8.8.8 1.1.1.1\n"
            "  python ip2location.py --json 8.8.8.8\n"
            "  python ip2location.py --reverse-country US\n"
            "  python ip2location.py --reverse-city Tokyo --json\n"
        ),
    )
    parser.add_argument("ips",        nargs="*",  metavar="IP",
                        help="IPv4 or IPv6 addresses to look up.")
    parser.add_argument("--download", nargs="+",  metavar="DB",
                        help="Download one or more databases (e.g. DB11 ASN PX7).")
    parser.add_argument("--update",   nargs="*",  metavar="DB",
                        help="Re-download stale DBs. Omit names to update all downloaded ones.")
    parser.add_argument("--force",    action="store_true",
                        help="With --download/--update: skip the freshness check.")
    parser.add_argument("--db",       metavar="DB",
                        help="Query a specific database instead of auto-detecting.")
    parser.add_argument("--list",     action="store_true",
                        help="Show all databases with download status, then exit.")
    parser.add_argument("--json",     action="store_true",
                        help="Output as JSON. Single IP → object; multiple IPs → array.")
    parser.add_argument("--csv",      action="store_true",
                        help="Output as CSV with a header row.")
    parser.add_argument("--reverse-country", metavar="CC",
                        help="Find CIDR ranges for a country code (e.g. US, DE, JP)."
                             " Requires DB1CIDR or DB3CIDR to be downloaded.")
    parser.add_argument("--reverse-city",    metavar="NAME",
                        help="Find CIDR ranges assigned to a city (substring match)."
                             " Requires DB3CIDR to be downloaded.")
    parser.add_argument("--limit",    type=int, default=20, metavar="N",
                        help="Max results for reverse lookup (default: 20).")

    args = parser.parse_args()

    # ── --list ────────────────────────────────────────────────────────────────
    if args.list:
        list_databases()
        sys.exit(0)

    # ── --download ────────────────────────────────────────────────────────────
    if args.download:
        print(f"\nDownloading to: {DB_DIR}\n")
        ok = download(args.download, force=args.force)
        if not args.ips:
            sys.exit(0 if ok else 1)
        print()

    # ── --update ──────────────────────────────────────────────────────────────
    if args.update is not None:
        # --update with no names → refresh every database that's already downloaded.
        targets = args.update or [n for n in CATALOG if _downloaded(n)]
        if not targets:
            print("Nothing downloaded yet — use --download <DB> first.")
            sys.exit(0)
        print(f"\nUpdating in: {DB_DIR}\n")
        ok = download(targets, force=True)
        if not args.ips:
            sys.exit(0 if ok else 1)
        print()

    # ── --reverse-country / --reverse-city ───────────────────────────────────
    if args.reverse_country or args.reverse_city:
        rows = reverse_lookup(
            country_code=args.reverse_country,
            city=args.reverse_city,
            limit=args.limit,
        )
        cleaned = [{k: v.strip('"') for k, v in r.items()} for r in rows]
        if args.json:
            print(json.dumps(cleaned, indent=2))
        elif args.csv:
            print_csv(cleaned)
        else:
            label = args.reverse_country or f'"{args.reverse_city}"'
            print_reverse(rows, label)
        sys.exit(0)

    # ── No IPs provided: show help ────────────────────────────────────────────
    if not args.ips:
        parser.print_help()
        sys.exit(0)

    # ── Warn about stale databases ────────────────────────────────────────────
    for name in CATALOG:
        if _downloaded(name) and _age_days(_db_path(name)) > STALE_DAYS:
            print(
                f"[WARN] {name} is stale"
                f" — run: python ip2location.py --update {name}",
                file=sys.stderr,
            )

    # ── Perform lookups ───────────────────────────────────────────────────────
    db_name = args.db.upper() if args.db else None
    all_results = [lookup(ip.strip(), db_name) for ip in args.ips]

    def _pub(d):
        return {k: v for k, v in d.items() if not k.startswith("_")}

    if args.json:
        out = _pub(all_results[0]) if len(all_results) == 1 \
              else [_pub(r) for r in all_results]
        print(json.dumps(out, indent=2))
    elif args.csv:
        print_csv([_pub(r) for r in all_results])
    elif len(all_results) == 1:
        print_result(all_results[0])
    else:
        print_table(all_results)


if __name__ == "__main__":
    main()
