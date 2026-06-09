#!/usr/bin/env python3
"""
ipinfo.py — IP information lookup tool
=======================================
Looks up geolocation, ASN, and proxy/threat data for any IPv4 or IPv6 address
using three local IP2Location binary databases.

Databases used (downloaded automatically when you run --update):
  DB11  : IP2LOCATION-LITE-DB11.IPV6.BIN   ← geo: country, city, lat/lon, ISP …
  ASN   : IP2LOCATION-LITE-ASN.IPV6.BIN    ← autonomous system number & name
  PROXY : IP2PROXY-LITE-PX11.BIN           ← proxy / VPN / threat detection

Prerequisites
─────────────
  pip install IP2Location IP2Proxy python-dotenv requests

.env file (place it next to this script)
─────────────────────────────────────────
  IP2LOCATION_TOKEN=your_download_token_here

  # Optional — override where the .BIN files live (default: same folder as script)
  # IP2LOCATION_DB_DIR=/some/other/path

Get your free token at: https://lite.ip2location.com  → sign in → Download

Usage
─────
  python ipinfo.py 8.8.8.8
  python ipinfo.py 8.8.8.8 1.1.1.1 2001:4860:4860::8888
  python ipinfo.py --json 8.8.8.8
  python ipinfo.py --update            ← download / refresh all three databases
  python ipinfo.py --update 8.8.8.8   ← update first, then look up
"""

# ── Standard-library imports ──────────────────────────────────────────────────
# These come built into Python — no installation needed.
import sys          # sys.exit(), sys.stderr
import os           # os.path helpers, environment variables
import json         # pretty-print results as JSON
import argparse     # parse command-line arguments (--json, --update, etc.)
import socket       # reverse-DNS hostname lookup
import zipfile      # extract the .zip archives that IP2Location provides
import io           # treat downloaded bytes as a file-like object (for zipfile)
from datetime import datetime, timezone  # check how old the local DB files are
from pathlib import Path                 # modern, readable file-path handling

# ── Third-party imports ───────────────────────────────────────────────────────
# Install these with:  pip install IP2Location IP2Proxy python-dotenv requests
try:
    from dotenv import load_dotenv   # reads KEY=VALUE pairs from a .env file
except ImportError:
    # If python-dotenv is not installed we print a helpful message and stop.
    print(
        "[ERROR] 'python-dotenv' is not installed.\n"
        "        Run:  pip install python-dotenv",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import requests  # makes HTTP(S) downloads easy
except ImportError:
    print(
        "[ERROR] 'requests' is not installed.\n"
        "        Run:  pip install requests",
        file=sys.stderr,
    )
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Configuration
# ══════════════════════════════════════════════════════════════════════════════

# __file__ is the absolute path of *this* script.
# .resolve() turns it into an unambiguous, canonical path.
# .parent gives us the directory that contains the script.
SCRIPT_DIR = Path(__file__).resolve().parent

# Load the .env file that lives in the same folder as this script.
# load_dotenv() reads each line like  KEY=VALUE  and places those values into
# the process environment so that os.environ["KEY"] works afterward.
# override=False means it will NOT replace variables that are already set in
# the real environment — real env vars always win.
load_dotenv(SCRIPT_DIR / ".env", override=False)

# Read the download token.  os.environ.get() returns None if the key is absent
# (safer than os.environ["KEY"] which would raise a KeyError).
DOWNLOAD_TOKEN = os.environ.get("IP2LOCATION_TOKEN", "")

# Directory where we store the .BIN database files.
# Defaults to the same folder as this script unless overridden in .env.
DB_DIR = Path(os.environ.get("IP2LOCATION_DB_DIR", str(SCRIPT_DIR)))

# Full paths to each binary database file.
DB11_BIN  = DB_DIR / "IP2LOCATION-LITE-DB11.IPV6.BIN"
ASN_BIN   = DB_DIR / "IP2LOCATION-LITE-ASN.IPV6.BIN"
PROXY_BIN = DB_DIR / "IP2PROXY-LITE-PX11.BIN"

# IP2Location download endpoint.
# We append  ?token=TOKEN&file=CODE  to build the full URL.
DOWNLOAD_BASE_URL = "https://www.ip2location.com/download"

# Each database has an official "file code" used in the download URL.
# These codes come from the IP2Location download documentation.
DB_CONFIGS = [
    {
        "name":       "DB11 (Geo)",                       # human-readable label
        "code":       "DB11LITEBINIPV6",                  # file= parameter in URL
        "zip_member": "IP2LOCATION-LITE-DB11.IPV6.BIN",  # filename inside the ZIP
        "dest":       DB11_BIN,                           # where to save it locally
    },
    {
        "name":       "ASN",
        "code":       "DBASNLITEBINIPV6",
        "zip_member": "IP2LOCATION-LITE-ASN.IPV6.BIN",
        "dest":       ASN_BIN,
    },
    {
        "name":       "Proxy (PX11)",
        "code":       "PX11LITEBIN",
        "zip_member": "IP2PROXY-LITE-PX11.BIN",
        "dest":       PROXY_BIN,
    },
]

# IP2Location updates their geo databases on the 1st of each month and their
# proxy database daily.  We consider a file "stale" if it is older than this
# many days — warn the user but still proceed with the lookup.
STALE_DAYS = 35


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Database download & update
# ══════════════════════════════════════════════════════════════════════════════

def _file_age_days(path: Path) -> float:
    """
    Return how many days old a file is, measured from its last-modified time.
    Returns a very large number if the file does not exist.

    path.stat().st_mtime gives the Unix timestamp of the last modification.
    We compare it to the current UTC time to get the age in seconds, then
    convert to days.
    """
    if not path.exists():
        return float("inf")   # infinity — treat missing files as infinitely old

    mtime_ts  = path.stat().st_mtime                             # Unix timestamp (float)
    mtime_dt  = datetime.fromtimestamp(mtime_ts, tz=timezone.utc)  # as datetime object
    age_secs  = (datetime.now(tz=timezone.utc) - mtime_dt).total_seconds()
    return age_secs / 86400   # convert seconds → days  (86400 = 60 × 60 × 24)


def download_databases(force: bool = False) -> bool:
    """
    Download and unzip all three IP2Location databases.

    Parameters
    ----------
    force : bool
        If True, download even if the local files are still fresh.
        If False (default), skip files that were modified within the last month.

    Returns True if all downloads succeeded, False if any failed.
    """

    # Make sure we have a token before attempting anything.
    if not DOWNLOAD_TOKEN:
        print(
            "[ERROR] No download token found.\n"
            "        Add this line to your .env file:\n"
            "          IP2LOCATION_TOKEN=your_token_here\n"
            "        Get a free token at https://lite.ip2location.com",
            file=sys.stderr,
        )
        return False

    # Make sure the destination directory exists.
    # parents=True creates any missing parent folders too.
    # exist_ok=True means no error if the folder already exists.
    DB_DIR.mkdir(parents=True, exist_ok=True)

    all_ok = True   # track whether every download succeeded

    for db in DB_CONFIGS:
        dest: Path = db["dest"]
        age = _file_age_days(dest)

        # Skip if the file is fresh enough and we are not forcing a re-download.
        if not force and age < STALE_DAYS:
            print(
                f"  [SKIP] {db['name']} — already up to date "
                f"({age:.0f} days old, threshold is {STALE_DAYS})"
            )
            continue

        # Build the download URL.
        # f-strings (f"...") let us embed variables directly using {variable}.
        url = f"{DOWNLOAD_BASE_URL}?token={DOWNLOAD_TOKEN}&file={db['code']}"
        print(f"  [DL]   {db['name']} ← {url}")

        try:
            # allow_redirects=True is required: since May 2025 IP2Location
            # redirects downloads through Cloudflare R2 storage.
            # stream=False lets requests download the full body before returning,
            # which means timeout=(15, 600) covers the entire transfer — not just
            # the first byte.  With stream=True the read timeout only applies to
            # each individual chunk, so a stalled mid-transfer connection hangs
            # forever even with a timeout set.
            response = requests.get(
                url,
                stream=False,
                allow_redirects=True,
                timeout=(15, 600),   # 15 s connect, 10 min full-body read
            )

            # raise_for_status() throws an exception if the server returned
            # an HTTP error code like 401 Unauthorized or 404 Not Found.
            response.raise_for_status()

            raw_bytes = response.content

            # The downloaded file is a ZIP archive.
            # io.BytesIO wraps raw bytes so zipfile can read them like a real
            # file — without us needing to write the ZIP to disk first.
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:

                # List all filenames inside the archive.
                members = zf.namelist()

                # Find the specific .BIN file we want.
                # next(..., None) returns the first match or None if not found.
                target = next(
                    (m for m in members if db["zip_member"] in m),
                    None,
                )

                if target is None:
                    print(
                        f"  [ERR]  {db['name']} — could not find "
                        f"'{db['zip_member']}' inside the downloaded ZIP.\n"
                        f"         ZIP contains: {members}",
                        file=sys.stderr,
                    )
                    all_ok = False
                    continue

                # Read the binary content of the target file out of the ZIP.
                bin_data = zf.read(target)

            # Write the .BIN data to its final destination on disk.
            # "wb" mode = write binary.  This overwrites any existing file.
            dest.write_bytes(bin_data)
            print(f"  [OK]   {db['name']} → {dest}  ({len(bin_data):,} bytes)")

        except requests.HTTPError as e:
            # HTTP-level error (401 = bad token, 404 = wrong file code, etc.)
            print(f"  [ERR]  {db['name']} — HTTP error: {e}", file=sys.stderr)
            all_ok = False

        except requests.RequestException as e:
            # Network-level error: timeout, DNS failure, connection refused, …
            print(f"  [ERR]  {db['name']} — network error: {e}", file=sys.stderr)
            all_ok = False

        except zipfile.BadZipFile:
            # The downloaded content is not a valid ZIP.
            # This often means the token is wrong and the server returned an
            # HTML error page instead of the actual archive.
            print(
                f"  [ERR]  {db['name']} — downloaded file is not a valid ZIP.\n"
                "         Check that your IP2LOCATION_TOKEN is correct.",
                file=sys.stderr,
            )
            all_ok = False

    return all_ok


def warn_if_stale():
    """
    Print a warning for each database that is missing or hasn't been updated
    recently.  Call this just before performing lookups.
    """
    for db in DB_CONFIGS:
        age = _file_age_days(db["dest"])
        if age == float("inf"):
            print(
                f"[WARN] {db['name']} database not found: {db['dest']}\n"
                "       Run:  python ipinfo.py --update",
                file=sys.stderr,
            )
        elif age > STALE_DAYS:
            print(
                f"[WARN] {db['name']} database is {age:.0f} days old — consider updating.\n"
                "       Run:  python ipinfo.py --update",
                file=sys.stderr,
            )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Lazy database loaders
# ══════════════════════════════════════════════════════════════════════════════
#
# "Lazy loading" means we don't open the database files until the first time we
# actually need them.  This is done with module-level variables initialised to
# None.  The first call opens the file and caches the handle; every subsequent
# call returns the cached handle immediately.
#
# The leading underscore on names (_db11_handle etc.) is a Python convention
# meaning "private — intended for use only within this file".

_db11_handle  = None   # will hold an open IP2Location object once loaded
_asn_handle   = None
_proxy_handle = None


def _load_db11():
    """Open (or return the already-open) DB11 geolocation database."""
    global _db11_handle   # tell Python we're assigning to the module-level var
    if _db11_handle is None:
        try:
            import IP2Location                                   # pip install IP2Location
            _db11_handle = IP2Location.IP2Location(str(DB11_BIN))
        except Exception as e:
            # Don't crash — just warn.  The lookup will show an error for geo.
            print(f"[WARN] Could not open DB11 ({DB11_BIN}): {e}", file=sys.stderr)
    return _db11_handle


def _load_asn():
    """Open (or return the already-open) ASN database."""
    global _asn_handle
    if _asn_handle is None:
        try:
            import IP2Location
            _asn_handle = IP2Location.IP2Location(str(ASN_BIN))
        except Exception as e:
            print(f"[WARN] Could not open ASN db ({ASN_BIN}): {e}", file=sys.stderr)
    return _asn_handle


def _load_proxy():
    """Open (or return the already-open) IP2Proxy database."""
    global _proxy_handle
    if _proxy_handle is None:
        try:
            import IP2Proxy                        # pip install IP2Proxy
            db = IP2Proxy.IP2Proxy()
            db.open(str(PROXY_BIN))
            _proxy_handle = db
        except Exception as e:
            print(f"[WARN] Could not open Proxy db ({PROXY_BIN}): {e}", file=sys.stderr)
    return _proxy_handle


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Helper utilities
# ══════════════════════════════════════════════════════════════════════════════

# Maps the short proxy-type codes returned by IP2Proxy to human-readable labels.
# A dict (dictionary) stores key → value pairs: dict["KEY"] returns the value.
PROXY_TYPE_LABELS = {
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

# Maps the numeric is_proxy return value to a readable description.
IS_PROXY_LABELS = {
     0: "No",
     1: "Yes (forward proxy)",
     2: "Yes (reverse proxy / CDN)",
    -1: "Unknown",
}


def _safe(value, default: str = "-") -> str:
    """
    Convert *value* to a printable string, replacing "no data" sentinels with
    *default* (a dash by default).

    IP2Location returns things like "N/A", empty strings, or "0.000000" when a
    field is not available in the current database edition.  We normalise all of
    those to a single dash so the output looks consistent.
    """
    if value is None:
        return default
    s = str(value).strip()          # convert to str and remove surrounding spaces
    if s in ("", "N/A", "-", "0.000000", "0"):
        return default
    return s


def _reverse_dns(ip: str) -> str:
    """
    Try to resolve an IP address back to its hostname (reverse DNS lookup).
    Returns "-" if the lookup fails or the host has no PTR record.

    socket.gethostbyaddr() queries your OS resolver and returns a tuple:
      (hostname, alias_list, address_list)
    We only need index [0] — the primary hostname.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — Core lookup logic
# ══════════════════════════════════════════════════════════════════════════════

def lookup(ip: str) -> dict:
    """
    Look up *ip* in all three databases and return a dict with the results.

    The returned dict always has the same keys regardless of success or failure
    — missing data appears as "-", errors appear under an "error" key inside
    the relevant sub-dict.

    Parameters
    ----------
    ip : str
        An IPv4 or IPv6 address string, e.g. "8.8.8.8" or "2001:4860::1".

    Returns
    -------
    dict with keys: "ip", "hostname", "geo", "asn", "proxy"
    """

    # Start building the result with the IP itself and its reverse-DNS name.
    result = {
        "ip":       ip,
        "hostname": _reverse_dns(ip),
    }

    # ── 5a. Geolocation (DB11) ────────────────────────────────────────────────
    db = _load_db11()
    if db:
        try:
            # get_all() queries the binary database and returns a record object
            # whose attributes correspond directly to the database fields.
            rec = db.get_all(ip)

            # Build a nested dict from the record's attributes.
            # _safe() normalises "no data" values to "-".
            result["geo"] = {
                "country_code": _safe(rec.country_short),   # e.g. "US"
                "country":      _safe(rec.country_long),    # e.g. "United States of America"
                "region":       _safe(rec.region),          # e.g. "California"
                "city":         _safe(rec.city),            # e.g. "Mountain View"
                "latitude":     _safe(rec.latitude),        # e.g. "37.38600"
                "longitude":    _safe(rec.longitude),       # e.g. "-122.08380"
                "zip":          _safe(rec.zipcode),         # e.g. "94043"
                "timezone":     _safe(rec.timezone),        # e.g. "-07:00"
                "isp":          _safe(rec.isp),             # e.g. "Google LLC"
                "domain":       _safe(rec.domain),          # e.g. "google.com"
                "usage_type":   _safe(rec.usage_type),      # e.g. "DCH" (data center/hosting)
            }
        except Exception as e:
            # Something went wrong for this specific IP — store the error message.
            result["geo"] = {"error": str(e)}
    else:
        result["geo"] = {"error": "DB11 database not loaded — run --update"}

    # ── 5b. ASN lookup ────────────────────────────────────────────────────────
    adb = _load_asn()
    if adb:
        try:
            arec = adb.get_all(ip)

            # The ASN database record has slightly different attribute names.
            # hasattr() checks whether an attribute exists before we access it,
            # preventing AttributeError on older library versions.
            as_name = (
                arec.as_name                             # preferred attribute name
                if hasattr(arec, "as_name")
                else getattr(arec, "asn", "-")           # fallback attribute
            )
            cidr = arec.cidr if hasattr(arec, "cidr") else "-"

            result["asn"] = {
                "asn":  _safe(arec.asn),   # e.g. "AS15169"
                "as":   _safe(as_name),    # e.g. "Google LLC"
                "cidr": _safe(cidr),       # e.g. "8.8.8.0/24"
            }
        except Exception as e:
            result["asn"] = {"error": str(e)}
    else:
        result["asn"] = {"error": "ASN database not loaded — run --update"}

    # ── 5c. Proxy / threat detection ──────────────────────────────────────────
    pdb = _load_proxy()
    if pdb:
        try:
            # IP2Proxy's get_all() may return either a dict or an object
            # depending on the library version.  We handle both cases below.
            prec = pdb.get_all(ip)

            # Inner helper: extract a field whether prec is a dict or an object.
            # isinstance(x, dict) returns True if x is a dictionary.
            # getattr(obj, name, default) safely reads obj.name or returns default.
            def _pget(field, default="-"):
                if isinstance(prec, dict):
                    return prec.get(field, default)
                return getattr(prec, field, default)

            is_proxy_raw = _pget("is_proxy", -1)
            ptype_raw    = _pget("proxy_type", "")
            threat_raw   = _pget("threat", "-")

            # Convert the numeric is_proxy code to a readable label.
            # We guard against non-numeric strings with a try/except.
            try:
                is_proxy_int = int(is_proxy_raw)
            except (ValueError, TypeError):
                is_proxy_int = -1

            result["proxy"] = {
                "is_proxy": IS_PROXY_LABELS.get(is_proxy_int, "Unknown"),
                # Look up the short type code in our label dict;
                # fall back to the raw value if the code is unrecognised.
                "proxy_type": PROXY_TYPE_LABELS.get(
                    str(ptype_raw).upper(), _safe(ptype_raw)
                ),
                "threat": _safe(threat_raw),
            }
        except Exception as e:
            result["proxy"] = {"error": str(e)}
    else:
        result["proxy"] = {"error": "Proxy database not loaded — run --update"}

    return result


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Pretty-print display
# ══════════════════════════════════════════════════════════════════════════════
#
# ANSI escape codes control terminal colours and styles.
# The format is:  \033[<code>m
#   \033  = ESC character (octal 033)
#   [     = start of CSI (Control Sequence Introducer)
#   <code>= numeric style/colour code
#   m     = final byte marking the end of the sequence
# Code 0 resets everything back to defaults.

RESET  = "\033[0m"   # reset all formatting
BOLD   = "\033[1m"   # bold / bright text
DIM    = "\033[2m"   # dim / greyed-out text (used for labels)
CYAN   = "\033[36m"  # cyan colour (used for section headers)
YELLOW = "\033[33m"  # yellow colour (used for ISP / hostname)
GREEN  = "\033[32m"  # green colour (used for ASN and "not a proxy")
RED    = "\033[31m"  # red colour (used for proxy flags and errors)


def _header(title: str):
    """Print a coloured section header with a horizontal rule above and below."""
    width = 54
    bar = "─" * width   # Unicode box-drawing character, repeated
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}")


def _row(label: str, value: str, color: str = ""):
    """
    Print a single label → value row with consistent alignment.
    {label:<18} left-aligns the label in a 18-character wide field
    (padding with spaces on the right as needed).
    """
    print(f"{DIM}  {label:<18}{RESET} {color}{value}{RESET}")


def print_table(results: list):
    """Print multiple lookup results as an aligned summary table."""

    def _get(data, *keys):
        v = data
        for k in keys:
            if not isinstance(v, dict):
                return "-"
            v = v.get(k, "-")
        return str(v) if v not in (None, "") else "-"

    def _trunc(s: str, width: int) -> str:
        return s if len(s) <= width else s[: width - 1] + "…"

    cols = [
        ("IP",       15),
        ("Hostname", 22),
        ("CC",        4),
        ("City",     15),
        ("ISP",      20),
        ("ASN",       9),
        ("Proxy",    28),
    ]

    def _values(data):
        return [
            _get(data, "ip"),
            _get(data, "hostname"),
            _get(data, "geo", "country_code"),
            _get(data, "geo", "city"),
            _get(data, "geo", "isp"),
            _get(data, "asn", "asn"),
            _get(data, "proxy", "is_proxy"),
        ]

    header = "  ".join(f"{h:<{w}}" for h, w in cols)
    sep    = "  ".join("─" * w for _, w in cols)
    print(f"\n{BOLD}{header}{RESET}")
    print(f"{DIM}{sep}{RESET}")

    for data in results:
        vals = _values(data)
        parts = []
        for i, ((_, w), val) in enumerate(zip(cols, vals)):
            cell = _trunc(val, w)
            padded = f"{cell:<{w}}"
            if i == 6:  # Proxy column
                color = RED if val.startswith("Yes") else GREEN
                parts.append(f"{color}{padded}{RESET}")
            else:
                parts.append(padded)
        print("  ".join(parts))

    print()


def print_result(data: dict):
    """Render a lookup result dict as formatted, coloured terminal output."""

    ip = data.get("ip", "?")
    hn = data.get("hostname", "-")

    _header(f"IP Info  ›  {ip}")
    _row("Hostname", hn, YELLOW)

    # ── Geolocation section ───────────────────────────────────────────────────
    geo = data.get("geo", {})
    if "error" not in geo:
        print(f"\n{BOLD}  Geolocation  (DB11){RESET}")
        cc = geo.get("country_code", "")
        _row("Country",    f"{cc}  {geo.get('country', '-')}")
        _row("Region",     geo.get("region",     "-"))
        _row("City",       geo.get("city",       "-"))
        _row("Lat / Lon",  f"{geo.get('latitude', '-')}, {geo.get('longitude', '-')}")
        _row("ZIP",        geo.get("zip",        "-"))
        _row("Timezone",   geo.get("timezone",   "-"))
        _row("ISP",        geo.get("isp",        "-"), YELLOW)
        _row("Domain",     geo.get("domain",     "-"))
        _row("Usage Type", geo.get("usage_type", "-"))
    else:
        print(f"\n  {RED}Geo lookup error: {geo['error']}{RESET}")

    # ── ASN section ───────────────────────────────────────────────────────────
    asn = data.get("asn", {})
    if "error" not in asn:
        print(f"\n{BOLD}  ASN{RESET}")
        _row("ASN",  asn.get("asn",  "-"), GREEN)
        _row("Name", asn.get("as",   "-"), GREEN)
        _row("CIDR", asn.get("cidr", "-"))
    else:
        print(f"\n  {RED}ASN lookup error: {asn['error']}{RESET}")

    # ── Proxy / threat section ────────────────────────────────────────────────
    proxy = data.get("proxy", {})
    if "error" not in proxy:
        print(f"\n{BOLD}  Proxy / Threat{RESET}")
        is_p = proxy.get("is_proxy", "-")
        # Use red if the IP is flagged as a proxy, green if clean.
        proxy_color = RED if is_p.startswith("Yes") else GREEN
        _row("Is Proxy",   is_p,                          proxy_color)
        _row("Proxy Type", proxy.get("proxy_type", "-"))
        _row("Threat",     proxy.get("threat",     "-"))
    else:
        print(f"\n  {RED}Proxy lookup error: {proxy['error']}{RESET}")

    print(f"\n{DIM}{'─' * 54}{RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — Command-line interface (CLI)
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """
    Entry point: parse arguments, optionally update databases, then look up IPs.
    """

    # argparse handles --flags and positional arguments automatically.
    # It also generates --help output for free.
    parser = argparse.ArgumentParser(
        prog="ipinfo",
        description="IP geolocation, ASN, and proxy lookup using local IP2Location databases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ipinfo.py 8.8.8.8\n"
            "  python ipinfo.py --update\n"
            "  python ipinfo.py --update 8.8.8.8 1.1.1.1\n"
            "  python ipinfo.py --json 8.8.8.8\n"
        ),
    )

    # nargs="*" means "zero or more" positional arguments.
    # This lets us run  --update  alone (no IPs required).
    parser.add_argument(
        "ips",
        nargs="*",
        metavar="IP",
        help="One or more IPv4 or IPv6 addresses to look up.",
    )
    parser.add_argument(
        "--update",
        action="store_true",   # sets args.update = True when the flag is given
        help="Download / refresh all three IP2Location databases, then exit "
             "(or look up IPs if also provided).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --update: re-download even if the databases are still fresh.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON instead of coloured text.",
    )

    args = parser.parse_args()   # parses sys.argv (the command-line arguments)

    # ── Handle --update ───────────────────────────────────────────────────────
    if args.update:
        print(f"\nUpdating IP2Location databases in: {DB_DIR}\n")
        ok = download_databases(force=args.force)
        if not ok:
            print("\n[WARN] One or more databases failed to download.", file=sys.stderr)
        else:
            print("\n[OK] All databases are up to date.")

        # If no IP addresses were given alongside --update, we are done.
        if not args.ips:
            # sys.exit(0) = success exit code; sys.exit(1) = error exit code.
            sys.exit(0 if ok else 1)

        print()   # blank line between update output and lookup output

    # ── Warn about stale or missing databases before doing lookups ────────────
    if args.ips:
        warn_if_stale()

    # ── No IPs and no --update — show help ───────────────────────────────────
    if not args.ips:
        parser.print_help()
        sys.exit(0)

    # ── Perform lookups ───────────────────────────────────────────────────────
    all_results = []

    for ip in args.ips:
        data = lookup(ip.strip())
        all_results.append(data)

    if args.json:
        # Single IP → plain object; multiple IPs → JSON array.
        output = all_results[0] if len(all_results) == 1 else all_results
        print(json.dumps(output, indent=2))
    elif len(all_results) == 1:
        print_result(all_results[0])
    else:
        print_table(all_results)


# ── Script entry point ────────────────────────────────────────────────────────
# Python sets __name__ to "__main__" when you run this file directly:
#   python ipinfo.py ...
# When another file does  import ipinfo  instead, __name__ is "ipinfo" and
# this block is skipped — so importing the module won't trigger main().
if __name__ == "__main__":
    main()