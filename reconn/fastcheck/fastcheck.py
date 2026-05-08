#!/usr/bin/env python3
"""
fastcheck.py  —  rapid host discovery using nmap
=================================================
Checks whether targets are online (nmap -sn ping scan).
Accepts a single target or a file of targets.

  python fastcheck.py 8.8.8.8
  python fastcheck.py 10.0.0.0/24
  python fastcheck.py 10.0.0.1-50
  python fastcheck.py -f targets.txt -o results.jsonl
  python fastcheck.py -f targets.txt -w 20 --up-only

Output format
  JSON Lines (.jsonl) — one JSON object per line, UTF-8.
  Every downstream tool reads it with:
    for line in open("results.jsonl"):
        record = json.loads(line)

Prerequisites
  nmap must be installed:  brew install nmap  /  apt install nmap
"""

import sys
import json
import argparse
import ipaddress
import subprocess
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from xml.etree import ElementTree as ET


# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"

# Set once in main(); included in every output record for traceability.
NMAP_VERSION = "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# 1 — Target expansion
# ══════════════════════════════════════════════════════════════════════════════

def expand_target(raw: str) -> list:
    """
    Expand one target string into a list of individual host strings.

    Supported formats
      10.0.0.1            single IPv4
      2001:db8::1         single IPv6
      10.0.0.0/24         CIDR  → every host address in the block
      10.0.0.1-10.0.0.50  full IPv4 range
      10.0.0.1-50         shorthand range (last-octet end)
      example.com         hostname (returned as-is)
    """
    raw = raw.strip()
    if not raw:
        return []

    # ── CIDR ─────────────────────────────────────────────────────────────────
    try:
        net   = ipaddress.ip_network(raw, strict=False)
        hosts = list(net.hosts())
        # /32 or /128 have no hosts(); return the address itself
        return [str(h) for h in hosts] if hosts else [str(net.network_address)]
    except ValueError:
        pass

    # ── IPv4 range ────────────────────────────────────────────────────────────
    if "-" in raw:
        parts = raw.split("-", 1)
        try:
            start = ipaddress.IPv4Address(parts[0].strip())
            end_s = parts[1].strip()
            try:
                end = ipaddress.IPv4Address(end_s)
            except ipaddress.AddressValueError:
                # Shorthand: "10.0.0.1-50" → end = "10.0.0.50"
                prefix = ".".join(str(start).split(".")[:3])
                end = ipaddress.IPv4Address(f"{prefix}.{end_s}")
            return [str(ipaddress.IPv4Address(i))
                    for i in range(int(start), int(end) + 1)]
        except (ValueError, ipaddress.AddressValueError):
            pass  # not a range — fall through to single host

    # ── Single IP or hostname ─────────────────────────────────────────────────
    return [raw]


def load_targets(args) -> list:
    """
    Build the complete ordered list of scan entries from CLI arguments.

    Each entry: {"target": "10.0.0.1", "input": "10.0.0.0/24"}
    'input' preserves the original spec the user provided.
    """
    raw_list = []

    if args.target:
        raw_list.append(args.target)

    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.exit(f"[ERROR] Target file not found: {args.file}")
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_list.append(line)

    if not raw_list:
        sys.exit("[ERROR] No targets — provide TARGET or use -f FILE.")

    entries = []
    for raw in raw_list:
        for host in expand_target(raw):
            entries.append({"target": host, "input": raw})
    return entries


# ══════════════════════════════════════════════════════════════════════════════
# 2 — nmap wrapper
# ══════════════════════════════════════════════════════════════════════════════

def check_nmap() -> str:
    """Return the nmap version string, or exit with a helpful error."""
    try:
        out = subprocess.run(
            ["nmap", "--version"], capture_output=True, timeout=5
        ).stdout.decode(errors="replace")
        first = out.splitlines()[0] if out else ""
        # "Nmap version 7.99 ( https://nmap.org )" → "7.99"
        tokens = first.split()
        for tok in tokens:
            if tok[0].isdigit():
                return tok
        return "unknown"
    except FileNotFoundError:
        sys.exit(
            "[ERROR] nmap not found.\n"
            "        Install:  brew install nmap   /   apt install nmap"
        )
    except Exception as exc:
        sys.exit(f"[ERROR] Cannot run nmap: {exc}")


def scan_host(target: str, timeout: int) -> dict:
    """
    Run  nmap -sn -T4  against a single target and return a result dict.

    -sn           ping scan only (ICMP echo + ARP) — no port scanning
    -T4           aggressive timing template for faster responses
    --host-timeout cap per-host wait time
    -oX -         structured XML output to stdout for reliable parsing
    """
    ts = datetime.now(tz=timezone.utc).isoformat()

    result = {
        "timestamp":    ts,
        "input":        target,   # overwritten by caller with the original spec
        "target":       target,
        "status":       "unknown",
        "latency_ms":   None,
        "hostname":     None,
        "mac":          None,
        "nmap_version": NMAP_VERSION,
    }

    cmd = [
        "nmap", "-sn", "-T4",
        "--host-timeout", f"{timeout}s",
        "-oX", "-",
        target,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        _parse_nmap_xml(proc.stdout.decode(errors="replace"), result)
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as exc:
        result["status"] = "error"
        result["error"]  = str(exc)

    return result


def _parse_nmap_xml(xml: str, result: dict):
    """Fill *result* in-place from nmap's XML output."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        result["status"] = "error"
        result["error"]  = "nmap XML parse error"
        return

    host_el = root.find("host")
    if host_el is None:
        # nmap produced no <host> element → target did not respond
        result["status"] = "down"
        return

    # up / down
    st = host_el.find("status")
    if st is not None:
        result["status"] = st.get("state", "unknown")

    # Resolved IP address and optional MAC
    for addr in host_el.findall("address"):
        atype = addr.get("addrtype", "")
        if atype in ("ipv4", "ipv6"):
            result["target"] = addr.get("addr", result["target"])
        elif atype == "mac":
            result["mac"] = addr.get("addr")

    # Reverse-DNS hostname (PTR record)
    for hn in host_el.findall(".//hostname"):
        if hn.get("type") == "PTR":
            result["hostname"] = hn.get("name")
            break

    # Round-trip latency: <times srtt="N"> in microseconds → convert to ms
    times = host_el.find("times")
    if times is not None:
        srtt = times.get("srtt", "")
        if srtt.lstrip("-").isdigit() and int(srtt) > 0:
            result["latency_ms"] = round(int(srtt) / 1000, 3)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Live progress display
# ══════════════════════════════════════════════════════════════════════════════

_print_lock = threading.Lock()


def print_progress(idx: int, total: int, result: dict):
    """Print one coloured result line (thread-safe)."""
    status  = result.get("status", "?")
    target  = result.get("target", "?")
    lat     = result.get("latency_ms")
    host    = result.get("hostname") or ""
    width   = len(str(total))

    lat_s = f"{lat:.2f}ms" if lat is not None else ""

    if status == "up":
        status_col = f"{GREEN}{BOLD}up  {RESET}"
        lat_col    = f"{DIM}{lat_s:<10}{RESET}"
    elif status == "down":
        status_col = f"{RED}down{RESET}"
        lat_col    = " " * 10
    elif status == "timeout":
        status_col = f"{YELLOW}tout{RESET}"
        lat_col    = " " * 10
    else:
        status_col = f"{YELLOW}{status[:4]:<4}{RESET}"
        lat_col    = " " * 10

    host_col = f"  {DIM}{host}{RESET}" if host else ""
    counter  = f"{CYAN}[{idx:{width}}/{total}]{RESET}"

    with _print_lock:
        print(f"{counter}  {target:<22}  {status_col}  {lat_col}{host_col}")


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Output file
# ══════════════════════════════════════════════════════════════════════════════

def prompt_output_path() -> Path:
    """
    Interactively ask the user for the output file path.
    Called only when multiple targets are scanned and no -o was given.
    The output file is mandatory in that case.
    """
    default = f"fastcheck_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    while True:
        sys.stdout.write(f"\n{BOLD}Output file{RESET} (required) [{default}]: ")
        sys.stdout.flush()
        try:
            answer = input().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        path = Path(answer if answer else default)
        # Ensure the parent directory exists
        if not path.parent.exists():
            print(f"  {RED}Directory does not exist: {path.parent}{RESET}")
            continue
        return path


_file_lock = threading.Lock()


def write_record(fh, record: dict):
    """Append one JSON line to the open file handle (thread-safe)."""
    with _file_lock:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()


# ══════════════════════════════════════════════════════════════════════════════
# 5 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global NMAP_VERSION

    parser = argparse.ArgumentParser(
        prog="fastcheck",
        description="Check whether hosts are online using nmap ping scan.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python fastcheck.py 8.8.8.8\n"
            "  python fastcheck.py 192.168.1.0/24 -o results.jsonl\n"
            "  python fastcheck.py 10.0.0.1-50 -o results.jsonl -w 20\n"
            "  python fastcheck.py -f targets.txt -o results.jsonl\n"
            "  python fastcheck.py -f targets.txt --up-only\n"
        ),
    )
    parser.add_argument("target",      nargs="?",      metavar="TARGET",
                        help="IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname.")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="File of targets, one per line (# lines are comments).")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output .jsonl file. Prompted if omitted and multiple targets.")
    parser.add_argument("-w", "--workers", type=int, default=10, metavar="N",
                        help="Parallel nmap processes (default: 10).")
    parser.add_argument("--timeout",   type=int, default=5,  metavar="SEC",
                        help="Per-host nmap timeout in seconds (default: 5).")
    parser.add_argument("--up-only",   action="store_true",
                        help="Only write 'up' hosts to the output file.")

    args = parser.parse_args()

    NMAP_VERSION = check_nmap()
    targets      = load_targets(args)
    total        = len(targets)
    multi        = total > 1

    # ── Resolve output path ───────────────────────────────────────────────────
    # Single target: optional. Multiple targets: mandatory (prompt if not given).
    out_path = None
    if args.output:
        out_path = Path(args.output)
    elif multi:
        out_path = prompt_output_path()

    # ── Print scan header ─────────────────────────────────────────────────────
    bar = "─" * 62
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  fastcheck  ·  nmap {NMAP_VERSION}{RESET}")
    print(f"  Targets  : {total}")
    print(f"  Workers  : {args.workers}")
    print(f"  Timeout  : {args.timeout}s / host")
    if out_path:
        print(f"  Output   : {out_path}")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")

    # ── Concurrent scan ───────────────────────────────────────────────────────
    counts    = {"up": 0, "down": 0, "other": 0}
    idx_state = {"n": 0}
    idx_lock  = threading.Lock()
    cnt_lock  = threading.Lock()

    def run_one(entry: dict, fh):
        result          = scan_host(entry["target"], args.timeout)
        result["input"] = entry["input"]   # original spec (e.g. "10.0.0.0/24")

        with idx_lock:
            idx_state["n"] += 1
            idx = idx_state["n"]

        print_progress(idx, total, result)

        s = result.get("status", "other")
        with cnt_lock:
            if   s == "up":   counts["up"]    += 1
            elif s == "down": counts["down"]  += 1
            else:             counts["other"] += 1

        if fh and (not args.up_only or s == "up"):
            write_record(fh, result)

    fh = open(out_path, "w", encoding="utf-8") if out_path else None

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(run_one, e, fh) for e in targets]
            for future in as_completed(futures):
                future.result()   # surface any unexpected exception
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted — partial results saved.{RESET}")
    finally:
        if fh:
            fh.close()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'─' * 62}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"  {GREEN}Up     : {counts['up']}{RESET}")
    print(f"  {RED}Down   : {counts['down']}{RESET}")
    if counts["other"]:
        print(f"  {YELLOW}Other  : {counts['other']}{RESET}")
    total_records = counts["up"] + counts["down"] + counts["other"]
    if out_path and out_path.exists():
        sz = out_path.stat().st_size
        print(f"  Output : {out_path}  ({sz:,} bytes, {total_records} records)")
    print(f"{BOLD}{CYAN}{'─' * 62}{RESET}\n")


if __name__ == "__main__":
    main()
