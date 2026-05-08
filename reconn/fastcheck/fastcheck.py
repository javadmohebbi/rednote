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
      10.0.0.1-10.0.0.50  full IPv4 range (spaces around dash are fine)
      10.0.0.1-50         shorthand range (last-octet end)
      example.com         hostname (returned as-is)

    Yields one host string at a time — no list is built in memory.
    """
    raw = raw.strip()
    if not raw:
        return

    # ── CIDR ─────────────────────────────────────────────────────────────────
    try:
        net = ipaddress.ip_network(raw, strict=False)
        # net.hosts() is a lazy iterator — safe for /8 (16 M addresses)
        hosts = net.hosts()
        yielded = False
        for h in hosts:
            yield str(h)
            yielded = True
        if not yielded:                         # /32 or /128
            yield str(net.network_address)
        return
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
                prefix = ".".join(str(start).split(".")[:3])
                end    = ipaddress.IPv4Address(f"{prefix}.{end_s}")
            for i in range(int(start), int(end) + 1):
                yield str(ipaddress.IPv4Address(i))
            return
        except (ValueError, ipaddress.AddressValueError):
            pass

    # ── Single IP or hostname ─────────────────────────────────────────────────
    yield raw


def _raw_list(args) -> list:
    """Return the list of raw (unexpanded) target strings from CLI args."""
    raw = []
    if args.target:
        raw.append(args.target)
    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.exit(f"[ERROR] Target file not found: {args.file}")
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw.append(line)
    if not raw:
        sys.exit("[ERROR] No targets — provide TARGET or use -f FILE.")
    return raw


def count_targets(raw_list: list) -> int:
    """
    Count the total number of hosts without expanding them into memory.
    Uses integer arithmetic for CIDRs and ranges — O(1) per spec regardless
    of how large the block is.
    """
    total = 0
    for raw in raw_list:
        raw = raw.strip()
        # CIDR
        try:
            net = ipaddress.ip_network(raw, strict=False)
            n   = int(net.num_addresses)
            total += max(n - 2, 1) if net.prefixlen < 31 else n
            continue
        except ValueError:
            pass
        # Range
        if "-" in raw:
            parts = raw.split("-", 1)
            try:
                start = ipaddress.IPv4Address(parts[0].strip())
                end_s = parts[1].strip()
                try:
                    end = ipaddress.IPv4Address(end_s)
                except ipaddress.AddressValueError:
                    prefix = ".".join(str(start).split(".")[:3])
                    end    = ipaddress.IPv4Address(f"{prefix}.{end_s}")
                total += int(end) - int(start) + 1
                continue
            except (ValueError, ipaddress.AddressValueError):
                pass
        total += 1
    return total


def iter_targets(raw_list: list):
    """Yield {"target": ip, "input": original_spec} entries lazily, one at a time."""
    for raw in raw_list:
        for host in expand_target(raw):
            yield {"target": host, "input": raw}


# ══════════════════════════════════════════════════════════════════════════════
# 2 — nmap wrapper
# ══════════════════════════════════════════════════════════════════════════════

def check_nmap() -> str:
    """Return the nmap version string, or exit with a helpful error."""
    try:
        out   = subprocess.run(
            ["nmap", "--version"], capture_output=True, timeout=5
        ).stdout.decode(errors="replace")
        first = out.splitlines()[0] if out else ""
        for tok in first.split():
            if tok and tok[0].isdigit():
                return tok
        return "unknown"
    except FileNotFoundError:
        sys.exit(
            "[ERROR] nmap not found.\n"
            "        Install:  brew install nmap   /   apt install nmap"
        )
    except Exception as exc:
        sys.exit(f"[ERROR] Cannot run nmap: {exc}")


_PERM_KEYWORDS = ("root", "privileges", "administrator", "permission denied",
                  "operation not permitted", "requires root")

def preflight_check(light: bool):
    """
    Before starting the scan, verify we can actually send the required packets.
    If the default scan needs raw sockets and we don't have them, exit with a
    clear message rather than silently reporting every host as 'error'.
    """
    if light:
        return   # ICMP + ARP works without root on most systems

    # Quick test: run one SYN probe on localhost and check stderr for denials.
    try:
        test = subprocess.run(
            ["nmap", "-PS80", "-sn", "--host-timeout", "3s", "127.0.0.1"],
            capture_output=True, timeout=8,
        )
        stderr = test.stderr.decode(errors="replace").lower()
        if any(kw in stderr for kw in _PERM_KEYWORDS):
            _permission_error_exit()
    except Exception:
        pass   # if test itself fails, let the scan proceed and surface the error


def _permission_error_exit():
    print(
        f"\n{RED}{BOLD}Permission denied{RESET}"
        f" — the default scan needs raw socket access (TCP SYN/ACK, UDP).\n\n"
        f"  Fix 1 — run with sudo:  {BOLD}sudo python fastcheck.py ...{RESET}\n"
        f"  Fix 2 — use light mode: {BOLD}python fastcheck.py ... --light{RESET}\n"
        f"\n  --light uses ICMP echo + ARP only and does not need root.\n",
        file=sys.stderr,
    )
    sys.exit(1)


# Probe flags used by each scan mode.
# Default (high-accuracy): combines TCP SYN, TCP ACK, UDP, ICMP echo, and
#   ICMP timestamp probes so that hosts which silently drop one probe type
#   are still discovered via another.
# Light: ICMP echo + ARP only — fast, but misses firewalled/filtered hosts.
PROBES_DEFAULT = ["-PS22,80,443", "-PA80,443", "-PU161", "-PE", "-PP"]
PROBES_LIGHT   = []   # nmap's built-in default (ICMP echo + ARP)


def scan_host(target: str, timeout: int, light: bool = False) -> dict:
    """
    Run nmap -sn against a single target and return a result dict.

    Default (high-accuracy) probes
      -PS22,80,443   TCP SYN ping   → discovers hosts that answer on SSH/HTTP/HTTPS
      -PA80,443      TCP ACK ping   → bypasses stateful firewalls that drop SYN
      -PU161         UDP ping       → discovers SNMP devices and UDP-only hosts
      -PE            ICMP echo      → classic ping
      -PP            ICMP timestamp → fallback for hosts that block echo but allow timestamp

    Light probes (--light)
      nmap default: ICMP echo + ARP (fast, less thorough)

    Common flags
      -sn            no port scan — host discovery only
      -T4            aggressive timing for faster responses
      --host-timeout cap per-host wait time
      -oX -          XML output to stdout for reliable parsing
    """
    result = {
        "timestamp":    datetime.now(tz=timezone.utc).isoformat(),
        "input":        target,
        "target":       target,
        "status":       "unknown",
        "latency_ms":   None,
        "hostname":     None,
        "mac":          None,
        "scan_mode":    "light" if light else "default",
        "nmap_version": NMAP_VERSION,
    }
    probes = PROBES_LIGHT if light else PROBES_DEFAULT
    cmd = ["nmap", "-sn"] + probes + ["-T4", "--host-timeout", f"{timeout}s", "-oX", "-", target]
    try:
        proc   = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        stderr = proc.stderr.decode(errors="replace")
        _parse_nmap_xml(proc.stdout.decode(errors="replace"), result)
        # If XML parsing didn't already catch an error, check stderr for
        # human-readable failure reasons (permissions, interface issues, etc.)
        if result["status"] in ("error", "unknown") and stderr:
            stderr_l = stderr.lower()
            if any(kw in stderr_l for kw in _PERM_KEYWORDS):
                result["error"] = "needs root/sudo — use --light or run with sudo"
            else:
                # Use the first non-empty stderr line as the error detail.
                first_line = next((l.strip() for l in stderr.splitlines() if l.strip()), "")
                if first_line:
                    result["error"] = first_line
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
        result["status"] = "down"
        return

    st = host_el.find("status")
    if st is not None:
        result["status"] = st.get("state", "unknown")

    for addr in host_el.findall("address"):
        atype = addr.get("addrtype", "")
        if atype in ("ipv4", "ipv6"):
            result["target"] = addr.get("addr", result["target"])
        elif atype == "mac":
            result["mac"] = addr.get("addr")

    for hn in host_el.findall(".//hostname"):
        if hn.get("type") == "PTR":
            result["hostname"] = hn.get("name")
            break

    times = host_el.find("times")
    if times is not None:
        srtt = times.get("srtt", "")
        if srtt.lstrip("-").isdigit() and int(srtt) > 0:
            result["latency_ms"] = round(int(srtt) / 1000, 3)


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Live display
# ══════════════════════════════════════════════════════════════════════════════
#
# Layout (all row numbers are 1-indexed):
#
#   Row 1         ─── separator bar ─────────────────────────────────────────
#   Row 2         fastcheck · nmap X.XX
#   Row 3         Targets: N  Workers: W  Timeout: Ts  → output.jsonl
#   Row 4         ─── separator bar ─────────────────────────────────────────
#   Rows 5..vend  SCROLL REGION — IP results appear here and scroll upward
#   Row vend+1    ─── separator bar ─────────────────────────────────────────
#   Row vend+2    Up: N  Down: N  [████░░░░] X/N
#
# The scroll region is set with ANSI  \033[5;{vend}r.
# When a new result arrives, we move to the last row of the region, emit \n
# (which scrolls the region up one line), then write the new line in the
# now-blank bottom row.  The header and footer are outside the region and
# are never disturbed by scroll operations.

class LiveDisplay:
    HEADER = 4   # fixed rows at top (rows 1–4)
    FOOTER = 3   # fixed rows at bottom (sep + stats + blank)

    def __init__(self, total: int, workers: int, timeout: int,
                 out_path, nmap_ver: str, light: bool = False):
        cols, rows = shutil.get_terminal_size((80, 24))
        self.total   = total
        self.cols    = cols
        self.rows    = rows
        self.v_start = self.HEADER + 1                      # first row of scroll region
        self.v_end   = max(self.v_start + 2, rows - self.FOOTER)  # last row
        self.f_sep   = self.v_end + 1                       # footer separator row
        self.f_stats = self.v_end + 2                       # stats row
        self.lock    = threading.Lock()
        self.done    = 0
        self.counts  = {"up": 0, "down": 0, "other": 0}

        o   = sys.stdout
        bar = "─" * cols
        mode_s = f"{DIM}light{RESET}" if light else f"{GREEN}default (high-accuracy){RESET}"

        o.write("\033[2J\033[H")    # clear screen, cursor home
        o.write("\033[?25l")        # hide cursor
        o.write("\033[?7l")         # disable line-wrap (lines are clipped, not wrapped)

        # ── Fixed header ──────────────────────────────────────────────────────
        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  fastcheck  ·  nmap {nmap_ver}  ·  {mode_s}{RESET}")
        self._at(3)
        info = f"  Targets: {total}  Workers: {workers}  Timeout: {timeout}s"
        if out_path:
            info += f"  →  {out_path}"
        o.write(info)
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        # ── Fixed footer ──────────────────────────────────────────────────────
        self._at(self.f_sep);   o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()

        # ── Activate scroll region ────────────────────────────────────────────
        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)    # park cursor at bottom of viewport
        o.flush()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _at(self, row: int, col: int = 1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _draw_stats(self):
        """Redraw the progress/stats line (call with lock held, or during init)."""
        o    = sys.stdout
        up   = self.counts["up"]
        down = self.counts["down"]
        done = self.done
        pct  = done / self.total if self.total else 0
        bw   = max(10, min(30, self.cols - 52))
        fill = int(bw * pct)
        bar  = f"{'█' * fill}{'░' * (bw - fill)}"

        self._at(self.f_stats)
        o.write("\033[K")
        o.write(
            f"  {GREEN}Up: {up:<5}{RESET}"
            f"  {RED}Down: {down:<5}{RESET}"
            f"  {CYAN}[{bar}]{RESET}"
            f"  {done}/{self.total}"
        )

    # ── Public ────────────────────────────────────────────────────────────────

    def add_result(self, result: dict):
        """Append one result line to the scrolling viewport (thread-safe)."""
        status = result.get("status", "?")
        target = result.get("target", "?")
        lat    = result.get("latency_ms")
        host   = result.get("hostname") or ""
        w      = len(str(self.total))

        lat_s = f"{lat:.2f}ms" if lat is not None else ""

        err = result.get("error", "")

        if status == "up":
            st_s  = f"{GREEN}{BOLD}up  {RESET}"
            lat_s = f"{DIM}{lat_s:<10}{RESET}"
        elif status == "down":
            st_s  = f"{RED}down{RESET}"
            lat_s = " " * 10
        elif status == "timeout":
            st_s  = f"{YELLOW}tout{RESET}"
            lat_s = " " * 10
        elif status == "error":
            st_s  = f"{RED}err {RESET}"
            lat_s = f"{RED}{err[:35]}{RESET}" if err else " " * 10
        else:
            st_s  = f"{YELLOW}{status[:4]:<4}{RESET}"
            lat_s = " " * 10

        host_s = f"  {DIM}{host}{RESET}" if host else ""

        with self.lock:
            self.done += 1
            s = result.get("status", "other")
            if   s == "up":   self.counts["up"]    += 1
            elif s == "down": self.counts["down"]  += 1
            else:             self.counts["other"] += 1

            counter = f"{CYAN}[{self.done:{w}}/{self.total}]{RESET}"
            line    = f"{counter}  {target:<20}  {st_s}  {lat_s}{host_s}"

            o = sys.stdout
            # Move to the bottom of the scroll region and emit \n:
            # → the region scrolls up one line, cursor stays at v_end on blank row.
            self._at(self.v_end, 1)
            o.write("\n")
            o.write("\033[K")   # clear the blank bottom row
            o.write(line)       # write new result there

            # Refresh footer stats (outside scroll region — unaffected by scroll).
            self._draw_stats()

            self._at(self.v_end)  # park cursor back at bottom of viewport
            o.flush()

    def finish(self):
        """Restore terminal to normal state after the scan."""
        with self.lock:
            o = sys.stdout
            o.write("\033[r")    # reset scroll region to full screen
            o.write("\033[?7h")  # re-enable line-wrap
            o.write("\033[?25h") # show cursor
            self._at(self.rows)
            o.write("\n")
            o.flush()


class SimpleDisplay:
    """Fallback for non-TTY output (pipes, redirection) — plain line-by-line."""

    def __init__(self, total: int, workers: int, timeout: int,
                 out_path, nmap_ver: str, light: bool = False):
        self.total  = total
        self.lock   = threading.Lock()
        self.done   = 0
        self.counts = {"up": 0, "down": 0, "other": 0}
        bar    = "─" * 62
        mode_s = "light" if light else "default (high-accuracy)"
        print(f"\n{bar}")
        print(f"  fastcheck  ·  nmap {nmap_ver}  ·  {mode_s}")
        print(f"  Targets: {total}  Workers: {workers}  Timeout: {timeout}s"
              + (f"  →  {out_path}" if out_path else ""))
        print(f"{bar}\n")

    def add_result(self, result: dict):
        status = result.get("status", "?")
        target = result.get("target", "?")
        lat    = result.get("latency_ms")
        host   = result.get("hostname") or ""
        w      = len(str(self.total))
        lat_s  = f"{lat:.2f}ms" if lat is not None else ""

        err = result.get("error", "")

        with self.lock:
            self.done += 1
            s = result.get("status", "other")
            if   s == "up":   self.counts["up"]    += 1
            elif s == "down": self.counts["down"]  += 1
            else:             self.counts["other"] += 1
            suffix = f"  {err[:50]}" if s == "error" and err else (f"  {host}" if host else "")
            print(f"[{self.done:{w}}/{self.total}]  {target:<20}  {status:<7}  {lat_s}{suffix}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Output file
# ══════════════════════════════════════════════════════════════════════════════

def prompt_output_path() -> Path:
    """Ask the user for an output path (mandatory for multi-target scans)."""
    default = f"fastcheck_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    while True:
        sys.stdout.write(f"\n{BOLD}Output file{RESET} (required) [{default}]: ")
        sys.stdout.flush()
        try:
            answer = input().strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        path = Path(answer if answer else default)
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
    parser.add_argument("target",       nargs="?",     metavar="TARGET",
                        help="IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname.")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="File of targets, one per line (# = comment).")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output .jsonl file. Prompted if omitted and multiple targets.")
    parser.add_argument("-w", "--workers", type=int, default=10, metavar="N",
                        help="Parallel nmap processes (default: 10).")
    parser.add_argument("--timeout",    type=int, default=None, metavar="SEC",
                        help="Per-host nmap timeout in seconds "
                             "(default: 10 for default scan, 5 for --light).")
    parser.add_argument("--light",      action="store_true",
                        help="Use ICMP echo + ARP only (faster, less thorough). "
                             "Default scan uses TCP SYN/ACK, UDP, and ICMP probes "
                             "for higher accuracy.")
    parser.add_argument("--up-only",    action="store_true",
                        help="Only write 'up' hosts to the output file.")

    args = parser.parse_args()

    NMAP_VERSION = check_nmap()
    preflight_check(args.light)

    raw_list = _raw_list(args)
    total    = count_targets(raw_list)   # O(1) per spec — never touches individual IPs
    multi    = total > 1

    # Timeout: default scan uses more probes and needs more time.
    if args.timeout is not None:
        timeout = args.timeout
    else:
        timeout = 5 if args.light else 10

    # Output path: single target → optional; multiple → mandatory, prompt if absent.
    out_path = None
    if args.output:
        out_path = Path(args.output)
    elif multi:
        out_path = prompt_output_path()

    # Choose display: live TUI for interactive terminal, plain text for pipes.
    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(total, args.workers, timeout, out_path, NMAP_VERSION,
                      light=args.light)

    fh = open(out_path, "w", encoding="utf-8") if out_path else None

    def run_one(entry: dict):
        result          = scan_host(entry["target"], timeout, light=args.light)
        result["input"] = entry["input"]
        display.add_result(result)
        if fh and (not args.up_only or result.get("status") == "up"):
            write_record(fh, result)

    # Bounded sliding-window execution:
    # At most (workers × 4) futures live in memory at any time.
    # The generator feeds new work only as old futures complete, so memory
    # stays flat even for 10 M+ targets.
    MAX_PENDING = args.workers * 4

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen     = iter_targets(raw_list)
            pending = set()

            # Prime the window
            for entry in itertools.islice(gen, MAX_PENDING):
                pending.add(pool.submit(run_one, entry))

            # Slide: as futures finish, retire them and submit new ones
            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    f.result()                              # surface exceptions
                for entry in itertools.islice(gen, len(done)):
                    pending.add(pool.submit(run_one, entry))

    except KeyboardInterrupt:
        pass
    finally:
        display.finish()
        if fh:
            fh.close()

    # Print final summary after display is torn down.
    c   = display.counts
    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"  {GREEN}Up     : {c['up']}{RESET}")
    print(f"  {RED}Down   : {c['down']}{RESET}")
    if c["other"]:
        print(f"  {YELLOW}Other  : {c['other']}{RESET}")
    if out_path and out_path.exists():
        sz    = out_path.stat().st_size
        total_rec = c["up"] + c["down"] + c["other"]
        print(f"  Output : {out_path}  ({sz:,} bytes, {total_rec} records)")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
