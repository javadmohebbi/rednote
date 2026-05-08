#!/usr/bin/env python3
"""
scantop100.py  —  top-100 port scan with service detection
===========================================================
Runs  nmap -n --top-ports 100 --min-rate 300 -sV  against each target.
Reads targets from a single IP/CIDR/range, a plain text file, or a
fastcheck .jsonl file (only 'up' hosts are extracted automatically).

  python scantop100.py 192.168.1.1
  python scantop100.py -f fastcheck_results.jsonl -o ports.jsonl
  python scantop100.py -f targets.txt -o ports.jsonl -w 10
  python scantop100.py 10.0.0.0/24 -o ports.jsonl

Resume
  If the scan is stopped, re-run the exact same command.
  Already-scanned hosts are detected from the output file and skipped.

Pause / quit
  Ctrl+C        pause  (workers finish their current host, then wait)
  Enter         resume
  Ctrl+C again  quit

Output
  JSON Lines (.jsonl) — one record per host with open ports and service
  versions, structured for downstream attack tooling.

Prerequisites
  nmap must be installed:  brew install nmap  /  apt install nmap
"""

import sys
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

NMAP_VERSION = "unknown"


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
    """
    Block the calling worker thread until resumed or quit.
    Returns False if quit was requested (caller should exit).
    """
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
# 2 — Target loading
# ══════════════════════════════════════════════════════════════════════════════

def _is_fastcheck_jsonl(path: Path) -> bool:
    """Detect whether a file is fastcheck .jsonl output."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                return "status" in obj and "target" in obj
    except Exception:
        pass
    return False


def expand_target(raw: str):
    """
    Yield individual host strings from one target spec (lazy generator).
    Handles: single IP, CIDR, full range, shorthand range, hostname.
    Spaces around the dash are handled automatically.
    """
    raw = raw.strip()
    if not raw:
        return
    # CIDR
    try:
        net     = ipaddress.ip_network(raw, strict=False)
        yielded = False
        for h in net.hosts():
            yield str(h)
            yielded = True
        if not yielded:
            yield str(net.network_address)
        return
    except ValueError:
        pass
    # IPv4 range
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
    yield raw


def _count_spec(spec: str) -> int:
    """Count hosts in one target spec without materialising them."""
    spec = spec.strip()
    try:
        net = ipaddress.ip_network(spec, strict=False)
        n   = int(net.num_addresses)
        return max(n - 2, 1) if net.prefixlen < 31 else n
    except ValueError:
        pass
    if "-" in spec:
        parts = spec.split("-", 1)
        try:
            start = ipaddress.IPv4Address(parts[0].strip())
            end_s = parts[1].strip()
            try:
                end = ipaddress.IPv4Address(end_s)
            except ipaddress.AddressValueError:
                prefix = ".".join(str(start).split(".")[:3])
                end    = ipaddress.IPv4Address(f"{prefix}.{end_s}")
            return int(end) - int(start) + 1
        except (ValueError, ipaddress.AddressValueError):
            pass
    return 1


def _iter_file(path: Path):
    """
    Yield (host, source_spec) pairs from a target file (lazy).
    Auto-detects fastcheck .jsonl and extracts only 'up' hosts.
    Plain text: one target per line, # = comment.
    """
    if _is_fastcheck_jsonl(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("status") == "up" and r.get("target"):
                        yield r["target"], str(path)
                except json.JSONDecodeError:
                    pass
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for host in expand_target(line):
                    yield host, line


def _count_file(path: Path) -> int:
    if _is_fastcheck_jsonl(path):
        count = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    if r.get("status") == "up" and r.get("target"):
                        count += 1
                except json.JSONDecodeError:
                    pass
        return count
    count = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                count += _count_spec(line)
    return count


def resolve_targets(args):
    """
    Return (total, generator_factory).
    The factory is a callable that returns a fresh (host, spec) generator.
    Memory stays flat regardless of total count.
    """
    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.exit(f"[ERROR] File not found: {args.file}")
        return _count_file(path), lambda: _iter_file(path)

    if args.target:
        hosts = list(expand_target(args.target))
        return len(hosts), lambda: ((h, args.target) for h in expand_target(args.target))

    sys.exit("[ERROR] Provide a TARGET or use -f FILE.")


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Resume: completed hosts are tracked via the output file itself
# ══════════════════════════════════════════════════════════════════════════════

def load_completed(out_path: Path) -> set:
    """
    Read the output file and return the set of already-scanned targets.
    Re-running the same command skips these hosts automatically.
    """
    completed = set()
    if not out_path or not out_path.exists():
        return completed
    with open(out_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                r = json.loads(line)
                if "target" in r:
                    completed.add(r["target"])
            except json.JSONDecodeError:
                pass
    return completed


# ══════════════════════════════════════════════════════════════════════════════
# 4 — nmap scan
# ══════════════════════════════════════════════════════════════════════════════

def check_nmap() -> str:
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


def scan_target(target: str, timeout: int) -> dict:
    """
    Run  nmap -n --top-ports 100 --min-rate 300 -sV  against one target.

    -n               skip DNS resolution  (faster, no resolver noise)
    --top-ports 100  scan the 100 most commonly seen ports
    --min-rate 300   enforce ≥ 300 packets/sec  (fast but not flood-level)
    -sV              detect service name and version on open ports
    --host-timeout   abort if the host takes longer than this
    -oX -            structured XML output to stdout
    """
    t_start = time.monotonic()
    result  = {
        "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
        "target":          target,
        "input":           target,       # overwritten by caller
        "host_status":     "unknown",
        "open_ports":      [],
        "ports":           [],
        "hostname":        None,
        "scan_duration_s": None,
        "nmap_version":    NMAP_VERSION,
    }

    cmd = [
        "nmap", "-n",
        "--top-ports", "100",
        "--min-rate",  "300",
        "-sV",
        "--host-timeout", f"{timeout}s",
        "-oX", "-",
        target,
    ]

    try:
        proc   = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
        stderr = proc.stderr.decode(errors="replace")
        _parse_scan_xml(proc.stdout.decode(errors="replace"), result)
        if result["host_status"] == "unknown" and stderr.strip():
            result["host_status"] = "error"
            result["error"]       = stderr.splitlines()[0][:100]
    except subprocess.TimeoutExpired:
        result["host_status"] = "timeout"
    except Exception as exc:
        result["host_status"] = "error"
        result["error"]       = str(exc)

    result["scan_duration_s"] = round(time.monotonic() - t_start, 2)
    return result


def _parse_scan_xml(xml: str, result: dict):
    """Extract host status, open ports, and service versions from nmap XML."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        result["host_status"] = "error"
        result["error"]       = "nmap XML parse error"
        return

    host_el = root.find("host")
    if host_el is None:
        result["host_status"] = "no_response"
        return

    st = host_el.find("status")
    if st is not None:
        result["host_status"] = st.get("state", "unknown")

    for hn in host_el.findall(".//hostname"):
        if hn.get("type") in ("PTR", "user"):
            result["hostname"] = hn.get("name")
            break

    ports = []
    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        info = {
            "port":     int(port_el.get("portid", 0)),
            "protocol": port_el.get("protocol", "tcp"),
            "state":    "open",
            "service":  "",
            "version":  "",
        }
        svc = port_el.find("service")
        if svc is not None:
            info["service"] = svc.get("name", "")
            parts = [
                svc.get("product",   ""),
                svc.get("version",   ""),
                svc.get("extrainfo", ""),
            ]
            info["version"] = " ".join(p for p in parts if p)

        ports.append(info)

    result["ports"]      = sorted(ports, key=lambda p: p["port"])
    result["open_ports"] = [p["port"] for p in result["ports"]]

    finished = root.find(".//finished")
    if finished is not None:
        elapsed = finished.get("elapsed")
        if elapsed:
            result["scan_duration_s"] = float(elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Live display
# ══════════════════════════════════════════════════════════════════════════════
#
# Fixed header / scrolling viewport / fixed footer — same layout as fastcheck.
# The scroll region uses ANSI  \033[top;botr  so the header and footer are
# never disturbed by new result lines appearing at the bottom of the viewport.

class LiveDisplay:
    HEADER = 4
    FOOTER = 3

    def __init__(self, total, workers, timeout, out_path, nmap_ver):
        cols, rows = shutil.get_terminal_size((80, 24))
        self.total   = total
        self.cols    = cols
        self.rows    = rows
        self.v_start = self.HEADER + 1
        self.v_end   = max(self.v_start + 2, rows - self.FOOTER)
        self.f_sep   = self.v_end + 1
        self.f_stats = self.v_end + 2
        self.lock    = threading.Lock()
        self.done    = 0
        self.counts  = {"open": 0, "none": 0, "other": 0}
        self._paused = False

        o   = sys.stdout
        bar = "─" * cols

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")

        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  scantop100  ·  nmap {nmap_ver}{RESET}")
        self._at(3)
        info = f"  Targets: {total}  Workers: {workers}  Timeout: {timeout}s"
        if out_path:
            info += f"  →  {out_path}"
        o.write(info)
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        self._at(self.f_sep);  o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()

        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

    def _at(self, row, col=1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _draw_stats(self):
        o    = sys.stdout
        pct  = self.done / self.total if self.total else 0
        bw   = max(10, min(28, self.cols - 56))
        fill = int(bw * pct)
        bar  = f"{'█' * fill}{'░' * (bw - fill)}"
        self._at(self.f_stats)
        o.write("\033[K")
        base = (
            f"  {GREEN}Open: {self.counts['open']:<5}{RESET}"
            f"  {DIM}None: {self.counts['none']:<5}{RESET}"
            f"  {CYAN}[{bar}]{RESET}  {self.done}/{self.total}"
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

    def add_result(self, result: dict):
        target     = result.get("target", "?")
        host_st    = result.get("host_status", "?")
        open_ports = result.get("open_ports", [])
        duration   = result.get("scan_duration_s")
        w          = len(str(self.total))
        dur_s      = f"{duration:.0f}s" if duration is not None else ""

        if open_ports:
            shown    = open_ports[:8]
            overflow = f" +{len(open_ports)-8}" if len(open_ports) > 8 else ""
            st_s     = f"{GREEN}{BOLD}open{RESET}"
            detail   = f"{GREEN}{' '.join(str(p) for p in shown)}{overflow}{RESET}"
        elif host_st in ("up", "unknown"):
            st_s   = f"{DIM}none{RESET}"
            detail = f"{DIM}{dur_s}{RESET}"
        elif host_st == "no_response":
            st_s   = f"{RED}down{RESET}"
            detail = ""
        elif host_st == "timeout":
            st_s   = f"{YELLOW}tout{RESET}"
            detail = f"{DIM}{dur_s}{RESET}"
        else:
            err    = result.get("error", "")[:35]
            st_s   = f"{RED}err {RESET}"
            detail = f"{RED}{err}{RESET}"

        with self.lock:
            self.done += 1
            if open_ports:                                       self.counts["open"]  += 1
            elif host_st in ("up", "unknown", "no_response"):   self.counts["none"]  += 1
            else:                                                self.counts["other"] += 1

            counter = f"{CYAN}[{self.done:{w}}/{self.total}]{RESET}"
            line    = f"{counter}  {target:<20}  {st_s}  {detail}"

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
    """Fallback for non-TTY output (piped / redirected)."""

    def __init__(self, total, workers, timeout, out_path, nmap_ver):
        self.total  = total
        self.lock   = threading.Lock()
        self.done   = 0
        self.counts = {"open": 0, "none": 0, "other": 0}
        bar = "─" * 62
        print(f"\n{bar}")
        print(f"  scantop100  ·  nmap {nmap_ver}")
        print(f"  Targets: {total}  Workers: {workers}  Timeout: {timeout}s"
              + (f"  →  {out_path}" if out_path else ""))
        print(f"{bar}\n")

    def set_paused(self, paused: bool):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def add_result(self, result: dict):
        target     = result.get("target", "?")
        open_ports = result.get("open_ports", [])
        w          = len(str(self.total))
        port_s     = " ".join(str(p) for p in open_ports) if open_ports else "(none)"
        with self.lock:
            self.done += 1
            if open_ports: self.counts["open"]  += 1
            else:          self.counts["none"]  += 1
            print(f"[{self.done:{w}}/{self.total}]  {target:<20}  {port_s}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 6 — Output file
# ══════════════════════════════════════════════════════════════════════════════

def prompt_output_path() -> Path:
    default = f"scantop100_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
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
    with _file_lock:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        fh.flush()


# ══════════════════════════════════════════════════════════════════════════════
# 7 — CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global NMAP_VERSION

    parser = argparse.ArgumentParser(
        prog="scantop100",
        description="Top-100 port scan with service detection using nmap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scantop100.py 192.168.1.1\n"
            "  python scantop100.py 192.168.1.0/24 -o ports.jsonl\n"
            "  python scantop100.py -f fastcheck_results.jsonl -o ports.jsonl\n"
            "  python scantop100.py -f targets.txt -o ports.jsonl -w 10\n"
        ),
    )
    parser.add_argument("target",       nargs="?",     metavar="TARGET",
                        help="IP, CIDR (10.0.0.0/24), range (10.0.0.1-50), or hostname.")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="Target file: plain text or fastcheck .jsonl (up hosts only).")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output .jsonl file. Prompted if omitted and multiple targets.")
    parser.add_argument("-w", "--workers", type=int, default=5, metavar="N",
                        help="Parallel nmap processes (default: 5).")
    parser.add_argument("--timeout",    type=int, default=120, metavar="SEC",
                        help="Per-host nmap timeout in seconds (default: 120).")
    parser.add_argument("--open-only",  action="store_true",
                        help="Only write hosts with at least one open port.")

    args = parser.parse_args()

    NMAP_VERSION  = check_nmap()
    total, gen_fn = resolve_targets(args)
    multi         = total > 1

    # ── Output path ───────────────────────────────────────────────────────────
    out_path = None
    if args.output:
        out_path = Path(args.output)
    elif multi:
        out_path = prompt_output_path()

    # ── Resume ────────────────────────────────────────────────────────────────
    completed = load_completed(out_path)
    remaining = total - len(completed)
    if completed:
        print(
            f"\n{YELLOW}Resume:{RESET} {len(completed):,} already scanned, "
            f"{remaining:,} remaining."
        )

    # ── Signal handler ────────────────────────────────────────────────────────
    signal.signal(signal.SIGINT, _sigint_handler)

    # ── Display ───────────────────────────────────────────────────────────────
    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(remaining or total, args.workers, args.timeout, out_path, NMAP_VERSION)

    # ── File (append on resume, fresh write otherwise) ────────────────────────
    fh = open(out_path, "a" if completed else "w", encoding="utf-8") if out_path else None

    def run_one(host: str, input_spec: str):
        if not wait_if_paused(display):
            return
        if _quit_event.is_set():
            return
        result          = scan_target(host, args.timeout)
        result["input"] = input_spec
        display.add_result(result)
        if fh and (not args.open_only or result.get("open_ports")):
            write_record(fh, result)

    # ── Bounded sliding-window scan (memory-flat for any target count) ────────
    MAX_PENDING = args.workers * 4

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            gen     = ((h, inp) for h, inp in gen_fn() if h not in completed)
            pending = set()
            for host, inp in itertools.islice(gen, MAX_PENDING):
                pending.add(pool.submit(run_one, host, inp))
            while pending and not _quit_event.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    f.result()
                if not _quit_event.is_set():
                    for host, inp in itertools.islice(gen, len(done)):
                        pending.add(pool.submit(run_one, host, inp))
    except Exception:
        pass
    finally:
        display.finish()
        if fh:
            fh.close()

    # ── Summary ───────────────────────────────────────────────────────────────
    c   = display.counts
    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"  {GREEN}With open ports  : {c['open']}{RESET}")
    print(f"  {DIM}No open ports    : {c['none']}{RESET}")
    if c["other"]:
        print(f"  {YELLOW}Errors / timeout : {c['other']}{RESET}")
    if out_path and out_path.exists():
        sz  = out_path.stat().st_size
        tot = c["open"] + c["none"] + c["other"]
        print(f"  Output           : {out_path}  ({sz:,} bytes, {tot} records)")
    if _quit_event.is_set() and out_path:
        print(
            f"\n  {YELLOW}Scan stopped — re-run the same command to resume.{RESET}"
        )
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
