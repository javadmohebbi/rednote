#!/usr/bin/env python3
"""
http.intruder.py  —  HTTP request intruder
==========================================
Sends templated HTTP requests with payload substitution, like Burp Suite Intruder.
Placeholders use the format  $$$_KEYNAME_$$$  anywhere in the request.

Attack modes
  sniper        One payload set; each position attacked one at a time,
                others filled with empty string (or configured base value)
  battering_ram One payload set; same value injected into every position
  pitchfork     One payload per position; all sets iterated in lock-step
  cluster_bomb  One payload per position; every combination tested (default)

Payload types (defined per-key in the config)
  file          Line-by-line from a wordlist — supports files with millions of entries
  bruteforce    All character-set combinations for a given length range
  list          Inline values array in the config
  numbers       Integer range with optional Python format string  (e.g. "{:04d}")

  python http.intruder.py config.json
  python http.intruder.py config.json --fresh   ← ignore previous run state

Pause / resume
  Ctrl+C        pause  (in-flight requests finish first)
  Enter         resume
  Ctrl+C again  quit and save state
  Re-run        prompted: continue or start fresh

No pip packages required — stdlib only.
"""

import sys
import re
import json
import time
import math
import signal
import shutil
import argparse
import itertools
import threading
import http.client
import ssl
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from pathlib import Path
from urllib.parse import urlparse


# ── ANSI codes ────────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[32m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"

# Placeholder regex:  $$$_KEYNAME_$$$
PLACEHOLDER_RE = re.compile(r'\$\$\$_([A-Z0-9_]+)_\$\$\$')


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
    resume = threading.Event()

    def _read():
        try:
            sys.stdin.readline()
        except Exception:
            pass
        resume.set()

    threading.Thread(target=_read, daemon=True).start()
    while _pause_event.is_set() and not _quit_event.is_set():
        if resume.is_set():
            _pause_event.clear()
            break
        time.sleep(0.1)
    display.set_paused(False)
    return not _quit_event.is_set()


# ══════════════════════════════════════════════════════════════════════════════
# 2 — Config loading and validation
# ══════════════════════════════════════════════════════════════════════════════

DEFAULTS = {
    "attack_mode":  "cluster_bomb",
    "match": {
        "status_codes":          [],
        "response_contains":     [],
        "response_not_contains": [],
        "length_not_equals":     None,
        "length_less_than":      None,
        "length_greater_than":   None,
    },
    "stop": {
        "on_first_match": False,
        "max_matches":    0,
        "max_requests":   0,
    },
    "options": {
        "workers":                20,
        "timeout":                10,
        "delay_ms":               0,
        "follow_redirects":       False,
        "verify_ssl":             False,
        "update_content_length":  True,
        "save_matches_only":      False,
        "output":                 None,
        "save_response_body":     False,
    },
}


def load_config(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"[ERROR] Config file not found: {path}")
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"[ERROR] Invalid JSON in config: {e}")

    # Merge defaults
    for section, vals in DEFAULTS.items():
        if section not in cfg:
            cfg[section] = vals if isinstance(vals, dict) else vals
        elif isinstance(vals, dict):
            for k, v in vals.items():
                cfg[section].setdefault(k, v)

    # Validate required fields
    if "target" not in cfg:
        sys.exit("[ERROR] Config must have a 'target' field (e.g. 'https://example.com')")
    if "request" not in cfg:
        sys.exit("[ERROR] Config must have a 'request' field pointing to the request template file")
    if "payloads" not in cfg or not cfg["payloads"]:
        sys.exit("[ERROR] Config must have a 'payloads' section with at least one key")

    return cfg


def load_request_template(cfg: dict, config_dir: Path) -> str:
    req_path = config_dir / cfg["request"]
    if not req_path.exists():
        sys.exit(f"[ERROR] Request file not found: {req_path}")
    return req_path.read_text(encoding="utf-8", errors="replace")


def extract_keys(template: str) -> list:
    """Return ordered list of unique placeholder key names found in the template."""
    return list(dict.fromkeys(PLACEHOLDER_RE.findall(template)))


# ══════════════════════════════════════════════════════════════════════════════
# 3 — Payload generators  (all lazy — O(1) memory regardless of size)
# ══════════════════════════════════════════════════════════════════════════════

def make_generator(spec: dict, config_dir: Path):
    """Return a fresh generator for one payload spec."""
    t = spec.get("type", "file")

    if t == "file":
        path = config_dir / spec["path"]
        if not path.exists():
            sys.exit(f"[ERROR] Payload file not found: {path}")
        def _file():
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield line.rstrip("\n")
        return _file

    if t == "bruteforce":
        charset  = spec.get("charset", "abcdefghijklmnopqrstuvwxyz")
        min_len  = int(spec.get("min_length", 1))
        max_len  = int(spec.get("max_length", 4))
        chars    = list(charset)
        def _brute():
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(chars, repeat=length):
                    yield "".join(combo)
        return _brute

    if t == "list":
        values = list(spec.get("values", []))
        def _list():
            yield from values
        return _list

    if t == "numbers":
        start  = int(spec.get("start", 0))
        end    = int(spec.get("end",   100))
        step   = int(spec.get("step",  1))
        fmt    = spec.get("format", None)
        def _nums():
            for i in range(start, end + 1, step):
                yield fmt.format(i) if fmt else str(i)
        return _nums

    sys.exit(f"[ERROR] Unknown payload type: '{t}'")


def count_payload(spec: dict, config_dir: Path) -> int:
    """Count payload size without materialising. Returns -1 if unknown."""
    t = spec.get("type", "file")
    if t == "file":
        path = config_dir / spec["path"]
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    if t == "bruteforce":
        charset = spec.get("charset", "abcdefghijklmnopqrstuvwxyz")
        mn, mx  = int(spec.get("min_length", 1)), int(spec.get("max_length", 4))
        c       = len(charset)
        return sum(c**l for l in range(mn, mx + 1))
    if t == "list":
        return len(spec.get("values", []))
    if t == "numbers":
        return max(0, (int(spec.get("end", 100)) - int(spec.get("start", 0))) // int(spec.get("step", 1)) + 1)
    return -1


# ══════════════════════════════════════════════════════════════════════════════
# 4 — Attack combination generators
# ══════════════════════════════════════════════════════════════════════════════

def build_attack_gen(mode: str, keys: list, gen_factories: dict, base_values: dict):
    """
    Return a generator that yields {KEY: value, ...} dicts for each request.

    sniper        — one payload set (first key); each key attacked in turn,
                    others get their base_value (default "")
    battering_ram — one payload set (first key); all keys get the same value
    pitchfork     — parallel iteration across all keys (stops at shortest)
    cluster_bomb  — cartesian product of all payload sets
    """
    if mode == "sniper":
        first_key  = keys[0]
        first_gen  = gen_factories[first_key]
        for key in keys:
            for val in first_gen():
                payloads = {k: base_values.get(k, "") for k in keys}
                payloads[key] = val
                yield payloads

    elif mode == "battering_ram":
        first_key = keys[0]
        for val in gen_factories[first_key]():
            yield {k: val for k in keys}

    elif mode == "pitchfork":
        gens = [gen_factories[k]() for k in keys]
        for vals in zip(*gens):
            yield dict(zip(keys, vals))

    else:  # cluster_bomb (default)
        gens = [gen_factories[k]() for k in keys]
        for combo in itertools.product(*gens):
            yield dict(zip(keys, combo))


def count_total(mode: str, keys: list, payload_specs: dict, config_dir: Path) -> int:
    """Count total combinations without materialising."""
    sizes = []
    for k in keys:
        n = count_payload(payload_specs[k], config_dir)
        if n < 0:
            return -1
        sizes.append(n)

    if not sizes:
        return 0
    if mode == "sniper":
        return sizes[0] * len(keys)   # same payload set for each position
    if mode == "battering_ram":
        return sizes[0]
    if mode == "pitchfork":
        return min(sizes)
    # cluster_bomb
    result = 1
    for s in sizes:
        result *= s
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 5 — Request template substitution + parsing
# ══════════════════════════════════════════════════════════════════════════════

def apply_payloads(template: str, payloads: dict, update_cl: bool) -> str:
    """Substitute all placeholders in the template with payload values."""
    result = template
    for key, value in payloads.items():
        result = result.replace(f"$$$_{key}_$$$", value)
    # Remove any un-substituted placeholders
    result = PLACEHOLDER_RE.sub("", result)

    # Optionally recalculate Content-Length
    if update_cl and "\r\n\r\n" in result:
        head, _, body = result.partition("\r\n\r\n")
    elif "\n\n" in result:
        head, _, body = result.partition("\n\n")
    else:
        return result

    if update_cl and body:
        body_bytes = body.encode("utf-8", errors="replace")
        # Replace Content-Length header
        head = re.sub(
            r"(?i)content-length\s*:\s*\d+",
            f"Content-Length: {len(body_bytes)}",
            head,
        )
        sep = "\r\n\r\n" if "\r\n\r\n" in result else "\n\n"
        return head + sep + body
    return result


def parse_raw_request(raw: str) -> tuple:
    """
    Parse a raw HTTP/1.1 request string.
    Returns (method, path, headers_dict, body_str).
    """
    # Normalise line endings
    raw = raw.replace("\r\n", "\n")
    lines = raw.split("\n")

    # First line: METHOD /path HTTP/1.1
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2:
        sys.exit(f"[ERROR] Could not parse request line: {first!r}")
    method = parts[0].upper()
    path   = parts[1]

    # Headers until blank line
    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1

    # Body (everything after blank line)
    body = "\n".join(lines[i + 1:]).strip() if i < len(lines) else ""
    return method, path, headers, body


# ══════════════════════════════════════════════════════════════════════════════
# 6 — HTTP request sending
# ══════════════════════════════════════════════════════════════════════════════

def send_request(target: str, method: str, path: str,
                 headers: dict, body: str,
                 timeout: int, verify_ssl: bool,
                 follow_redirects: bool) -> dict:
    """
    Send one HTTP request and return a result dict.
    Uses http.client (stdlib) — no external dependencies.
    """
    t_start = time.monotonic()
    result  = {
        "status":   0,
        "length":   0,
        "time_ms":  0,
        "headers":  {},
        "body":     "",
        "error":    None,
    }

    try:
        parsed  = urlparse(target)
        use_ssl = parsed.scheme.lower() == "https"
        host    = parsed.hostname or ""
        port    = parsed.port or (443 if use_ssl else 80)

        if use_ssl:
            ctx = ssl.create_default_context() if verify_ssl \
                  else ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        body_bytes = body.encode("utf-8", errors="replace") if body else b""
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()

        result["status"]  = resp.status
        result["headers"] = dict(resp.getheaders())

        # Read at most 256 KB of the response body
        raw_body = resp.read(262144)
        result["length"]  = int(resp.getheader("Content-Length") or len(raw_body))
        result["body"]    = raw_body.decode("utf-8", errors="replace")
        conn.close()

        # Follow redirects (max 5 hops)
        if follow_redirects and resp.status in (301, 302, 303, 307, 308):
            location = result["headers"].get("Location", result["headers"].get("location", ""))
            if location:
                redirect_target = location if location.startswith("http") else target
                redirect_path   = location if not location.startswith("http") else urlparse(location).path
                r2 = send_request(redirect_target, "GET", redirect_path,
                                  {k: v for k, v in headers.items() if k.lower() != "content-length"},
                                  "", timeout, verify_ssl, follow_redirects=False)
                result["status"]  = r2["status"]
                result["length"]  = r2["length"]
                result["body"]    = r2["body"]
                result["headers"] = r2["headers"]

    except http.client.RemoteDisconnected:
        result["error"] = "remote disconnected"
    except TimeoutError:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except Exception as exc:
        result["error"] = str(exc)[:80]

    result["time_ms"] = round((time.monotonic() - t_start) * 1000)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 7 — Match and stop evaluation
# ══════════════════════════════════════════════════════════════════════════════

def is_match(resp: dict, match_cfg: dict) -> bool:
    """Return True if the response meets any of the configured match criteria."""
    status = resp.get("status", 0)
    body   = resp.get("body", "")
    length = resp.get("length", 0)

    if match_cfg.get("status_codes") and status in match_cfg["status_codes"]:
        return True
    for text in match_cfg.get("response_contains", []):
        if text in body:
            return True
    for text in match_cfg.get("response_not_contains", []):
        if text not in body:
            return True
    if match_cfg.get("length_not_equals") is not None \
            and length != match_cfg["length_not_equals"]:
        return True
    if match_cfg.get("length_less_than") is not None \
            and length < match_cfg["length_less_than"]:
        return True
    if match_cfg.get("length_greater_than") is not None \
            and length > match_cfg["length_greater_than"]:
        return True
    return False


def should_stop(match: bool, stop_cfg: dict, match_count: int, req_count: int) -> bool:
    """Return True if the attack should be halted."""
    if stop_cfg.get("on_first_match") and match:
        return True
    if stop_cfg.get("max_matches") and match_count >= stop_cfg["max_matches"]:
        return True
    if stop_cfg.get("max_requests") and req_count >= stop_cfg["max_requests"]:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# 8 — State management  (pause / resume / restart)
# ══════════════════════════════════════════════════════════════════════════════

def state_path(output_file: Path) -> Path:
    return output_file.with_suffix(output_file.suffix + ".state")


def save_state(output_file: Path, completed: int, matches: int, started: str):
    sp = state_path(output_file)
    sp.write_text(json.dumps({
        "output":       str(output_file),
        "completed":    completed,
        "matches":      matches,
        "started":      started,
        "last_updated": datetime.now(tz=timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")


def load_state(output_file: Path) -> dict | None:
    sp = state_path(output_file)
    if not sp.exists():
        return None
    try:
        return json.loads(sp.read_text(encoding="utf-8"))
    except Exception:
        return None


def ask_continue_or_start(state: dict) -> bool:
    """Prompt user. Returns True = continue, False = start fresh."""
    completed = state.get("completed", 0)
    matches   = state.get("matches", 0)
    started   = state.get("started", "?")
    print(
        f"\n{YELLOW}Previous run found:{RESET}"
        f"  {completed:,} requests completed,  {matches} matches"
        f"  (started {started[:19]})"
    )
    print(f"  Output: {state['output']}")
    while True:
        sys.stdout.write(f"\n  {BOLD}[1]{RESET} Continue  {BOLD}[2]{RESET} Start fresh: ")
        sys.stdout.flush()
        try:
            choice = input().strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if choice in ("1", ""):
            return True
        if choice == "2":
            return False


# ══════════════════════════════════════════════════════════════════════════════
# 9 — Live display
# ══════════════════════════════════════════════════════════════════════════════
#
# Layout
#   Row 1          ─── CYAN bar ────────────────────────────
#   Row 2          http.intruder  ·  mode  ·  target
#   Row 3          Total: N  Workers: W  Output: file.jsonl
#   Row 4          ─── CYAN bar ────────────────────────────
#   Row 5          Active:
#   Rows 6..5+W    One row per worker — current payload values
#   Row 6+W        ─── thin separator ──────────────────────
#   Rows 7+W..vend SCROLL REGION — results scroll upward
#   Row vend+1     ─── separator ───────────────────────────
#   Row vend+2     Done: N  Matches: N  [████░░]  Ctrl+C pause

class LiveDisplay:
    HEADER = 4
    FOOTER = 3

    def __init__(self, total: int, workers: int, mode: str, target: str, output_file: Path):
        cols, rows   = shutil.get_terminal_size((80, 24))
        self.total   = total
        self.cols    = cols
        self.rows    = rows
        self.lock    = threading.RLock()
        self.done    = 0
        self.matches = 0
        self._paused = False
        self._stopped = False

        self.w_shown = min(workers, max(1, rows - self.HEADER - self.FOOTER - 4))
        self._r_label  = self.HEADER + 1
        self._r_w0     = self.HEADER + 2
        self._r_wsep   = self.HEADER + 2 + self.w_shown
        self.v_start   = self.HEADER + 3 + self.w_shown
        self.v_end     = max(self.v_start + 1, rows - self.FOOTER)
        self.f_sep     = self.v_end + 1
        self.f_stats   = self.v_end + 2

        self._slots       = {}   # slot_idx → {payloads_str, t}
        self._tid_to_slot = {}

        o   = sys.stdout
        bar = "─" * cols
        total_s = f"{total:,}" if total >= 0 else "?"

        o.write("\033[2J\033[H")
        o.write("\033[?25l")
        o.write("\033[?7l")

        self._at(1); o.write(f"{BOLD}{CYAN}{bar}{RESET}")
        self._at(2); o.write(f"{BOLD}  http.intruder  ·  {mode}  ·  {target}{RESET}")
        self._at(3); o.write(f"  Total: {total_s}  Workers: {workers}  Output: {output_file}")
        self._at(4); o.write(f"{BOLD}{CYAN}{bar}{RESET}")

        self._at(self._r_label); o.write(f"  {DIM}Active:{RESET}")
        for i in range(self.w_shown):
            self._at(self._r_w0 + i); o.write(f"  {DIM}w{i:<2}  ─{RESET}")

        self._at(self._r_wsep); o.write(f"{DIM}{bar}{RESET}")
        self._at(self.f_sep);   o.write(f"{DIM}{bar}{RESET}")
        self._draw_stats()

        o.write(f"\033[{self.v_start};{self.v_end}r")
        self._at(self.v_end)
        o.flush()

        threading.Thread(target=self._ticker, daemon=True).start()

    def _at(self, row, col=1):
        sys.stdout.write(f"\033[{row};{col}H")

    def _fmt_total(self) -> str:
        return f"{self.total:,}" if self.total >= 0 else "?"

    def _draw_stats(self):
        o    = sys.stdout
        pct  = self.done / self.total if self.total > 0 else 0
        bw   = max(10, min(24, self.cols - 56))
        fill = int(bw * pct)
        bar  = f"{'█' * fill}{'░' * (bw - fill)}"
        self._at(self.f_stats)
        o.write("\033[K")
        base = (
            f"  {GREEN}Done: {self.done:,}/{self._fmt_total()}{RESET}"
            f"  {MAGENTA}Matches: {self.matches}{RESET}"
            f"  {CYAN}[{bar}]{RESET}"
        )
        if self._paused:
            o.write(base + f"  {YELLOW}{BOLD}⏸ PAUSED{RESET}  ↵ resume  ·  Ctrl+C quit")
        else:
            o.write(base + f"  {DIM}Ctrl+C pause{RESET}")

    def _redraw_slot(self, idx: int):
        row = self._r_w0 + idx
        if row > self._r_wsep - 1:
            return
        o = sys.stdout
        self._at(row, 1)
        o.write("\033[K")
        slot = self._slots.get(idx)
        if slot:
            elapsed = int(time.monotonic() - slot["t"])
            ps      = slot["payloads"][:self.cols - 20]
            o.write(f"  {CYAN}w{idx:<2}{RESET}  {YELLOW}{ps}{RESET}  {DIM}{elapsed}s{RESET}")
        else:
            o.write(f"  {DIM}w{idx:<2}  ─{RESET}")

    def _ticker(self):
        while not self._stopped:
            time.sleep(2)
            with self.lock:
                if self._stopped:
                    break
                for idx in list(self._slots):
                    self._redraw_slot(idx)
                self._at(self.v_end)
                sys.stdout.flush()

    # ── Slot API ──────────────────────────────────────────────────────────────

    def claim_slot(self, payloads_str: str):
        tid = threading.get_ident()
        with self.lock:
            used = set(self._slots)
            idx  = next((i for i in range(self.w_shown) if i not in used), 0)
            self._slots[idx]      = {"payloads": payloads_str, "t": time.monotonic()}
            self._tid_to_slot[tid] = idx
            self._redraw_slot(idx)
            self._at(self.v_end)
            sys.stdout.flush()

    def release_slot(self):
        tid = threading.get_ident()
        with self.lock:
            idx = self._tid_to_slot.pop(tid, None)
            if idx is not None:
                self._slots.pop(idx, None)
                self._redraw_slot(idx)
                self._at(self.v_end)
                sys.stdout.flush()

    # ── Result display ────────────────────────────────────────────────────────

    def set_paused(self, paused: bool):
        with self.lock:
            self._paused = paused
            self._draw_stats()
            self._at(self.v_end)
            sys.stdout.flush()

    def add_result(self, seq: int, payloads: dict, resp: dict, match: bool):
        status  = resp.get("status", 0)
        length  = resp.get("length", 0)
        time_ms = resp.get("time_ms", 0)
        error   = resp.get("error")
        w       = max(7, len(str(self.total))) if self.total >= 0 else 7

        # Payload summary: show first 2 keys
        items   = list(payloads.items())
        pay_s   = "  ".join(f"{k}={v}" for k, v in items[:2])
        if len(items) > 2:
            pay_s += f"  +{len(items)-2}"
        pay_s = pay_s[:30]

        if error:
            st_s  = f"{RED}{error[:12]}{RESET}"
            info_s = ""
        elif match:
            st_s  = f"{MAGENTA}{BOLD}{status}{RESET}"
            info_s = f"  {length}b  {time_ms}ms  {MAGENTA}{BOLD}★ MATCH{RESET}"
        else:
            col   = GREEN if 200 <= status < 300 else (YELLOW if 300 <= status < 400 else RED)
            st_s  = f"{col}{status}{RESET}"
            info_s = f"  {DIM}{length}b  {time_ms}ms{RESET}"

        with self.lock:
            self.done += 1
            if match:
                self.matches += 1

            counter = f"{CYAN}[{seq:{w}}]{RESET}"
            line    = f"{counter}  {pay_s:<32}  {st_s}{info_s}"

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
    def __init__(self, total, workers, mode, target, output_file):
        self.total   = total
        self.lock    = threading.Lock()
        self.done    = 0
        self.matches = 0
        total_s = f"{total:,}" if total >= 0 else "?"
        bar = "─" * 62
        print(f"\n{bar}")
        print(f"  http.intruder  ·  {mode}  ·  {target}")
        print(f"  Total: {total_s}  Workers: {workers}  Output: {output_file}")
        print(f"{bar}")
        print("  Ctrl+C pause  ·  Enter resume  ·  Ctrl+C quit\n")

    def claim_slot(self, payloads_str):
        pass

    def release_slot(self):
        pass

    def set_paused(self, paused):
        if paused:
            print("[PAUSED]  Press Enter to resume or Ctrl+C to quit...")

    def add_result(self, seq, payloads, resp, match):
        status  = resp.get("status", 0)
        length  = resp.get("length", 0)
        time_ms = resp.get("time_ms", 0)
        pay_s   = "  ".join(f"{k}={v}" for k, v in list(payloads.items())[:2])
        with self.lock:
            self.done += 1
            if match:
                self.matches += 1
            flag = "  ★ MATCH" if match else ""
            print(f"[{seq}]  {pay_s:<30}  {status}  {length}b  {time_ms}ms{flag}")

    def finish(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 10 — Output file
# ══════════════════════════════════════════════════════════════════════════════

_out_lock = threading.Lock()


def write_result(fh, seq: int, payloads: dict, resp: dict, match: bool,
                 save_body: bool):
    rec = {
        "seq":      seq,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "payloads": payloads,
        "status":   resp.get("status", 0),
        "length":   resp.get("length", 0),
        "time_ms":  resp.get("time_ms", 0),
        "match":    match,
    }
    if resp.get("error"):
        rec["error"] = resp["error"]
    if save_body and match:
        rec["response_body"] = resp.get("body", "")
    with _out_lock:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()


# ══════════════════════════════════════════════════════════════════════════════
# 11 — Test run
# ══════════════════════════════════════════════════════════════════════════════

def test_run(cfg: dict, config_dir: Path):
    """
    Send exactly one request using the first value from each payload (or the
    configured test_value) and print the full request + response.
    Exits after printing — does not write output or touch any state file.
    """
    opts     = cfg["options"]
    target   = cfg["target"].rstrip("/")
    template = load_request_template(cfg, config_dir)
    keys     = extract_keys(template)

    bar  = "─" * 64
    wide = "═" * 64

    # ── Build test payloads ───────────────────────────────────────────────────
    test_val = opts.get("test_value", "TEST")
    payloads = {}
    for k in keys:
        spec = cfg["payloads"].get(k, {})
        # Use explicit test_value first, then first value from generator
        if spec.get("test_value"):
            payloads[k] = str(spec["test_value"])
        else:
            gen = make_generator(spec, config_dir)
            payloads[k] = next(iter(gen()), test_val)

    print(f"\n{BOLD}{CYAN}{wide}{RESET}")
    print(f"{BOLD}  http.intruder  ·  TEST RUN{RESET}")
    print(f"{BOLD}{CYAN}{wide}{RESET}\n")

    # ── Show substituted placeholders ─────────────────────────────────────────
    print(f"{BOLD}  Placeholders:{RESET}")
    for k, v in payloads.items():
        print(f"    {CYAN}$$$_{k}_$$${RESET}  →  {YELLOW}{v}{RESET}")
    print()

    # ── Substitute and parse ──────────────────────────────────────────────────
    raw    = apply_payloads(template, payloads, opts["update_content_length"])
    method, path, headers, body = parse_raw_request(raw)

    print(f"{BOLD}  Request:{RESET}")
    print(f"{DIM}{bar}{RESET}")
    print(f"  {BOLD}{method}{RESET} {target}{path}")
    for k, v in headers.items():
        print(f"  {DIM}{k}:{RESET} {v}")
    if body:
        print()
        print(f"  {body}")
    print(f"{DIM}{bar}{RESET}\n")

    # ── Send ──────────────────────────────────────────────────────────────────
    print(f"  {DIM}Sending…{RESET}", end="", flush=True)
    resp = send_request(
        target, method, path, headers, body,
        timeout      = opts["timeout"],
        verify_ssl   = opts["verify_ssl"],
        follow_redirects = opts["follow_redirects"],
    )
    print(f"\r{' '*20}\r", end="")

    # ── Show response ─────────────────────────────────────────────────────────
    status   = resp.get("status", 0)
    length   = resp.get("length", 0)
    time_ms  = resp.get("time_ms", 0)
    error    = resp.get("error")
    resp_hdr = resp.get("headers", {})
    resp_body = resp.get("body", "")

    status_col = GREEN if 200 <= status < 300 else (YELLOW if 300 <= status < 400 else RED)

    print(f"{BOLD}  Response:{RESET}")
    print(f"{DIM}{bar}{RESET}")

    if error:
        print(f"  {RED}Error: {error}{RESET}")
    else:
        print(f"  Status : {status_col}{BOLD}{status}{RESET}   Length: {length} bytes   Time: {time_ms} ms")
        print()
        for k, v in list(resp_hdr.items())[:15]:
            print(f"  {DIM}{k}:{RESET} {v}")
        if resp_body:
            print()
            preview = resp_body[:2000]
            for line in preview.splitlines()[:40]:
                print(f"  {DIM}{line}{RESET}")
            if len(resp_body) > 2000:
                print(f"  {DIM}… ({len(resp_body):,} bytes total){RESET}")

    print(f"{DIM}{bar}{RESET}\n")

    # ── Match evaluation against config criteria ──────────────────────────────
    match = is_match(resp, cfg["match"])
    print(f"  Match criteria : ", end="")
    if not any([
        cfg["match"].get("status_codes"),
        cfg["match"].get("response_contains"),
        cfg["match"].get("response_not_contains"),
        cfg["match"].get("length_not_equals"),
        cfg["match"].get("length_less_than"),
        cfg["match"].get("length_greater_than"),
    ]):
        print(f"{DIM}none configured{RESET}")
    elif match:
        print(f"{MAGENTA}{BOLD}★  This response would be flagged as a MATCH{RESET}")
    else:
        print(f"{DIM}no match (expected for a test with non-payload values){RESET}")

    print(f"\n  {DIM}Test complete. No output file written.{RESET}\n")
    sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# 12 — CLI / main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="http.intruder",
        description="HTTP request intruder with $$$_KEY_$$$ placeholder substitution.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python http.intruder.py config.json\n"
            "  python http.intruder.py config.json --fresh\n"
        ),
    )
    parser.add_argument("config",  metavar="CONFIG", help="Path to the JSON config file.")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore any previous run state and start from the beginning.")
    parser.add_argument("--test",  action="store_true",
                        help="Send one request using the first payload value, print the "
                             "full response, and exit. Verifies the template and target "
                             "are configured correctly before a full run.")
    args = parser.parse_args()

    config_path = Path(args.config)
    config_dir  = config_path.parent
    cfg         = load_config(config_path)
    opts        = cfg["options"]
    mode        = cfg.get("attack_mode", "cluster_bomb")
    target      = cfg["target"].rstrip("/")

    # ── Load request template ─────────────────────────────────────────────────
    template = load_request_template(cfg, config_dir)
    keys     = extract_keys(template)
    if not keys:
        sys.exit("[ERROR] No $$$_KEY_$$$ placeholders found in the request template.")

    # Check all keys have a payload definition
    for k in keys:
        if k not in cfg["payloads"]:
            sys.exit(f"[ERROR] Placeholder $$$_{k}_$$$ has no payload defined in config.")

    # ── Test mode — send one request and show result, then exit ───────────────
    if args.test:
        test_run(cfg, config_dir)

    # ── Output file ───────────────────────────────────────────────────────────
    if opts.get("output"):
        output_file = config_dir / opts["output"]
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = config_dir / f"{config_path.stem}_results_{ts}.jsonl"

    # ── Resume / fresh start ──────────────────────────────────────────────────
    state    = None
    skip     = 0
    started  = datetime.now(tz=timezone.utc).isoformat()

    if not args.fresh:
        state = load_state(output_file)
        if state:
            continue_run = ask_continue_or_start(state)
            if continue_run:
                skip    = state["completed"]
                started = state["started"]
                print(f"\n  {GREEN}Continuing from request {skip+1:,}{RESET}")
            else:
                state = None
                output_file.unlink(missing_ok=True)
                state_path(output_file).unlink(missing_ok=True)

    # ── Count total combinations (show counting message for large files) ──────
    print(f"\n  {DIM}Counting combinations…{RESET}", end="\r", flush=True)
    gen_factories  = {k: make_generator(cfg["payloads"][k], config_dir) for k in keys}
    base_values    = cfg.get("base_values", {})
    total          = count_total(mode, keys, cfg["payloads"], config_dir)
    remaining      = (total - skip) if total >= 0 else -1
    total_s        = f"{total:,}" if total >= 0 else "?"
    print(f"  Total combinations: {total_s}  (skipping first {skip:,})     ")

    # ── Setup signal handler + display ───────────────────────────────────────
    signal.signal(signal.SIGINT, _sigint_handler)
    Display = LiveDisplay if sys.stdout.isatty() else SimpleDisplay
    display = Display(remaining if remaining >= 0 else total,
                      opts["workers"], mode, target, output_file)

    # ── Shared counters ───────────────────────────────────────────────────────
    _seq_state  = {"n": skip}
    _match_cnt  = {"n": state["matches"] if state else 0}
    _req_cnt    = {"n": skip}
    _stop_flag  = threading.Event()
    _seq_lock   = threading.Lock()

    # ── State auto-save every 200 requests ───────────────────────────────────
    def _autosave():
        while not _stop_flag.is_set():
            time.sleep(10)
            save_state(output_file, _req_cnt["n"], _match_cnt["n"], started)
    threading.Thread(target=_autosave, daemon=True).start()

    # ── Open output file ──────────────────────────────────────────────────────
    fh = open(output_file, "a" if skip > 0 else "w", encoding="utf-8")

    def process_one(payloads: dict):
        if not wait_if_paused(display) or _quit_event.is_set() or _stop_flag.is_set():
            return

        pay_s = "  ".join(f"{k}={v}" for k, v in list(payloads.items())[:3])
        display.claim_slot(pay_s)

        try:
            # Substitute payloads into template
            raw = apply_payloads(template, payloads, opts["update_content_length"])
            method, path, headers, body = parse_raw_request(raw)

            # Optional delay
            if opts["delay_ms"] > 0:
                time.sleep(opts["delay_ms"] / 1000)

            resp  = send_request(target, method, path, headers, body,
                                 opts["timeout"], opts["verify_ssl"],
                                 opts["follow_redirects"])
            match = is_match(resp, cfg["match"])

            with _seq_lock:
                _seq_state["n"] += 1
                _req_cnt["n"]   += 1
                seq = _seq_state["n"]
                if match:
                    _match_cnt["n"] += 1
                mc = _match_cnt["n"]
                rc = _req_cnt["n"]

            display.release_slot()
            display.add_result(seq, payloads, resp, match)

            # Save result
            if not opts["save_matches_only"] or match:
                write_result(fh, seq, payloads, resp, match, opts["save_response_body"])

            # Check stop conditions
            if should_stop(match, cfg["stop"], mc, rc):
                _stop_flag.set()

        except Exception as exc:
            display.release_slot()
        finally:
            pass

    # ── Build attack generator, skip already-done combinations ───────────────
    MAX_PENDING = opts["workers"] * 4

    try:
        with ThreadPoolExecutor(max_workers=opts["workers"]) as pool:
            raw_gen = build_attack_gen(mode, keys, gen_factories, base_values)
            gen     = itertools.islice(raw_gen, skip, None)   # skip completed
            pending = set()

            for p in itertools.islice(gen, MAX_PENDING):
                if _stop_flag.is_set():
                    break
                pending.add(pool.submit(process_one, p))

            while pending and not _quit_event.is_set() and not _stop_flag.is_set():
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    f.result()
                if not _quit_event.is_set() and not _stop_flag.is_set():
                    for p in itertools.islice(gen, len(done)):
                        if _stop_flag.is_set():
                            break
                        pending.add(pool.submit(process_one, p))

    except Exception:
        pass
    finally:
        _stop_flag.set()
        save_state(output_file, _req_cnt["n"], _match_cnt["n"], started)
        display.finish()
        fh.close()

    # ── Final summary ─────────────────────────────────────────────────────────
    bar = "─" * 62
    print(f"{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"  {GREEN}Requests sent   : {_req_cnt['n']:,}{RESET}")
    print(f"  {MAGENTA}Matches found   : {_match_cnt['n']}{RESET}")
    print(f"  Output          : {output_file}")
    print(f"  State saved     : {state_path(output_file)}")
    if _quit_event.is_set():
        print(f"\n  {YELLOW}Paused — re-run to continue from request {_req_cnt['n']+1:,}.{RESET}")
    elif _stop_flag.is_set() and not _quit_event.is_set():
        print(f"\n  {GREEN}Stop condition met — attack halted.{RESET}")
    print(f"{BOLD}{CYAN}{bar}{RESET}\n")


if __name__ == "__main__":
    main()
