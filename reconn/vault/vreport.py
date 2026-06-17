#!/usr/bin/env python3
"""
vreport.py  —  vault intelligence reporter
==========================================
Query the vault SQLite database and group findings by OS, open port,
service, vulnerability severity, CVE, or host.

Usage
  python vreport.py --by os
  python vreport.py --by port
  python vreport.py --by service
  python vreport.py --by severity
  python vreport.py --by cve
  python vreport.py --by host
  python vreport.py --ip 192.168.1.1
  python vreport.py --by cve   --min-severity high
  python vreport.py --by port  --port 443
  python vreport.py --by host  --country US
"""

import sys
import json
import sqlite3
import argparse
from pathlib import Path

# ── ANSI ─────────────────────────────────────────────────────────────────────
_IS_TTY = sys.stdout.isatty()
RESET   = "\033[0m"  if _IS_TTY else ""
BOLD    = "\033[1m"  if _IS_TTY else ""
DIM     = "\033[2m"  if _IS_TTY else ""
GREEN   = "\033[32m" if _IS_TTY else ""
RED     = "\033[31m" if _IS_TTY else ""
YELLOW  = "\033[33m" if _IS_TTY else ""
CYAN    = "\033[36m" if _IS_TTY else ""
MAGENTA = "\033[35m" if _IS_TTY else ""

_SEV_COLOR = {
    "critical": RED + BOLD,
    "high":     RED,
    "medium":   YELLOW,
    "low":      DIM,
    "info":     DIM,
    "unknown":  DIM,
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def _sev_color(s: str) -> str:
    return _SEV_COLOR.get((s or "unknown").lower(), DIM)


def _bar(n: int, mx: int, width: int = 20) -> str:
    fill = int(width * n / mx) if mx else 0
    return f"{'█' * fill}{'░' * (width - fill)}"


def open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        sys.exit(f"[ERROR] Database not found: {path}\n"
                 f"        Run vault.py first to build it.")
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# ══════════════════════════════════════════════════════════════════════════════
# Reporters
# ══════════════════════════════════════════════════════════════════════════════

def _sep(width: int = 66):
    print(f"{CYAN}{'─' * width}{RESET}")


def report_by_os(conn: sqlite3.Connection, country: str | None):
    where = "WHERE h.country_code = ?" if country else ""
    params = (country,) if country else ()
    rows = conn.execute(
        f"""
        SELECT os, COUNT(*) AS n,
               GROUP_CONCAT(ip, ', ') AS ips
        FROM   hosts h
        {where}
        WHERE  scan_status = 'done'
        GROUP  BY os
        ORDER  BY n DESC
        """,
        params,
    ).fetchall()

    mx = max((r["n"] for r in rows), default=1)
    _sep()
    print(f"{BOLD}  Hosts grouped by OS{RESET}  ({len(rows)} unique)")
    _sep()
    for r in rows:
        os_s = r["os"] or "(unknown)"
        print(f"  {CYAN}{r['n']:>4}{RESET}  {_bar(r['n'], mx)}  {os_s}")
        for ip in (r["ips"] or "").split(", ")[:5]:
            print(f"         {DIM}{ip}{RESET}")
        if len((r["ips"] or "").split(", ")) > 5:
            print(f"         {DIM}… and {len((r['ips']).split(', ')) - 5} more{RESET}")
    _sep()


def report_by_port(conn: sqlite3.Connection, port_filter: int | None):
    where = "WHERE p.port = ?" if port_filter else ""
    params = (port_filter,) if port_filter else ()
    rows = conn.execute(
        f"""
        SELECT p.port, p.protocol, p.service, p.product,
               COUNT(DISTINCT p.ip) AS n,
               GROUP_CONCAT(DISTINCT p.ip) AS ips
        FROM   ports p
        {where}
        WHERE  p.state = 'open'
        GROUP  BY p.port, p.protocol
        ORDER  BY n DESC, p.port ASC
        """,
        params,
    ).fetchall()

    mx = max((r["n"] for r in rows), default=1)
    _sep()
    print(f"{BOLD}  Open ports{RESET}  ({len(rows)} unique port/protocol pairs)")
    _sep()
    for r in rows:
        svc_s = " ".join(filter(None, [r["service"], r["product"]])) or ""
        print(
            f"  {CYAN}{r['n']:>4}{RESET}  {_bar(r['n'], mx)}"
            f"  {BOLD}{r['port']}/{r['protocol']}{RESET}"
            f"  {DIM}{svc_s}{RESET}"
        )
        for ip in (r["ips"] or "").split(",")[:4]:
            print(f"         {DIM}{ip.strip()}{RESET}")
        if len((r["ips"] or "").split(",")) > 4:
            print(f"         {DIM}… and more{RESET}")
    _sep()


def report_by_service(conn: sqlite3.Connection):
    rows = conn.execute(
        """
        SELECT service, product,
               COUNT(DISTINCT ip) AS n_hosts,
               COUNT(*)           AS n_ports,
               GROUP_CONCAT(DISTINCT port || '/' || protocol) AS port_list
        FROM   ports
        WHERE  state = 'open' AND service IS NOT NULL
        GROUP  BY service, product
        ORDER  BY n_hosts DESC
        """
    ).fetchall()

    mx = max((r["n_hosts"] for r in rows), default=1)
    _sep()
    print(f"{BOLD}  Services / products{RESET}  ({len(rows)} unique)")
    _sep()
    for r in rows:
        svc_s = " ".join(filter(None, [r["service"], r["product"]])) or "(unnamed)"
        ports_s = (r["port_list"] or "")[:60]
        print(
            f"  {CYAN}{r['n_hosts']:>4}{RESET}  {_bar(r['n_hosts'], mx)}"
            f"  {svc_s}  {DIM}{ports_s}{RESET}"
        )
    _sep()


def report_by_severity(conn: sqlite3.Connection, min_sev: str | None):
    sev_filter = ""
    params: tuple = ()
    if min_sev:
        include = _SEVERITY_ORDER[:_SEVERITY_ORDER.index(min_sev.lower()) + 1]
        sev_filter = f"WHERE severity IN ({','.join('?' * len(include))})"
        params = tuple(include)

    rows = conn.execute(
        f"""
        SELECT severity,
               COUNT(DISTINCT ip) AS n_hosts,
               COUNT(*)           AS n_findings,
               COUNT(DISTINCT cve) AS n_cves
        FROM   vulns
        {sev_filter}
        GROUP  BY severity
        ORDER  BY CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high'     THEN 2
            WHEN 'medium'   THEN 3
            WHEN 'low'      THEN 4
            WHEN 'info'     THEN 5
            ELSE 6 END
        """,
        params,
    ).fetchall()

    _sep()
    print(f"{BOLD}  Vulnerabilities by severity{RESET}")
    _sep()
    for r in rows:
        sc = _sev_color(r["severity"])
        print(
            f"  {sc}{r['severity'].upper():<10}{RESET}"
            f"  {CYAN}{r['n_findings']:>4} finding(s){RESET}"
            f"  {r['n_cves']:>4} CVE(s)"
            f"  {r['n_hosts']:>4} host(s)"
        )
    _sep()


def report_by_cve(conn: sqlite3.Connection, min_sev: str | None):
    sev_filter = ""
    params: tuple = ()
    if min_sev:
        include = _SEVERITY_ORDER[:_SEVERITY_ORDER.index(min_sev.lower()) + 1]
        sev_filter = f"AND severity IN ({','.join('?' * len(include))})"
        params = tuple(include)

    rows = conn.execute(
        f"""
        SELECT cve, severity, MAX(cvss) AS cvss,
               COUNT(DISTINCT ip) AS n_hosts,
               GROUP_CONCAT(DISTINCT ip) AS ips,
               title
        FROM   vulns
        WHERE  cve IS NOT NULL {sev_filter}
        GROUP  BY cve
        ORDER  BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high'     THEN 2
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 4
                ELSE 5 END,
            n_hosts DESC
        """,
        params,
    ).fetchall()

    _sep()
    print(f"{BOLD}  CVEs{RESET}  ({len(rows)} unique)")
    _sep()
    for r in rows:
        sc    = _sev_color(r["severity"])
        cvss  = f"{r['cvss']:.1f}" if r["cvss"] is not None else "  ?"
        ips   = (r["ips"] or "").split(",")
        ips_s = ", ".join(i.strip() for i in ips[:4])
        more  = f" … +{len(ips) - 4}" if len(ips) > 4 else ""
        print(
            f"  {sc}{r['cve']:<18}{RESET}"
            f"  {sc}{r['severity']:<8}{RESET}"
            f"  CVSS {cvss}"
            f"  {CYAN}{r['n_hosts']:>3} host(s){RESET}"
            f"  {DIM}{ips_s}{more}{RESET}"
        )
    _sep()


def report_by_host(conn: sqlite3.Connection, country: str | None):
    where = "WHERE h.country_code = ?" if country else ""
    params = (country,) if country else ()
    hosts = conn.execute(
        f"""
        SELECT h.ip, h.os, h.os_accuracy, h.hostname, h.country_code,
               h.scan_status, h.flag_reason
        FROM   hosts h
        {where}
        WHERE  h.scan_status = 'done'
        ORDER  BY h.ip
        """,
        params,
    ).fetchall()

    _sep()
    print(f"{BOLD}  Host summary{RESET}  ({len(hosts)} host(s))")
    _sep()
    for h in hosts:
        ip    = h["ip"]
        os_s  = f"{h['os'] or 'OS unknown'}"
        acc_s = f" ({h['os_accuracy']}%)" if h["os_accuracy"] else ""
        hn_s  = f"  {DIM}{h['hostname']}{RESET}" if h["hostname"] else ""
        print(f"\n  {BOLD}{CYAN}{ip}{RESET}{hn_s}")
        print(f"    OS : {os_s}{acc_s}")

        ports = conn.execute(
            "SELECT port, protocol, service, product, version "
            "FROM ports WHERE ip = ? AND state = 'open' ORDER BY port",
            (ip,),
        ).fetchall()
        if ports:
            print(f"    Ports ({len(ports)}):")
            for p in ports:
                svc = " ".join(filter(None, [p["service"], p["product"], p["version"]]))
                print(f"      {CYAN}{p['port']}/{p['protocol']}{RESET}  {svc}")

        vulns = conn.execute(
            "SELECT cve, severity, title FROM vulns WHERE ip = ? ORDER BY "
            "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 ELSE 4 END",
            (ip,),
        ).fetchall()
        if vulns:
            print(f"    Vulns ({len(vulns)}):")
            for v in vulns[:10]:
                sc    = _sev_color(v["severity"])
                label = v["cve"] or v["title"] or "(unnamed)"
                print(f"      {sc}{v['severity']:<8}{RESET}  {label}")
            if len(vulns) > 10:
                print(f"      {DIM}… and {len(vulns) - 10} more{RESET}")
    _sep()


def report_by_ip(conn: sqlite3.Connection, ip: str):
    host = conn.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)).fetchone()
    if host is None:
        sys.exit(f"[ERROR] IP not found in vault: {ip}")

    _sep()
    print(f"{BOLD}  {ip}{RESET}  —  detailed view")
    _sep()
    print(f"  Hostname  : {host['hostname'] or '—'}")
    print(f"  Status    : {host['status'] or '—'}")
    print(f"  OS        : {host['os'] or '—'}"
          + (f"  ({host['os_accuracy']}%)" if host["os_accuracy"] else ""))
    print(f"  Country   : {host['country_code'] or '—'}")
    print(f"  Flagged   : {host['flagged']}  {host['flag_reason'] or ''}")
    print(f"  Scanned   : {host['last_scanned'] or '—'}")
    print(f"  Scan status: {host['scan_status']}")
    if host["scan_error"]:
        print(f"  {RED}Scan error: {host['scan_error']}{RESET}")

    ports = conn.execute(
        "SELECT port, protocol, state, service, product, version, extra_info "
        "FROM ports WHERE ip = ? ORDER BY port",
        (ip,),
    ).fetchall()
    print(f"\n  {BOLD}Ports ({len(ports)}){RESET}")
    for p in ports:
        svc = " ".join(filter(None, [p["service"], p["product"], p["version"], p["extra_info"]]))
        print(f"    {CYAN}{p['port']}/{p['protocol']}{RESET}  {p['state']:<10}  {svc}")

    vulns = conn.execute(
        "SELECT cve, cvss, severity, title, description, tool, refs "
        "FROM vulns WHERE ip = ? ORDER BY "
        "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 ELSE 4 END",
        (ip,),
    ).fetchall()
    print(f"\n  {BOLD}Vulnerabilities ({len(vulns)}){RESET}")
    for v in vulns:
        sc    = _sev_color(v["severity"])
        label = v["cve"] or v["title"] or "(unnamed)"
        cvss  = f"  CVSS {v['cvss']:.1f}" if v["cvss"] is not None else ""
        print(f"\n    {sc}{v['severity'].upper():<8}{RESET}  {BOLD}{label}{RESET}{cvss}")
        print(f"    Tool: {DIM}{v['tool'] or '—'}{RESET}")
        if v["description"]:
            for line in v["description"].strip().splitlines()[:3]:
                print(f"    {DIM}{line}{RESET}")
        try:
            refs = json.loads(v["refs"] or "[]")
            for ref in refs[:2]:
                print(f"    {DIM}{ref}{RESET}")
        except Exception:
            pass

    scan_log = conn.execute(
        "SELECT tool, command, started_at, finished_at FROM scan_log WHERE ip = ? ORDER BY id",
        (ip,),
    ).fetchall()
    if scan_log:
        print(f"\n  {BOLD}Scan log{RESET}")
        for s in scan_log:
            print(f"    {DIM}[{s['started_at']}]  {s['tool']}:{RESET}")
            print(f"    {DIM}{s['command'][:100]}{RESET}")

    _sep()


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="vreport",
        description="Query and group vault intelligence database findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python vreport.py --by os\n"
            "  python vreport.py --by port\n"
            "  python vreport.py --by port --port 443\n"
            "  python vreport.py --by service\n"
            "  python vreport.py --by severity\n"
            "  python vreport.py --by cve\n"
            "  python vreport.py --by cve --min-severity high\n"
            "  python vreport.py --by host\n"
            "  python vreport.py --by host --country US\n"
            "  python vreport.py --ip 192.168.1.1\n"
        ),
    )

    parser.add_argument("--db", metavar="FILE", default=None,
        help="vault SQLite path (default: vault.sqlite next to this script)")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--by", metavar="GROUP",
        choices=["os", "port", "service", "severity", "cve", "host"],
        help="Group findings by: os | port | service | severity | cve | host")
    mode.add_argument("--ip", metavar="IP",
        help="Show all findings for a specific IP address")

    parser.add_argument("--min-severity", metavar="SEV",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter vulns to this severity and above (for --by cve/severity)")
    parser.add_argument("--port", type=int, metavar="PORT",
        help="Filter to a specific port number (for --by port)")
    parser.add_argument("--country", metavar="CC",
        help="Filter hosts by country code (for --by host/os)")

    args = parser.parse_args()

    db_path = (Path(args.db) if args.db
               else Path(__file__).resolve().parent / "vault.sqlite")
    conn = open_db(db_path)

    try:
        if args.ip:
            report_by_ip(conn, args.ip)
        elif args.by == "os":
            report_by_os(conn, args.country)
        elif args.by == "port":
            report_by_port(conn, args.port)
        elif args.by == "service":
            report_by_service(conn)
        elif args.by == "severity":
            report_by_severity(conn, args.min_severity)
        elif args.by == "cve":
            report_by_cve(conn, args.min_severity)
        elif args.by == "host":
            report_by_host(conn, args.country)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
