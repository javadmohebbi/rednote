# ipdb

IP intelligence database builder.  
Reads **fastcheck** `.jsonl` output, enriches every live host with geo data from two independent sources, cross-validates them, and stores all results in a **SQLite database** for downstream recon and attack tooling.  
Supports **pause**, **resume from pause**, **resume after being stopped**, and **rerun** of incomplete records.

---

## Quick start

```bash
# Enrich all 'up' hosts — no country filter
python ipdb.py -f fastcheck.jsonl

# Enforce a target country — flag anything that isn't confirmed US by both sources
python ipdb.py -f fastcheck.jsonl --country US

# Custom DB path
python ipdb.py -f fastcheck.jsonl --country DE --db de-targets.sqlite

# Slower delay to stay well within ipinfo.io free tier
python ipdb.py -f fastcheck.jsonl --country US --online-delay 2.5

# Resume a stopped run — re-run the same command
python ipdb.py -f fastcheck.jsonl --country US
# Output: Resume: 12,480 already in DB, 487,520 remaining.

# Rerun all VERIFICATION_INCOMPLETE records (e.g. after quota resets)
python ipdb.py --rerun --db campaign.sqlite
python ipdb.py --rerun --db campaign.sqlite --country US
```

---

## Prerequisites

```bash
pip install IP2Location IP2Proxy python-dotenv requests
brew install curl      # macOS
apt  install curl      # Debian / Ubuntu
```

IP2Location binary databases must be downloaded first via the ipinfo tool:

```bash
python ../ipinfo/ipinfo.py --update
```

---

## Usage

```
python ipdb.py -f JSONL [options]
python ipdb.py --rerun  [options]

Modes:
  -f, --file JSONL       fastcheck .jsonl input file (normal mode)
  --rerun                re-process all VERIFICATION_INCOMPLETE records in --db

Options:
  --db FILE              SQLite path (default: ipdb.sqlite next to this script)
  --country CC           Two-letter country code to enforce (e.g. US, DE, CN)
                         Both sources must confirm CC for flagged=0.
                         Any disagreement — or unavailable source — sets flagged=1.
  -w, --workers N        Worker threads (default: 5)
                         Online requests share one rate-limited slot regardless of N.
                         More workers help parallelise local lookups and DB writes.
  --online-delay SEC     Minimum seconds between ipinfo.io requests (default: 1.5)
                         Set to 0 to disable (risk: 429 rate limiting).
  --all                  Process all hosts in the JSONL, not only 'up' ones
                         (ignored with --rerun)
```

---

## Geo sources

| Source | Method | Cost |
|--------|--------|------|
| **local** | IP2Location binary databases via `../ipinfo/ipinfo.py` | offline, instant |
| **online** | `curl ipinfo.io/<ip>` | ~50 k req/month free tier |

Both sources are **always** queried for every IP. Neither is skipped.

---

## Flagging rules

An IP is written to the database with `flagged=1` when verification fails.  
`flagged=1` IPs **must not be used** for further recon or attacks.

### With `--country CC`

| Local result | Online result | `flagged` | `flag_reason` |
|---|---|---|---|
| CC | CC | 0 | — |
| CC | different | 1 | `COUNTRY_MISMATCH` |
| different | CC | 1 | `COUNTRY_MISMATCH` |
| different | different | 1 | `COUNTRY_MISMATCH` |
| error / unavailable | anything | 1 | `VERIFICATION_INCOMPLETE` |
| anything | error / rate_limited | 1 | `VERIFICATION_INCOMPLETE` |

If either source reports anything other than the expected country code, the IP is flagged — no exceptions.

### Without `--country`

| Situation | `flagged` | `flag_reason` |
|---|---|---|
| Both agree on any country code | 0 | — |
| Sources report different country codes | 1 | `COUNTRY_MISMATCH` |
| Either source unavailable or errored | 1 | `VERIFICATION_INCOMPLETE` |

---

## Workflow: fastcheck → ipdb

```bash
# Step 1 — discover live hosts
python ../fastcheck/fastcheck.py 10.0.0.0/8 --light -w 200 --up-only -o live.jsonl

# Step 2 — geo-verify and build the intelligence database
python ipdb.py -f live.jsonl --country US --db campaign.sqlite

# Step 3 — query clean targets for downstream tools
sqlite3 campaign.sqlite "SELECT ip FROM hosts WHERE flagged = 0"
```

---

## Rate limiting

The default `--online-delay 1.5` enforces ≥ 1.5 s between `curl ipinfo.io/...` calls (~40 req/min, ~57 k/day).

**ipinfo.io free tier: ~50 k requests/month.**  
For large input files (500 k hosts) the online verification will take many sessions across multiple days. The SQLite checkpoint means every session picks up exactly where the last one stopped.

### When a `429` is returned

When ipinfo.io returns a rate-limit response, ipdb **auto-pauses immediately** — all workers finish their current IP and then wait. The display shows:

```
⏸ PAUSED  ↵ resume  ·  Ctrl+C quit
```

The rate-limited IP is stored as:

```
online_status = 'rate_limited'
flagged       = 1
flag_reason   = 'VERIFICATION_INCOMPLETE'
```

Press **Enter** to resume once the quota resets, or **Ctrl+C** to stop and come back later. Use `--rerun` to recheck all rate-limited records in a future session.

---

## Pause and resume

### Manual pause during a run

Press **Ctrl+C**. Workers finish their current IP, then wait.  
The footer shows `⏸ PAUSED  ↵ resume  ·  Ctrl+C quit`.

Press **Enter** to resume. Press **Ctrl+C** again to quit.

### Auto-pause on rate limit

When ipinfo.io returns a `429`, the tool pauses itself — no Ctrl+C needed. Same footer, same controls. Resume after waiting for the quota window to reset.

### Resume after stopping

Re-run the **exact same command**. IPs already in the database are skipped:

```bash
# First run — stopped after 12,480 IPs
python ipdb.py -f live.jsonl --country US

# Re-run — continues from IP 12,481
python ipdb.py -f live.jsonl --country US
# Resume: 12,480 already in DB, 487,520 remaining.
```

`first_seen` is preserved when an IP is re-processed — it always reflects when the IP was first encountered.

---

## Rerun mode

`--rerun` re-processes every `VERIFICATION_INCOMPLETE` record already in the database. No JSONL file is needed — the DB itself is the source. Use this after:

- the ipinfo.io monthly quota resets
- a network outage cleared
- timeout errors resolved

```bash
# Recheck all incomplete records
python ipdb.py --rerun --db campaign.sqlite

# With a country filter applied to the recheck
python ipdb.py --rerun --db campaign.sqlite --country US
```

Each recheck increments `retry_count` for the record. The live display shows the try number next to each result:

```
[  3/87]  104.21.18.9    FLAG  L:US  O:?   VERIFICATION_INCOMPLETE  [try:3]
```

Records that resolve cleanly on rerun are updated to `flagged=0`. Records that fail again remain flagged with an incremented `retry_count`.

---

## Live display

Fixed header, scrolling results, fixed footer — the screen never scrolls.

```
──────────────────────────────────────────────────────────────────
  ipdb  ·  IP intelligence database builder  filter: US
  Targets: 487520  Workers: 5  Online delay: 1.5s  →  campaign.sqlite
──────────────────────────────────────────────────────────────────
  [   41/487520]  104.21.18.7    OK    L:US  O:US                  ▲
  [   42/487520]  104.21.18.9    FLAG  L:US  O:DE  COUNTRY_MISMATCH │
  [   43/487520]  198.41.0.1     FLAG  L:US  O:?   VERIFICATION_... │ scroll
  [   44/487520]  104.21.19.2    OK    L:US  O:US                   │ region
  [   45/487520]  104.21.19.5    FLAG  L:CN  O:CN  COUNTRY_MISMATCH ▼
──────────────────────────────────────────────────────────────────
  Clean: 32       Flagged: 13      [░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  45/487520
──────────────────────────────────────────────────────────────────
```

`L:` = local IP2Location result, `O:` = online ipinfo.io result.  
`[try:N]` appears on rerun records when N > 1.  
When output is piped or redirected (non-TTY), plain line-by-line output is used instead.

---

## SQLite schema

```sql
hosts (
    ip                  -- PRIMARY KEY
    first_seen          -- UTC ISO-8601; never updated on re-process
    last_updated        -- UTC ISO-8601; updated every run

    -- fastcheck source
    fc_status           -- 'up', 'down', etc.
    fc_latency_ms
    fc_hostname
    fc_mac
    fc_source           -- source .jsonl filename

    -- local IP2Location
    local_country_code  -- e.g. 'US'
    local_country       -- e.g. 'United States of America'
    local_region
    local_city
    local_lat / local_lon
    local_isp
    local_asn / local_asn_name
    local_error         -- NULL on success

    -- rerun tracking
    retry_count         -- incremented each time this record is reprocessed

    -- online ipinfo.io
    online_country_code -- e.g. 'US'
    online_region / online_city
    online_lat / online_lon
    online_org          -- e.g. 'AS15169 Google LLC'
    online_hostname
    online_timezone
    online_status       -- 'ok' | 'rate_limited' | 'timeout' | 'error' | 'bogon'
    online_error        -- NULL on success

    -- verification
    flagged             -- 0 = safe to use, 1 = do not use
    flag_reason         -- COUNTRY_MISMATCH | VERIFICATION_INCOMPLETE | NULL
    country_filter      -- the --country value used when this record was written

    -- reserved for future tools
    ports_json          -- port scan results (scantop100 / custom)
    os_detected
    vulns_json
    last_port_scan
    last_vuln_scan
)
```

Existing databases are migrated automatically — `retry_count` is added via `ALTER TABLE` on first open if it doesn't exist.

---

## Querying the database

### sqlite3

```bash
sqlite3 campaign.sqlite

-- Clean targets only
SELECT ip FROM hosts WHERE flagged = 0;

-- Flagged summary
SELECT flag_reason, COUNT(*) FROM hosts GROUP BY flag_reason;

-- Country distribution of clean targets
SELECT local_country_code, COUNT(*) AS n
  FROM hosts WHERE flagged = 0
  GROUP BY local_country_code ORDER BY n DESC;

-- Rate-limited IPs (candidates for --rerun)
SELECT ip FROM hosts WHERE online_status = 'rate_limited';

-- Records with the most rerun attempts
SELECT ip, retry_count, flag_reason
  FROM hosts WHERE retry_count > 0
  ORDER BY retry_count DESC LIMIT 20;

-- IPs where sources disagree (for investigation)
SELECT ip, local_country_code, online_country_code
  FROM hosts WHERE flag_reason = 'COUNTRY_MISMATCH';
```

### Python

```python
import sqlite3

conn = sqlite3.connect("campaign.sqlite")
conn.row_factory = sqlite3.Row

# Feed clean IPs to the next tool
for row in conn.execute("SELECT ip FROM hosts WHERE flagged = 0"):
    print(row["ip"])

# Find country mismatches for review
for row in conn.execute(
    "SELECT ip, local_country_code, online_country_code "
    "FROM hosts WHERE flag_reason = 'COUNTRY_MISMATCH'"
):
    print(row["ip"], row["local_country_code"], "vs", row["online_country_code"])
```

### Shell pipeline

```bash
# Extract clean IPs as a plain list for downstream tools
sqlite3 campaign.sqlite "SELECT ip FROM hosts WHERE flagged = 0" > clean_targets.txt

# Feed into scantop100
python ../scantop100/scantop100.py -f clean_targets.txt -o ports.jsonl

# Count clean vs flagged
sqlite3 campaign.sqlite "SELECT flagged, COUNT(*) FROM hosts GROUP BY flagged"
```

---

## Notes

- **Both sources always queried**: local and online lookups run for every IP — there is no short-circuit.
- **`--country` is strict**: if either source is unavailable (timeout, rate limit, error), the IP is flagged even if the other source matches. The goal is certainty.
- **Auto-pause on 429**: a rate-limit response from ipinfo.io pauses all workers immediately. Press Enter to resume; the record is stored as `VERIFICATION_INCOMPLETE` and can be retried with `--rerun`.
- **`--rerun` is safe to repeat**: it increments `retry_count` each time and only touches `VERIFICATION_INCOMPLETE` records. Already-clean records are never re-queried.
- **Memory**: the fastcheck JSONL is read line-by-line — a 500 k-record file uses the same ~few MB of RAM as a 10-record file.
- **Task queue**: at most `workers × 4` futures are live at once; the rest wait in the generator.
- **Online requests are serialized**: all N workers share one `RateLimiter`. Throughput is `1 / online-delay` req/s regardless of worker count. Workers help with local lookups and DB writes, not online speed.
- **WAL mode**: the SQLite database is opened in WAL mode — concurrent reads while workers are writing are safe.
- **Re-processing**: to force re-processing of specific IPs, delete their rows and re-run. `first_seen` is reset; `last_updated` reflects the new run.
- **Future columns**: `ports_json`, `os_detected`, `vulns_json`, `last_port_scan`, `last_vuln_scan` are already in the schema (nullable) — reserved for port scanning and vuln detection tools to fill in.
