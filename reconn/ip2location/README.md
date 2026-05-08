# ip2location

Universal IP lookup tool built on [IP2Location LITE](https://lite.ip2location.com).  
Download any database once; every query runs fully offline against local `.BIN` files.

## Quick start

```bash
# 1. Install dependencies
pip install IP2Location IP2Proxy python-dotenv requests

# 2. Set your download token
cp .env.example .env
#  → edit .env and fill in IP2LOCATION_TOKEN=<your token>

# 3. Download databases
python ip2location.py --download DB11 ASN PX7

# 4. Query IPs
python ip2location.py 8.8.8.8

# 5. Reverse-lookup: find CIDR ranges for a country or city
python ip2location.py --reverse-country US
python ip2location.py --reverse-city "Mountain View"
```

---

## Databases

Each family is **cumulative** — every level adds fields to the one above it.  
★ = recommended starting point.

### Geolocation

| Name  | Contents                              |
|-------|---------------------------------------|
| DB1   | Country                               |
| DB3   | + Region, City                        |
| DB5   | + Latitude, Longitude                 |
| DB9   | + ZIP, Timezone                       |
| **DB11** ★ | + ISP, Domain, Usage type      |
| **ASN** ★  | ASN number, name, CIDR prefix   |

### Proxy / VPN detection

| Name  | Contents                              |
|-------|---------------------------------------|
| PX1   | Is-proxy flag + Country               |
| PX2   | + Proxy type (VPN / Tor / DCH …)      |
| PX3   | + ISP                                 |
| PX4   | + Domain                              |
| PX5   | + Usage type                          |
| PX6   | + ASN                                 |
| **PX7** ★  | + Threat category              |
| PX8   | + Provider name                       |
| PX9   | + Fraud score (0–100)                 |
| **PX11** ★ | + Last seen (days)             |

---

## Usage

```
python ip2location.py [options] [IP ...]

Lookup (forward):
  IP …                One or more IPv4 or IPv6 addresses
  --db DB             Query a specific database (default: auto-detect richest)

Reverse-lookup (get IP ranges):
  --reverse-country CC   Find CIDR ranges for a country code (e.g. US, DE)
  --reverse-city NAME    Find CIDR ranges for a city name (requires CSV database)
  --limit N              Max results for reverse lookup (default: 20)

Download:
  --download DB …     Download one or more databases
  --update [DB …]     Re-download stale DBs (no names = update all downloaded)
  --force             Skip freshness check when downloading

Output:
  --list              Show all databases with download status
  --json              JSON output (single IP → object, multiple → array)
  --csv               CSV output with a header row
```

### Examples

```bash
# See all databases and which are downloaded
python ip2location.py --list

# Download the recommended set
python ip2location.py --download DB11 ASN PX11

# Single IP — auto-uses all downloaded DBs
python ip2location.py 8.8.8.8

# Multiple IPs → compact table
python ip2location.py 8.8.8.8 1.1.1.1 9.9.9.9

# Query a specific database only
python ip2location.py --db PX7 8.8.8.8

# JSON output
python ip2location.py --json 8.8.8.8
python ip2location.py --json 8.8.8.8 1.1.1.1    # → array

# Reverse: all CIDR ranges for a country
python ip2location.py --reverse-country US
python ip2location.py --reverse-country DE --limit 50

# Reverse: CIDR ranges for a city
python ip2location.py --reverse-city "Mountain View"
python ip2location.py --reverse-city Tokyo --json

# Refresh all downloaded databases
python ip2location.py --update
```

---

## Output

### Single IP — detail view

```
────────────────────────────────────────────────────────
  8.8.8.8  [DB11, ASN, PX7]
────────────────────────────────────────────────────────
  Hostname               dns.google
  Country                US  United States of America
  Region                 California
  City                   Mountain View
  Lat / Lon              37.38600, -122.08380
  ZIP                    94043
  Timezone               -07:00
  ISP                    Google LLC
  Domain                 google.com
  Usage type             DCH
  ASN                    AS15169
  AS name                Google LLC
  CIDR                   8.8.8.0/24
  Is proxy               No
  Proxy type             -
  Threat                 -

────────────────────────────────────────────────────────
```

### Multiple IPs — tabular view

```bash
$ python ip2location.py 8.8.8.8 1.1.1.1 9.9.9.9
```

```
IP               Hostname                CC    City             ISP                   ASN        Proxy
───────────────  ──────────────────────  ────  ───────────────  ────────────────────  ─────────  ────────────────────────────
8.8.8.8          dns.google              US    Mountain View    Google LLC            AS15169    No
1.1.1.1          one.one.one.one         AU    Research         Cloudflare Inc.       AS13335    No
9.9.9.9          dns9.quad9.net          US    Berkeley         Quad9                 AS19281    No
```

### Reverse lookup

```bash
$ python ip2location.py --reverse-country JP --limit 5
```

```
CIDR ranges for country: JP  (showing 5 of 8241)

  1.0.16.0/20
  1.1.1.0/24
  1.21.0.0/17
  1.66.0.0/15
  1.72.0.0/13
```

### CSV output

`--csv` works for both forward and reverse lookups. The header row is derived from
whichever fields the queried database(s) populate, in a consistent column order.

```bash
# Single or multiple IPs
python ip2location.py --csv 8.8.8.8
python ip2location.py --csv 8.8.8.8 1.1.1.1 9.9.9.9

# Pipe to a file
python ip2location.py --csv --db DB11 8.8.8.8 1.1.1.1 > results.csv

# Reverse lookup as CSV
python ip2location.py --reverse-country DE --limit 100 --csv > de_ranges.csv
python ip2location.py --reverse-city Tokyo --csv
```

Example output:

```
ip,hostname,country_code,country_name,region,city,latitude,longitude,zip,timezone,isp,domain,usage_type,asn,as_name,cidr,is_proxy,proxy_type
8.8.8.8,dns.google,US,United States of America,California,Mountain View,37.38600,-122.08380,94043,-07:00,Google LLC,google.com,DCH,AS15169,Google LLC,8.8.8.0/24,No,-
1.1.1.1,one.one.one.one,AU,Australia,Queensland,Research,-27.46794,153.02809,4000,+10:00,Cloudflare Inc.,cloudflare.com,CDN,AS13335,Cloudflare Inc.,1.1.1.0/24,No,-
```

---

## JSON + jq

Single IP → object; multiple IPs → array:

```bash
python ip2location.py --json 8.8.8.8
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9   # → [ {}, {}, {} ]
```

### jq recipes

```bash
# Extract a single field
python ip2location.py --json 8.8.8.8 | jq '.city'

# Pull key fields from a batch
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq '.[] | {ip, city, isp, asn}'

# Only IPs flagged as proxies
python ip2location.py --json 8.8.8.8 1.1.1.1 \
  | jq '[.[] | select(.is_proxy | startswith("Yes"))]'

# Only IPs with a threat label
python ip2location.py --json --db PX7 8.8.8.8 1.1.1.1 \
  | jq '[.[] | select(.threat and .threat != "-")]'

# Tab-separated: IP, country, city, ASN
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq -r '.[] | [.ip, .country_code, .city, .asn] | @tsv'

# One-liner summary per IP
python ip2location.py --json 8.8.8.8 1.1.1.1 \
  | jq -r '.[] | "\(.ip)\t\(.country_code)/\(.city)\t\(.asn)\t\(.is_proxy)"'

# Reverse lookup as JSON, then filter large ranges only
python ip2location.py --reverse-country US --json \
  | jq '[.[] | select(.cidr | split("/")[1] | tonumber < 20)]'

# Sort batch results by country code
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq 'sort_by(.country_code)'

# Unique ASNs seen across a batch
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq '[.[].asn] | unique'
```

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `IP2LOCATION_TOKEN` | For download | Token from IP2Location LITE |
| `IP2LOCATION_DB_DIR` | No | Override folder where `.BIN`/`.CSV` files are stored |

Copy `.env.example` → `.env` and fill in your token.  
Get a free token at **https://lite.ip2location.com** → sign in → Download.
