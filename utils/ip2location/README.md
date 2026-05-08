# ip2location

Universal IP lookup tool built on [IP2Location LITE](https://lite.ip2location.com).  
Download any database once; every query runs fully offline against local `.BIN` files.

## Quick start

```bash
# 1. Install dependencies
pip install IP2Location IP2Proxy python-dotenv requests

# 2. Add your download token to .env
cp .env.example .env
#  → edit .env and set IP2LOCATION_TOKEN=<your token>

# 3. Download databases
python ip2location.py --download DB11 ASN PX7

# 4. Query
python ip2location.py 8.8.8.8
```

---

## Databases

Each database family is **cumulative** — every level adds fields to the one above it.

### Geolocation

| Name  | Fields added                      | Recommended? |
|-------|-----------------------------------|:---:|
| DB1   | Country                           | |
| DB3   | + Region, City                    | |
| DB5   | + Latitude, Longitude             | |
| DB9   | + ZIP, Timezone                   | |
| **DB11** | + ISP, Domain, Usage type      | ★ |
| ASN   | ASN number, name, CIDR prefix     | ★ |

### Proxy / VPN detection

| Name  | Fields added                      | Recommended? |
|-------|-----------------------------------|:---:|
| PX1   | Is-proxy flag + Country           | |
| PX2   | + Proxy type (VPN / Tor / DCH …)  | |
| PX3   | + ISP                             | |
| PX4   | + Domain                          | |
| PX5   | + Usage type                      | |
| PX6   | + ASN                             | |
| **PX7** | + Threat category               | ★ |
| PX8   | + Provider name                   | |
| PX9   | + Fraud score (0–100)             | |
| **PX11** | + Last seen (days)             | ★ |

---

## Usage

```
python ip2location.py [options] [IP ...]

Positional:
  IP               One or more IPv4 or IPv6 addresses

Options:
  --list           Show all databases with download status
  --download DB…   Download one or more databases
  --update [DB…]   Re-download stale databases (no names = update all downloaded)
  --force          Skip freshness check when downloading
  --db DB          Query a specific database instead of auto-detecting
  --json           Output as JSON (single IP → object, multiple → array)
```

### Examples

```bash
# See what's available and what's already downloaded
python ip2location.py --list

# Download the richest geo + ASN + proxy databases
python ip2location.py --download DB11 ASN PX11

# Download just what you need
python ip2location.py --download PX7

# Query a single IP (auto-uses the richest downloaded DB in each family)
python ip2location.py 8.8.8.8

# Query against a specific database
python ip2location.py --db PX7 8.8.8.8

# Multiple IPs → compact table
python ip2location.py 8.8.8.8 1.1.1.1 9.9.9.9

# Multiple IPs with a specific DB → table for that DB's fields
python ip2location.py --db DB11 8.8.8.8 1.1.1.1

# JSON output
python ip2location.py --json 8.8.8.8
python ip2location.py --json 8.8.8.8 1.1.1.1      # → array

# Refresh all downloaded databases
python ip2location.py --update

# Refresh specific databases
python ip2location.py --update DB11 PX7
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
$ python ip2location.py --db DB11 8.8.8.8 1.1.1.1 9.9.9.9
```

```
IP               Hostname                CC    City             ISP                   Proxy
───────────────  ──────────────────────  ────  ───────────────  ────────────────────  ────────────────────────────
8.8.8.8          dns.google              US    Mountain View    Google LLC            No
1.1.1.1          one.one.one.one         AU    Research         Cloudflare Inc.       No
9.9.9.9          dns9.quad9.net          US    Berkeley         Quad9                 No
```

---

## JSON + jq

Single IP returns an object; multiple IPs always return an array:

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

# Filter: only IPs flagged as proxies
python ip2location.py --json 8.8.8.8 1.1.1.1 \
  | jq '[.[] | select(.is_proxy | startswith("Yes"))]'

# Filter: only IPs with a threat score
python ip2location.py --json --db PX7 8.8.8.8 1.1.1.1 \
  | jq '[.[] | select(.threat and .threat != "-")]'

# Tab-separated table: IP, country, city, ASN
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq -r '.[] | [.ip, .country_code, .city, .asn] | @tsv'

# One-liner summary per IP
python ip2location.py --json 8.8.8.8 1.1.1.1 \
  | jq -r '.[] | "\(.ip)\t\(.country_code)/\(.city)\t\(.asn)\t\(.is_proxy)"'

# Sort batch results by country code
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq 'sort_by(.country_code)'

# Extract unique ASNs seen across a batch
python ip2location.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq '[.[].asn] | unique'
```

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `IP2LOCATION_TOKEN` | Yes (for download) | Download token from IP2Location LITE |
| `IP2LOCATION_DB_DIR` | No | Override folder where `.BIN` files are stored |

Copy `.env.example` → `.env` and fill in your token.  
Get a free token at **https://lite.ip2location.com** → sign in → Download.
