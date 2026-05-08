# ipinfo

IP geolocation, ASN, and proxy/threat lookup tool using offline IP2Location binary databases.

## Features

- Geolocation: country, region, city, lat/lon, ZIP, timezone, ISP, domain, usage type
- ASN: autonomous system number, name, and CIDR range
- Proxy / threat detection: VPN, Tor exit nodes, data centers, residential proxies, and more
- IPv4 and IPv6 support
- JSON output mode
- Auto-download and refresh of all three databases via `--update`

## Databases

| Database file | Contents |
|---|---|
| `IP2LOCATION-LITE-DB11.IPV6.BIN` | Geo: country, city, lat/lon, ISP … |
| `IP2LOCATION-LITE-ASN.IPV6.BIN` | ASN number and name |
| `IP2PROXY-LITE-PX11.BIN` | Proxy / VPN / threat detection |

Databases are downloaded from [IP2Location LITE](https://lite.ip2location.com) and stored locally — no API calls at lookup time.

## Prerequisites

```
pip install IP2Location IP2Proxy python-dotenv requests
```

## Setup

1. Copy `.env.example` to `.env` in the same folder:

   ```
   cp .env.example .env
   ```

2. Add your IP2Location download token to `.env`:

   ```
   IP2LOCATION_TOKEN=your_token_here
   ```

   Get a free token at [https://lite.ip2location.com](https://lite.ip2location.com) → sign in → Download.

3. Download the databases:

   ```
   python ipinfo.py --update
   ```

## Usage

```
python ipinfo.py <IP> [<IP> ...]
python ipinfo.py --json <IP>
python ipinfo.py --update
python ipinfo.py --update --force
python ipinfo.py --update <IP>
```

### Examples

```
python ipinfo.py 8.8.8.8
python ipinfo.py 8.8.8.8 1.1.1.1 2001:4860:4860::8888
python ipinfo.py --json 8.8.8.8
python ipinfo.py --update
python ipinfo.py --update --force 8.8.8.8
```

### Options

| Flag | Description |
|---|---|
| `--update` | Download / refresh all three databases, then exit (or look up IPs if also provided) |
| `--force` | With `--update`: re-download even if databases are still fresh |
| `--json` | Print results as JSON instead of coloured text |

## Configuration

The `.env` file supports two variables:

| Variable | Required | Description |
|---|---|---|
| `IP2LOCATION_TOKEN` | Yes | Download token from IP2Location |
| `IP2LOCATION_DB_DIR` | No | Override folder for `.BIN` files (default: same folder as `ipinfo.py`) |

## Database refresh

IP2Location updates geo databases on the 1st of each month and the proxy database daily. The tool warns when a database is older than 35 days. Run `--update` to refresh.

## Output

### Single IP — detailed view

```
──────────────────────────────────────────────────────
  IP Info  ›  8.8.8.8
──────────────────────────────────────────────────────

  Geolocation  (DB11)
  Country            US  United States of America
  Region             California
  City               Mountain View
  Lat / Lon          37.38600, -122.08380
  ZIP                94043
  Timezone           -07:00
  ISP                Google LLC
  Domain             google.com
  Usage Type         DCH

  ASN
  ASN                AS15169
  Name               Google LLC
  CIDR               8.8.8.0/24

  Proxy / Threat
  Is Proxy           No
  Proxy Type         -
  Threat             -

──────────────────────────────────────────────────────
```

### Multiple IPs — tabular view

When more than one IP is provided, results are shown as a compact aligned table:

```
$ python ipinfo.py 8.8.8.8 1.1.1.1 9.9.9.9

IP               Hostname                CC    City             ISP                   ASN        Proxy
───────────────  ──────────────────────  ────  ───────────────  ────────────────────  ─────────  ────────────────────────────
8.8.8.8          dns.google              US    Mountain View    Google LLC            AS15169    No
1.1.1.1          one.one.one.one         AU    Research         Cloudflare Inc.       AS13335    No
9.9.9.9          dns9.quad9.net          US    Berkeley         Quad9                 AS19281    No
```

### JSON output

A single IP returns a JSON object; multiple IPs always return a JSON array:

```bash
# Single IP → object
python ipinfo.py --json 8.8.8.8

# Multiple IPs → array
python ipinfo.py --json 8.8.8.8 1.1.1.1 9.9.9.9
```

## jq recipes

```bash
# Extract the country for a single IP
python ipinfo.py --json 8.8.8.8 | jq '.geo.country'

# Pull city, ISP, and ASN from every IP in a batch
python ipinfo.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq '.[] | {ip, city: .geo.city, isp: .geo.isp, asn: .asn.asn}'

# Keep only IPs flagged as proxies or VPNs
python ipinfo.py --json 8.8.8.8 1.1.1.1 \
  | jq '[.[] | select(.proxy.is_proxy | startswith("Yes"))]'

# Tab-separated table: IP, country code, city, ASN
python ipinfo.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq -r '.[] | [.ip, .geo.country_code, .geo.city, .asn.asn] | @tsv'

# Compact summary — one line per IP
python ipinfo.py --json 8.8.8.8 1.1.1.1 \
  | jq -r '.[] | "\(.ip)\t\(.geo.country_code)/\(.geo.city)\t\(.asn.asn)\t\(.proxy.is_proxy)"'

# Extract unique ASNs seen across a batch
python ipinfo.py --json 8.8.8.8 1.1.1.1 9.9.9.9 \
  | jq '[.[].asn.asn] | unique'
```
