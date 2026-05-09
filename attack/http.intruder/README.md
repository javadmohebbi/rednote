# http.intruder

HTTP request intruder with `$$$_KEYNAME_$$$` placeholder substitution — similar to Burp Suite Intruder.  
Supports dictionary files, bruteforce, and number ranges. Handles millions of combinations with flat memory usage.  
Full pause, resume, and stop-condition support.

---

## Quick start

```bash
# 1. Copy a sample config and request from the samples/ folder
cp samples/login_bruteforce.txt     my_request.txt
cp samples/login_bruteforce_config.json config.json

# 2. Edit config.json — set "target", "request", and payload file paths
#    The "request" field must point to your request file (relative to config)

# 3. Test first — sends ONE request and prints the full response
python http.intruder.py config.json --test

# 4. Run the full attack
python http.intruder.py config.json

# Start fresh (ignore previous run)
python http.intruder.py config.json --fresh
```

---

## Request file

A raw HTTP/1.1 request with `$$$_KEYNAME_$$$` placeholders wherever you want payloads injected.  
The easiest way to get one: capture a request in Burp Suite → right-click → *Copy to file*.

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0
Connection: close

username=$$$_USER_$$$&password=$$$_PASS_$$$
```

Placeholders can appear anywhere — URL path, headers, body, cookies:

```
GET /user/$$$_ID_$$$?token=$$$_TOKEN_$$$ HTTP/1.1
Host: api.example.com
Authorization: Bearer $$$_JWT_$$$
```

---

## Config file

```json
{
  "target":      "https://example.com",
  "request":     "request.txt",
  "attack_mode": "cluster_bomb",

  "payloads": {
    "USER": { "type": "file",       "path": "users.txt" },
    "PASS": { "type": "file",       "path": "passwords.txt" },
    "ID":   { "type": "numbers",    "start": 1, "end": 9999, "format": "{:04d}" },
    "KEY":  { "type": "bruteforce", "charset": "abc123", "min_length": 4, "max_length": 6 },
    "OPT":  { "type": "list",       "values": ["admin", "root", "guest"] }
  },

  "match": {
    "status_codes":          [302, 200],
    "response_contains":     ["Welcome", "success"],
    "response_not_contains": ["Invalid", "failed"],
    "length_not_equals":     4832,
    "length_less_than":      null,
    "length_greater_than":   null
  },

  "stop": {
    "on_first_match": false,
    "max_matches":    0,
    "max_requests":   0
  },

  "options": {
    "workers":               20,
    "timeout":               10,
    "delay_ms":              0,
    "follow_redirects":      false,
    "verify_ssl":            false,
    "update_content_length": true,
    "save_matches_only":     false,
    "save_response_body":    false,
    "output":                "results.jsonl"
  }
}
```

### Config reference

#### `target`
Full base URL: `https://example.com` or `http://192.168.1.1:8080`.  
The scheme and port come from here — the request file only needs the path and headers.

#### `attack_mode`

| Mode | Payload sets | Total requests | Description |
|---|---|---|---|
| `cluster_bomb` | one per key | product of all sizes | Every combination — like a cartesian product |
| `pitchfork` | one per key | shortest set length | Parallel iteration — position 1 + position 2 together |
| `battering_ram` | one (shared) | size of payload set | Same value inserted into all positions simultaneously |
| `sniper` | one (shared) | size × number of positions | Each position attacked one at a time; others left empty |

#### `payloads`

Each key in this section must match a `$$$_KEYNAME_$$$` placeholder in the request.

| Type | Required fields | Optional |
|---|---|---|
| `file` | `path` | — |
| `bruteforce` | `charset`, `min_length`, `max_length` | — |
| `list` | `values` (array) | — |
| `numbers` | `start`, `end` | `step` (default 1), `format` (e.g. `"{:04d}"`) |

#### `match`

A response is flagged as a **match** if any of these conditions is true:

| Field | Matches when |
|---|---|
| `status_codes` | Response status is in the list |
| `response_contains` | Response body contains any of the strings |
| `response_not_contains` | Response body does NOT contain any of the strings |
| `length_not_equals` | Response length ≠ value (useful to spot anomalies vs a baseline) |
| `length_less_than` | Response length < value |
| `length_greater_than` | Response length > value |

#### `stop`

| Field | Effect |
|---|---|
| `on_first_match` | Stop after the first matched response |
| `max_matches` | Stop after this many matches (0 = unlimited) |
| `max_requests` | Stop after this many total requests (0 = unlimited) |

#### `options`

| Field | Default | Description |
|---|---|---|
| `workers` | 20 | Parallel HTTP connections |
| `timeout` | 10 | Per-request timeout in seconds |
| `delay_ms` | 0 | Delay between requests per worker (ms) |
| `follow_redirects` | false | Follow 3xx redirects (hides the redirect status) |
| `verify_ssl` | false | Verify SSL certificates |
| `update_content_length` | true | Recalculate `Content-Length` after substitution |
| `save_matches_only` | false | Only write matches to the output file |
| `save_response_body` | false | Include full response body in output for matches |
| `output` | auto-generated | Output `.jsonl` filename |
| `test_value` | `"TEST"` | Default substitution value used by `--test` when a payload's `test_value` is not set |
| `save_response_body` | false | Store full response body in output for matched requests |

Per-payload `test_value`: set `"test_value": "admin"` inside a payload spec to use a meaningful value during `--test` instead of the first dictionary entry.

---

## Test run (`--test`)

Before launching a full attack (which may send millions of requests), always verify your setup first:

```bash
python http.intruder.py config.json --test
```

The tool will:
1. Replace each placeholder with the payload's `test_value` (or the first entry from the wordlist/generator)
2. Print the fully-substituted request
3. Send it and print the complete response — status, headers, body preview
4. Evaluate whether the response would be flagged as a **match** under your config

Example output:

```
════════════════════════════════════════════════════════════════
  http.intruder  ·  TEST RUN
════════════════════════════════════════════════════════════════

  Placeholders:
    $$$_USER_$$$  →  admin
    $$$_PASS_$$$  →  password

  Request:
────────────────────────────────────────────────────────────────
  POST https://target.com/login
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 31

  username=admin&password=password
────────────────────────────────────────────────────────────────

  Response:
────────────────────────────────────────────────────────────────
  Status : 200   Length: 4832 bytes   Time: 43 ms

  content-type: text/html; charset=utf-8
  set-cookie: session=xyz; HttpOnly
  ...

  <html><body><p>Invalid username or password.</p>...
────────────────────────────────────────────────────────────────

  Match criteria : no match (expected for a test with non-payload values)

  Test complete. No output file written.
```

**What to check:**
- Status code is what you expect (200 for login forms, even on failure)
- Response body shows the "bad credentials" message — confirms the endpoint is right
- `Content-Length` was updated correctly after substitution
- If you see a connection error, check `target`, SSL settings, and the `Host` header

**Finding the baseline length** (for username enumeration):

```bash
# 1. Run test with an invalid username
python http.intruder.py config.json --test
# Note the response length, e.g. 4832

# 2. Set length_not_equals in the config
"match": { "length_not_equals": 4832 }

# 3. Run the attack — only valid usernames will be flagged
```

---

## Sample requests (`samples/`)

Three ready-to-use examples in the `samples/` folder:

| Files | Attack type | Description |
|---|---|---|
| `login_bruteforce.txt` + `login_bruteforce_config.json` | Cluster bomb | POST login form — try every user × every password |
| `username_enum.txt` + `username_enum_config.json` | Battering ram | Username enumeration via forgot-password response differences |
| `api_auth_fuzz.txt` + `api_auth_fuzz_config.json` | Pitchfork | API IDOR check — user IDs paired with known tokens |

### How to use a sample

```bash
cd samples/

# 1. Edit the config — change target, request path, and payload paths
#    The "request" field is relative to the config file location
nano login_bruteforce_config.json

# 2. Test
python ../http.intruder.py login_bruteforce_config.json --test

# 3. Attack
python ../http.intruder.py login_bruteforce_config.json
```

---

## Attack modes — examples

### Cluster bomb — credential brute-force (most common)

```json
"attack_mode": "cluster_bomb",
"payloads": {
  "USER": { "type": "file", "path": "users.txt" },
  "PASS": { "type": "file", "path": "passwords.txt" }
}
```

Tries every user + every password: `users × passwords` total requests.

### Pitchfork — token + username in parallel

```json
"attack_mode": "pitchfork",
"payloads": {
  "USER":  { "type": "file", "path": "users.txt" },
  "TOKEN": { "type": "file", "path": "tokens.txt" }
}
```

Row 1 of users.txt paired with row 1 of tokens.txt, row 2 with row 2, etc.

### Battering ram — same value everywhere

```json
"attack_mode": "battering_ram",
"payloads": {
  "USER": { "type": "file", "path": "wordlist.txt" }
}
```

Each word from the list is inserted into all `$$$_USER_$$$` placeholders simultaneously.

### Sniper — one position at a time

```json
"attack_mode": "sniper",
"payloads": {
  "PARAM": { "type": "file", "path": "fuzzing.txt" }
},
"base_values": { "PARAM2": "safe_value" }
```

Cycles through each placeholder in the request, injecting payloads one at a time while others get their `base_values` (default: empty string).

### Bruteforce — 4-to-6 char PIN

```json
"payloads": {
  "PIN": {
    "type":       "bruteforce",
    "charset":    "0123456789",
    "min_length": 4,
    "max_length": 6
  }
}
```

Generates: `0000, 0001, …, 9999, 00000, …, 999999` (1,110,000 values).

---

## Pause and resume

### Pause during a run

Press **Ctrl+C**. In-flight requests finish, then the attack pauses.  
The footer shows `⏸ PAUSED  ↵ resume  ·  Ctrl+C quit`.  
Press **Enter** to resume. Press **Ctrl+C** again to quit and save state.

### Resume after stopping

Re-run the same command:

```bash
python http.intruder.py config.json
```

The tool detects the saved state and prompts:

```
Previous run found:  45,231 requests completed,  3 matches  (started 2026-05-09T10:30:00)
  Output: results.jsonl

  [1] Continue   [2] Start fresh:
```

Choose **1** to skip the first 45,231 combinations and continue from where it left off.  
Choose **2** to delete the previous output and start fresh.

State is saved automatically every 10 seconds and always on pause/quit.

### Force fresh start (no prompt)

```bash
python http.intruder.py config.json --fresh
```

---

## Live display

```
──────────────────────────────────────────────────────────────────
  http.intruder  ·  cluster_bomb  ·  https://example.com
  Total: 10,000,000  Workers: 20  Output: results.jsonl
──────────────────────────────────────────────────────────────────
  Active:
  w0   USER=admin    PASS=password123           3s
  w1   USER=root     PASS=toor                  1s
  w2   USER=admin    PASS=p@ssword!             8s
──────────────────────────────────────────────────────────────────
  [45231]  USER=admin  PASS=password    200  4832b  44ms           ▲
  [45232]  USER=admin  PASS=Password1   302   234b   8ms  ★ MATCH  │
  [45233]  USER=root   PASS=toor        200  4832b  41ms           │
  [45234]  USER=guest  PASS=guest123    401   180b  12ms           ▼
──────────────────────────────────────────────────────────────────
  Done: 45,234/10,000,000  Matches: 1  [██░░░░░░░░░░░░░░░░░░░░░░]  Ctrl+C pause
```

---

## Output format (JSONL)

One record per request:

```jsonl
{"seq":45232,"timestamp":"2026-05-09T10:45:23Z","payloads":{"USER":"admin","PASS":"Password1"},"status":302,"length":234,"time_ms":8,"match":true}
{"seq":45233,"timestamp":"2026-05-09T10:45:23Z","payloads":{"USER":"root","PASS":"toor"},"status":200,"length":4832,"time_ms":41,"match":false}
```

### Fields

| Field | Description |
|---|---|
| `seq` | Request sequence number (1-based, global across resume) |
| `payloads` | Key → value map of injected values |
| `status` | HTTP response status code |
| `length` | Response body length in bytes |
| `time_ms` | Round-trip time in milliseconds |
| `match` | `true` if any match condition was met |
| `error` | Error message if the request failed |
| `response_body` | Full response body (only if `save_response_body: true` and `match: true`) |

### Querying results

```bash
# All matches
jq 'select(.match == true)' results.jsonl

# Matching payloads only
jq -r 'select(.match == true) | [.payloads.USER, .payloads.PASS] | @tsv' results.jsonl

# Status code distribution
jq -s 'group_by(.status) | map({status: .[0].status, count: length})' results.jsonl

# Anomalies — responses with unusual length
jq 'select(.length != 4832)' results.jsonl

# Fastest and slowest responses
jq -s 'sort_by(.time_ms) | last' results.jsonl
```

---

## Performance tips

| Scenario | Recommended settings |
|---|---|
| Small target (< 100k) | `workers: 20`, `timeout: 10` |
| Large target (1M+) | `workers: 50`, `timeout: 5`, `save_matches_only: true` |
| Rate-limited target | `workers: 5`, `delay_ms: 200` |
| Slow target | `workers: 10`, `timeout: 30` |
| Finding anomalies | Set `length_not_equals` to the baseline response size |

For 10M combinations with 50 workers and 200ms avg response:
```
10,000,000 / 50 × 0.2s ≈ 40,000s ≈ 11 hours
```

Use `stop.on_first_match: true` to halt immediately after a successful credential is found.

---

## Notes

- **`update_content_length`**: when `true` (default), the `Content-Length` header is recalculated after payload substitution. Set to `false` if the server ignores it or if you're injecting into the header itself.
- **SSL verification**: `verify_ssl: false` (default) accepts self-signed certificates.
- **Redirects**: `follow_redirects: false` (default) captures the raw 302 — usually what you want for login brute-force. Set to `true` to see the final page after redirect.
- **State file**: stored as `<output_file>.state` alongside the results. Delete it to force a fresh start (or use `--fresh`).
- **Memory**: all payload generators are lazy — a 10GB wordlist uses the same ~few KB of RAM as a 1KB file.
