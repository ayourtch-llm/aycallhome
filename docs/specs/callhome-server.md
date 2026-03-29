# aycallhome — Callhome Server Specification

## Overview

A HTTP server that receives "call home" registrations from Cisco IOS devices
running an EEM applet. The server tracks known (whitelisted) and unknown
devices, persists both tables to URLs via the `ayurl` crate, and periodically
refreshes the whitelist of valid serial numbers.

## EEM Applet

The applet runs every 300 seconds on each device. It extracts:

- **serial** — from `show inventory` (PID/SN line)
- **hostname** — from `show version` (uptime line)
- **model** — from `show inventory` (PID field)
- **version** — IOS software version from `show version`

It issues an HTTP GET to:

```
http://<server>/Register.aspx/serial=<SERIAL>/hostname=<HOSTNAME>/model=<MODEL>/version=<VERSION>
```

The device discards the response body (`copy <url> null:`).

### Modified EEM Applet

```
!
event manager applet CALLHOME
 event timer watchdog time 300
 ! Variable Initialisation
 action 010 cli command "enable"
 action 020 set URL "http://192.168.0.121/Register.aspx"
 action 030 set HOSTNAME "unknown"
 action 040 set SERIAL "unknown"
 action 050 set MODEL "unknown"
 action 055 set VERSION "unknown"
 ! Retrieve device serial number and model
 action 060 cli command "show inventory"
 action 070 regexp "[Pp][Ii][Dd]:\s*([A-Za-z0-9\-]*)[^\n]*[Ss][Nn]:\s*([A-Z0-9]*)" "$_cli_result" globalmatch MODEL SERIAL
 action 080 if $_regexp_result eq 0
 action 090 syslog priority errors msg "Unable to retrive serial or model from device inventory, please report the contents of 'show inventory'"
 action 100 else
 ! Retrieve device hostname and version
 action 110 cli command "show version | inc uptime|IOS Softwa"
 action 115 regexp "Version ([A-Za-z0-9\.\(\)]+)" "$_cli_result" globalmatch VERSION
 action 120 regexp "([A-Za-z0-9-]+) uptime is" "$_cli_result" globalmatch HOSTNAME
 ! Perform Callhome
 action 130 set URLARG "/serial=$SERIAL/hostname=$HOSTNAME/model=$MODEL/version=$VERSION"
 action 140 append URL "$URLARG"
 action 150 cli command "copy $URL null:"
 action 160 end
!
```

## Server Architecture

### Framework & Runtime

- **axum** for HTTP
- **tokio** for async runtime
- **tracing** + **tracing-subscriber** with `EnvFilter` for logging
  (consistent with aytelnet/ayurl patterns)
- **clap** with derive for CLI argument parsing (consistent with ayurl)
- **serde** + **serde_json** for table serialization
- **ayurl** (path dependency) for loading/saving data from/to URLs

### CLI Arguments

| Argument | Env var | Default | Description |
|---|---|---|---|
| `--listen-addr` | `AYCALLHOME_LISTEN_ADDR` | `::` | Address to bind (supports both IPv4 and IPv6) |
| `--port` | `AYCALLHOME_PORT` | `80` | Port to listen on |
| `--serial-url` | `AYCALLHOME_SERIAL_URL` | *(required)* | URL to file containing valid serial numbers (one per line) |
| `--known-url` | `AYCALLHOME_KNOWN_URL` | *(required)* | URL to load/save the known-devices table (JSON) |
| `--unknown-url` | `AYCALLHOME_UNKNOWN_URL` | *(required)* | URL to save the unknown-devices table (JSON) |
| `--known-save-interval` | `AYCALLHOME_KNOWN_SAVE_INTERVAL` | `60` | Seconds between periodic saves of the known-devices table |

### Listening

The server binds to the configured address and port. The default `::` binds
to both IPv4 and IPv6 on dual-stack systems. Users can override to `0.0.0.0`
for IPv4-only, `::1` for IPv6 loopback, etc.

## HTTP Endpoint

### `GET /Register.aspx/serial=<S>/hostname=<H>/model=<M>/version=<V>`

Path-based parameters (not query parameters) — this matches the EEM applet's
`copy <url> null:` mechanism which embeds values in the URL path.

The server must accept the `key=value` path segments in **any order**.

**Parameters** (extracted from URL path segments after `/Register.aspx/`):

| Name | Description |
|---|---|
| `serial` | Device serial number |
| `hostname` | Device hostname |
| `model` | Device model (PID) |
| `version` | IOS software version |

**Processing:**

1. Parse key=value pairs from path segments after `/Register.aspx/`
2. If serial is in the permitted-serials whitelist → upsert into **known devices** table
3. If serial is NOT in the whitelist → insert into **unknown devices** table
4. In both cases, record the source IP address. If the source is IPv4
   (including IPv4-mapped IPv6 like `::ffff:x.x.x.x`), update `last_ipv4`
   and `last_seen_ipv4`. If the source is IPv6, update `last_ipv6` and
   `last_seen_ipv6`.
5. Return HTTP 200 with a fun ASCII art response that includes the device's
   serial number.

**Response:**

HTTP 200 with `Content-Type: text/plain`. Body is an ASCII art picture
that incorporates the calling device's serial number. The response is
discarded by the device but is useful for manual testing.

## Data Model

### Permitted Serials

A plain-text file with one serial number per line (blank lines and lines
starting with `#` are ignored). Refreshed from the configured URL every
30 seconds.

### Known Devices Table

```json
[
  {
    "serial": "FCW2345G0AB",
    "version": "17.03.04a",
    "hostname": "switch-floor2",
    "model": "C9300-48P",
    "last_ipv4": "10.1.2.3",
    "last_ipv6": "2001:db8::1",
    "last_seen_ipv4": "2025-01-15T10:30:00Z",
    "last_seen_ipv6": "2025-01-15T10:30:00Z"
  }
]
```

- **Loaded** from `--known-url` at startup. If the URL returns an error or
  empty content, start with an empty table.
- **Saved** to `--known-url` every `--known-save-interval` seconds
  (default: 60s).
- Keyed by serial number. Each callhome request upserts the entry,
  updating hostname, model, version, and the relevant IP + timestamp fields.

### Unknown Devices Table

```json
[
  {
    "serial": "XYZUNKNOWN1",
    "version": "15.6(3)M7",
    "hostname": "rogue-router",
    "model": "ISR4331",
    "last_ipv4": "192.168.1.99",
    "last_ipv6": null,
    "last_seen_ipv4": "2025-01-15T10:31:00Z",
    "last_seen_ipv6": null,
    "first_seen": "2025-01-15T10:31:00Z",
    "last_seen": "2025-01-15T10:31:00Z"
  }
]
```

- **NOT loaded** at startup — always starts empty.
- **Saved** to `--unknown-url` when a new unknown device registers, but
  throttled to at most once per 30 seconds (coalescing multiple arrivals).
- `first_seen` records when the device was first observed.
- `last_seen` is updated on every request from this device and is used for
  FIFO eviction decisions.

### Unknown Devices — FIFO Eviction

When the number of unknown-device requests received in the past 60 seconds
exceeds 10,000:

- Delete entries with `last_seen` older than 3 minutes, oldest first (FIFO).
- This limits memory consumption under DoS-like conditions while preserving
  recently-active entries for investigation.

## Background Tasks

The server spawns the following `tokio::spawn` background tasks:

| Task | Interval | Description |
|---|---|---|
| Serial refresh | 30s | Fetch permitted-serials file via ayurl, parse, replace the in-memory set |
| Known-table save | configurable (default 60s) | Serialize known-devices table to JSON, PUT via ayurl |
| Unknown-table save | on-demand, throttled 30s | Serialize unknown-devices table to JSON, PUT via ayurl |
| Unknown-table eviction | continuous / on each request | Check rate counter; if >10k/min, purge entries older than 3 min |

## Shared State

Use `Arc<AppState>` passed to axum handlers via `Extension` or `State`:

```rust
struct AppState {
    known_devices: RwLock<HashMap<String, KnownDevice>>,
    unknown_devices: RwLock<HashMap<String, UnknownDevice>>,
    permitted_serials: RwLock<HashSet<String>>,
    unknown_request_timestamps: Mutex<VecDeque<Instant>>,
    // config fields...
}
```

`RwLock` from `tokio::sync` to allow concurrent reads from HTTP handlers with
exclusive writes from background tasks.

## Dependencies

```toml
[dependencies]
ayurl = { path = "../ayurl" }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive", "env"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
chrono = { version = "0.4", features = ["serde"] }
```

## Error Handling

- Background task failures (ayurl fetch/save) are logged at `warn` level and
  retried on the next interval. They do not crash the server.
- Malformed callhome requests (missing serial, unparseable path) return
  HTTP 400 with a plain-text error message.
- Startup failure to load known-devices table is logged at `warn` and the
  server starts with an empty table.

## Development Methodology — Red-Green TDD

All implementation must follow strict red-green TDD:

1. **Red** — Write a failing test first that describes the desired behavior.
2. **Green** — Write the minimum production code to make the test pass.
3. **Refactor** — Clean up while keeping tests green.

Repeat for each unit of functionality. Do not write production code without
a corresponding failing test already in place. The test suite should cover:

- URL path parsing (all parameter orders, missing params, malformed paths)
- Known vs unknown device classification based on permitted serials
- Upsert logic for known devices (IPv4/IPv6 address and timestamp updates)
- Unknown devices table insertion and `last_seen` updates
- FIFO eviction logic (rate threshold, age cutoff)
- Serial whitelist parsing (comments, blank lines, valid entries)
- ASCII art response generation with serial number
- Integration tests using axum's test utilities (`TestClient` or
  `oneshot` requests) for end-to-end request handling

## Future Considerations (out of scope)

- TLS termination (use a reverse proxy)
- Authentication beyond serial-number whitelisting
- Web UI for viewing device tables
- Webhook/notification on new unknown device
