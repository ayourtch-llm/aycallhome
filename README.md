# aycallhome

A call-home registration server for Cisco IOS devices. Receives HTTP GET
requests from an EEM applet running on each device, tracks known
(whitelisted) and unknown devices, and persists both tables to URLs via
the [ayurl](../ayurl) crate.

## How it works

Each Cisco device runs an EEM applet every 5 minutes that extracts the
device serial number, hostname, model, and IOS version, then issues:

```
GET /Register.aspx/serial=<S>/hostname=<H>/model=<M>/version=<V>
```

The server checks the serial against a whitelist of permitted serials:

- **Known device** — upserted into the known-devices table with IP and
  timestamp
- **Unknown device** — tracked in a separate table with first-seen and
  last-seen timestamps

Both tables are periodically saved as sorted, pretty-printed JSON to
configurable URLs (local files, HTTP endpoints, SCP/SFTP targets — anything
ayurl supports). The permitted-serials list is refreshed every 30 seconds.

When a device that was previously unknown gets added to the whitelist and
calls home again, it is automatically promoted to the known table and
removed from the unknown table.

## Usage

```
aycallhome \
  --serial-url file:///etc/aycallhome/serials.txt \
  --known-url file:///var/lib/aycallhome/known.json \
  --unknown-url file:///var/lib/aycallhome/unknown.json
```

### CLI arguments

| Argument | Env var | Default | Description |
|---|---|---|---|
| `--listen-addr` | `AYCALLHOME_LISTEN_ADDR` | `::` | Bind address (IPv4 and IPv6) |
| `--port` | `AYCALLHOME_PORT` | `80` | Listen port |
| `--serial-url` | `AYCALLHOME_SERIAL_URL` | *(required)* | URL to permitted serial numbers (one per line) |
| `--known-url` | `AYCALLHOME_KNOWN_URL` | *(required)* | URL to load/save known-devices table (JSON) |
| `--unknown-url` | `AYCALLHOME_UNKNOWN_URL` | *(required)* | URL to save unknown-devices table (JSON) |
| `--known-save-interval` | `AYCALLHOME_KNOWN_SAVE_INTERVAL` | `60` | Seconds between known-table saves |

### Serials file format

```
# Lines starting with # are comments
# Blank lines are ignored
FCW2345G0AB
FCW9876H1CD
```

## Library usage

The crate is also a library. Other tools can depend on it to read device
tables without reimplementing the schema:

```rust
use aycallhome::{load_known_devices, load_unknown_devices, load_serial_whitelist};
use aycallhome::{save_known_devices, save_unknown_devices};
use aycallhome::{KnownDevice, UnknownDevice};

// Load from any URL that ayurl supports
let known = load_known_devices("file:///var/lib/aycallhome/known.json").await;
let unknown = load_unknown_devices("sftp://host/path/unknown.json").await;
let serials = load_serial_whitelist("http://config-server/serials.txt").await;

// Save back
save_known_devices("file:///var/lib/aycallhome/known.json", &known).await.unwrap();
```

## Data model

### Known devices

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

### Unknown devices

Same fields plus `first_seen` and `last_seen`:

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

## EEM applet

Install this on each Cisco IOS device to enable call-home:

```
event manager applet CALLHOME
 event timer watchdog time 300
 action 010 cli command "enable"
 action 020 set URL "http://<server>/Register.aspx"
 action 030 set HOSTNAME "unknown"
 action 040 set SERIAL "unknown"
 action 050 set MODEL "unknown"
 action 055 set VERSION "unknown"
 action 060 cli command "show inventory"
 action 070 regexp "[Pp][Ii][Dd]:\s*([A-Za-z0-9\-]*)[^\n]*[Ss][Nn]:\s*([A-Z0-9]*)" "$_cli_result" globalmatch MODEL SERIAL
 action 080 if $_regexp_result eq 0
 action 090 syslog priority errors msg "Unable to retrieve serial or model from device inventory"
 action 100 else
 action 110 cli command "show version | inc uptime|IOS Softwa"
 action 115 regexp "Version ([A-Za-z0-9\.\(\)]+)" "$_cli_result" globalmatch VERSION
 action 120 regexp "([A-Za-z0-9-]+) uptime is" "$_cli_result" globalmatch HOSTNAME
 action 130 set URLARG "/serial=$SERIAL/hostname=$HOSTNAME/model=$MODEL/version=$VERSION"
 action 140 append URL "$URLARG"
 action 150 cli command "copy $URL null:"
 action 160 end
```

## Background tasks

| Task | Interval | Description |
|---|---|---|
| Serial refresh | 30s | Re-fetch and replace the permitted-serials set |
| Known-table save | configurable (default 60s) | Save known devices as sorted JSON |
| Unknown-table save | on-demand, throttled 30s | Save unknown devices when changes occur |
| Unknown-table eviction | per-request | If >10k unknown requests/min, purge entries older than 3 min |

## Design considerations

This design trades simplicity and loose coupling for scale. Device tables
are plain JSON files read and written via URLs — no database required.
The target network size is under 5,000 devices.

The call-home requests are unauthenticated. This is intended for
controlled, lightweight networks where the server is not exposed to the
public internet. Adding request authentication (e.g., per-device tokens
or mutual TLS) may be a subject for future work.

## Building and testing

```
cargo build
cargo test
```
