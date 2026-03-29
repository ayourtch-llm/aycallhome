use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(name = "aycallhome", about = "Cisco IOS call-home server")]
pub struct Cli {
    /// Address to bind (supports IPv4 and IPv6)
    #[arg(long, env = "AYCALLHOME_LISTEN_ADDR", default_value = "::")]
    pub listen_addr: String,

    /// Port to listen on
    #[arg(long, env = "AYCALLHOME_PORT", default_value_t = 80)]
    pub port: u16,

    /// URL to file containing valid serial numbers (one per line)
    #[arg(long, env = "AYCALLHOME_SERIAL_URL")]
    pub serial_url: String,

    /// URL to load/save the known-devices table (JSON)
    #[arg(long, env = "AYCALLHOME_KNOWN_URL")]
    pub known_url: String,

    /// URL to save the unknown-devices table (JSON)
    #[arg(long, env = "AYCALLHOME_UNKNOWN_URL")]
    pub unknown_url: String,

    /// Seconds between periodic saves of the known-devices table
    #[arg(long, env = "AYCALLHOME_KNOWN_SAVE_INTERVAL", default_value_t = 60)]
    pub known_save_interval: u64,
}

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnownDevice {
    pub serial: String,
    pub version: String,
    pub hostname: String,
    pub model: String,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_seen_ipv4: Option<DateTime<Utc>>,
    pub last_seen_ipv6: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownDevice {
    pub serial: String,
    pub version: String,
    pub hostname: String,
    pub model: String,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_seen_ipv4: Option<DateTime<Utc>>,
    pub last_seen_ipv6: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

// ─── CallhomeParams (parsed from URL path) ──────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct CallhomeParams {
    pub serial: String,
    pub hostname: String,
    pub model: String,
    pub version: String,
}

/// Parse key=value path segments after `/Register.aspx/`.
/// Returns `Ok(CallhomeParams)` or an error string describing what's missing/malformed.
pub fn parse_callhome_path(path: &str) -> Result<CallhomeParams, String> {
    // Strip the leading "/Register.aspx/" prefix (case-sensitive per spec)
    let rest = path
        .strip_prefix("/Register.aspx/")
        .ok_or_else(|| format!("path does not start with /Register.aspx/: {}", path))?;

    let mut map: HashMap<String, String> = HashMap::new();
    for segment in rest.split('/') {
        if segment.is_empty() {
            continue;
        }
        let mut parts = segment.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(k), Some(v)) => {
                map.insert(k.to_ascii_lowercase(), v.to_string());
            }
            _ => return Err(format!("malformed path segment: '{}'", segment)),
        }
    }

    let mut get = |key: &str| -> Result<String, String> {
        map.remove(key)
            .ok_or_else(|| format!("missing required parameter: '{}'", key))
    };

    Ok(CallhomeParams {
        serial: get("serial")?,
        hostname: get("hostname")?,
        model: get("model")?,
        version: get("version")?,
    })
}

// ─── Whitelist parsing ───────────────────────────────────────────────────────

/// Parse a permitted-serials text: one serial per line; blank lines and
/// lines starting with `#` are ignored.
pub fn parse_serial_whitelist(content: &str) -> HashSet<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

// ─── ASCII art response ──────────────────────────────────────────────────────

pub fn ascii_art_response(serial: &str) -> String {
    format!(
        r#"
   ___      _ _   _                  _
  / __|__ _| | | | |_  ___ _ __  ___| |
 | (__/ _` | | |_| ' \/ _ \ '  \/ -_)_|
  \___\__,_|_|\___/_||_\___/_|_|_\___(_)

  Device serial: [ {serial} ]

  Your call-home registration has been received.
  Have a great day!
"#,
        serial = serial
    )
}

// ─── IP address classification ───────────────────────────────────────────────

/// Returns `(is_ipv4, canonical_string)` where `is_ipv4` is true for both
/// real IPv4 addresses and IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
pub fn classify_ip(addr: &std::net::IpAddr) -> (bool, String) {
    match addr {
        std::net::IpAddr::V4(v4) => (true, v4.to_string()),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                (true, v4.to_string())
            } else {
                (false, v6.to_string())
            }
        }
    }
}

// ─── Shared state ────────────────────────────────────────────────────────────

pub struct AppState {
    pub known_devices: RwLock<HashMap<String, KnownDevice>>,
    pub unknown_devices: RwLock<HashMap<String, UnknownDevice>>,
    pub permitted_serials: RwLock<HashSet<String>>,
    pub unknown_request_timestamps: Mutex<VecDeque<Instant>>,
    pub config: Cli,
    /// Signals the unknown-save task to wake up.
    pub unknown_save_notify: tokio::sync::Notify,
}

impl AppState {
    pub fn new(config: Cli) -> Arc<Self> {
        Arc::new(Self {
            known_devices: RwLock::new(HashMap::new()),
            unknown_devices: RwLock::new(HashMap::new()),
            permitted_serials: RwLock::new(HashSet::new()),
            unknown_request_timestamps: Mutex::new(VecDeque::new()),
            config,
            unknown_save_notify: tokio::sync::Notify::new(),
        })
    }
}

// ─── FIFO eviction ───────────────────────────────────────────────────────────

/// Record a new unknown-device timestamp and, if the rate exceeds 10 000
/// requests in the past 60 seconds, evict entries older than 3 minutes.
pub async fn maybe_evict_unknown(state: &AppState) {
    let now = Instant::now();
    let window = std::time::Duration::from_secs(60);
    let evict_age = std::time::Duration::from_secs(180);

    let rate_exceeded = {
        let mut ts = state.unknown_request_timestamps.lock().await;
        ts.push_back(now);
        // Trim entries older than the window
        while ts.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            ts.pop_front();
        }
        ts.len() > 10_000
    };

    if rate_exceeded {
        let cutoff = now - evict_age;
        let mut unknown = state.unknown_devices.write().await;
        unknown.retain(|_, dev| {
            // Convert last_seen (UTC) to an approximate Instant for comparison.
            // We use the current wall time minus how long ago last_seen was.
            let age_secs = (Utc::now() - dev.last_seen).num_seconds().max(0) as u64;
            let approx_last_seen = now.checked_sub(std::time::Duration::from_secs(age_secs));
            match approx_last_seen {
                Some(t) => t > cutoff,
                None => false,
            }
        });
    }
}

// ─── HTTP handler ────────────────────────────────────────────────────────────

/// Axum wildcard handler for `/Register.aspx/*rest`
pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> Response {
    let path = uri.path();

    let params = match parse_callhome_path(path) {
        Ok(p) => p,
        Err(e) => {
            warn!("bad callhome request ({}): {}", addr, e);
            return (StatusCode::BAD_REQUEST, format!("Bad request: {}\n", e)).into_response();
        }
    };

    let (is_ipv4, ip_str) = classify_ip(&addr.ip());
    let now = Utc::now();

    let permitted = {
        let serials = state.permitted_serials.read().await;
        serials.contains(&params.serial)
    };

    if permitted {
        let mut known = state.known_devices.write().await;
        let entry = known.entry(params.serial.clone()).or_insert_with(|| KnownDevice {
            serial: params.serial.clone(),
            version: params.version.clone(),
            hostname: params.hostname.clone(),
            model: params.model.clone(),
            last_ipv4: None,
            last_ipv6: None,
            last_seen_ipv4: None,
            last_seen_ipv6: None,
        });
        entry.version = params.version.clone();
        entry.hostname = params.hostname.clone();
        entry.model = params.model.clone();
        if is_ipv4 {
            entry.last_ipv4 = Some(ip_str.clone());
            entry.last_seen_ipv4 = Some(now);
        } else {
            entry.last_ipv6 = Some(ip_str.clone());
            entry.last_seen_ipv6 = Some(now);
        }
        info!("known device registered: serial={} ip={}", params.serial, ip_str);
    } else {
        {
            let mut unknown = state.unknown_devices.write().await;
            let entry = unknown.entry(params.serial.clone()).or_insert_with(|| UnknownDevice {
                serial: params.serial.clone(),
                version: params.version.clone(),
                hostname: params.hostname.clone(),
                model: params.model.clone(),
                last_ipv4: None,
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
                first_seen: now,
                last_seen: now,
            });
            entry.version = params.version.clone();
            entry.hostname = params.hostname.clone();
            entry.model = params.model.clone();
            entry.last_seen = now;
            if is_ipv4 {
                entry.last_ipv4 = Some(ip_str.clone());
                entry.last_seen_ipv4 = Some(now);
            } else {
                entry.last_ipv6 = Some(ip_str.clone());
                entry.last_seen_ipv6 = Some(now);
            }
        }
        warn!("unknown device registered: serial={} ip={}", params.serial, ip_str);
        state.unknown_save_notify.notify_one();
        maybe_evict_unknown(&state).await;
    }

    let body = ascii_art_response(&params.serial);
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        body,
    )
        .into_response()
}

// ─── Router builder (shared with integration tests) ─────────────────────────

async fn fallback_handler(req: axum::extract::Request) -> impl IntoResponse {
    let remote = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    warn!(
        remote = %remote,
        method = %req.method(),
        uri = %req.uri(),
        "request to unknown URL"
    );
    (StatusCode::NOT_FOUND, "Not Found\n")
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/Register.aspx/{*rest}", get(register_handler))
        .fallback(fallback_handler)
        .with_state(state)
}

// ─── Background tasks ────────────────────────────────────────────────────────

async fn refresh_serials_task(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let url = state.config.serial_url.clone();
        match ayurl::get(&url).await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    let set = parse_serial_whitelist(&text);
                    info!("refreshed {} permitted serials from {}", set.len(), url);
                    *state.permitted_serials.write().await = set;
                }
                Err(e) => warn!("failed to read serial whitelist body: {}", e),
            },
            Err(e) => warn!("failed to fetch serial whitelist from {}: {}", url, e),
        }
    }
}

async fn save_known_task(state: Arc<AppState>) {
    let interval = state.config.known_save_interval;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
        let url = state.config.known_url.clone();
        let data = {
            let known = state.known_devices.read().await;
            let devices: Vec<&KnownDevice> = known.values().collect();
            serde_json::to_string(&devices)
        };
        match data {
            Ok(json) => {
                if let Err(e) = ayurl::put(&url).text(json).await {
                    warn!("failed to save known devices to {}: {}", url, e);
                } else {
                    info!("saved known devices to {}", url);
                }
            }
            Err(e) => warn!("failed to serialize known devices: {}", e),
        }
    }
}

async fn save_unknown_task(state: Arc<AppState>) {
    let throttle = std::time::Duration::from_secs(30);
    loop {
        // Wait for a notification from the request handler
        state.unknown_save_notify.notified().await;
        // Throttle: sleep 30 seconds, ignoring any further notifications during that time
        tokio::time::sleep(throttle).await;
        let url = state.config.unknown_url.clone();
        let data = {
            let unknown = state.unknown_devices.read().await;
            let devices: Vec<&UnknownDevice> = unknown.values().collect();
            serde_json::to_string(&devices)
        };
        match data {
            Ok(json) => {
                if let Err(e) = ayurl::put(&url).text(json).await {
                    warn!("failed to save unknown devices to {}: {}", url, e);
                } else {
                    info!("saved unknown devices to {}", url);
                }
            }
            Err(e) => warn!("failed to serialize unknown devices: {}", e),
        }
    }
}

// ─── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    ayurl::init_tracing();
    let cli = Cli::parse();

    let state = AppState::new(cli.clone());

    // Load known devices at startup
    match ayurl::get(&cli.known_url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) if !text.trim().is_empty() => {
                match serde_json::from_str::<Vec<KnownDevice>>(&text) {
                    Ok(devices) => {
                        let mut known = state.known_devices.write().await;
                        for d in devices {
                            known.insert(d.serial.clone(), d);
                        }
                        info!("loaded {} known devices", known.len());
                    }
                    Err(e) => warn!("failed to parse known devices JSON: {}", e),
                }
            }
            _ => info!("starting with empty known-devices table"),
        },
        Err(e) => warn!("could not load known devices from {}: {}", cli.known_url, e),
    }

    // Load initial serial whitelist
    match ayurl::get(&cli.serial_url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let set = parse_serial_whitelist(&text);
                info!("loaded {} permitted serials", set.len());
                *state.permitted_serials.write().await = set;
            }
            Err(e) => warn!("failed to read serial whitelist: {}", e),
        },
        Err(e) => warn!("could not load serials from {}: {}", cli.serial_url, e),
    }

    // Spawn background tasks
    tokio::spawn(refresh_serials_task(state.clone()));
    tokio::spawn(save_known_task(state.clone()));
    tokio::spawn(save_unknown_task(state.clone()));

    let router = build_router(state.clone());

    let bind_addr = format!("{}:{}", cli.listen_addr, cli.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", bind_addr, e);
        std::process::exit(1);
    });
    info!("listening on {}", listener.local_addr().unwrap());

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // ── parse_callhome_path ──────────────────────────────────────────────────

    #[test]
    fn test_parse_standard_order() {
        let p = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/hostname=router1/model=C9300/version=17.03",
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname, "router1");
        assert_eq!(p.model, "C9300");
        assert_eq!(p.version, "17.03");
    }

    #[test]
    fn test_parse_any_order() {
        let p = parse_callhome_path(
            "/Register.aspx/version=17.03/model=C9300/serial=FCW1234/hostname=router1",
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname, "router1");
        assert_eq!(p.model, "C9300");
        assert_eq!(p.version, "17.03");
    }

    #[test]
    fn test_parse_missing_serial() {
        let err = parse_callhome_path(
            "/Register.aspx/hostname=router1/model=C9300/version=17.03",
        )
        .unwrap_err();
        assert!(err.contains("serial"), "expected 'serial' in error: {}", err);
    }

    #[test]
    fn test_parse_missing_hostname() {
        let err = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/model=C9300/version=17.03",
        )
        .unwrap_err();
        assert!(err.contains("hostname"), "expected 'hostname' in error: {}", err);
    }

    #[test]
    fn test_parse_missing_model() {
        let err = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/hostname=router1/version=17.03",
        )
        .unwrap_err();
        assert!(err.contains("model"), "expected 'model' in error: {}", err);
    }

    #[test]
    fn test_parse_missing_version() {
        let err = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/hostname=router1/model=C9300",
        )
        .unwrap_err();
        assert!(err.contains("version"), "expected 'version' in error: {}", err);
    }

    #[test]
    fn test_parse_wrong_prefix() {
        let err =
            parse_callhome_path("/other/serial=FCW1234/hostname=r/model=C/version=1").unwrap_err();
        assert!(err.contains("Register.aspx"));
    }

    #[test]
    fn test_parse_malformed_segment() {
        let err = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/badnoequals/hostname=r/model=C/version=1",
        )
        .unwrap_err();
        assert!(err.contains("malformed"), "expected 'malformed' in: {}", err);
    }

    #[test]
    fn test_parse_value_with_dots_and_parens() {
        // IOS version strings look like "15.6(3)M7"
        let p = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/hostname=router1/model=ISR4331/version=15.6(3)M7",
        )
        .unwrap();
        assert_eq!(p.version, "15.6(3)M7");
    }

    // ── parse_serial_whitelist ───────────────────────────────────────────────

    #[test]
    fn test_whitelist_basic() {
        let set = parse_serial_whitelist("FCW1234\nFCW5678\n");
        assert!(set.contains("FCW1234"));
        assert!(set.contains("FCW5678"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_whitelist_ignores_comments() {
        let set = parse_serial_whitelist("# this is a comment\nFCW1234\n# another\n");
        assert!(!set.contains("# this is a comment"));
        assert!(set.contains("FCW1234"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_whitelist_ignores_blank_lines() {
        let set = parse_serial_whitelist("\n\nFCW1234\n\n");
        assert!(set.contains("FCW1234"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_whitelist_trims_whitespace() {
        let set = parse_serial_whitelist("  FCW1234  \n  FCW5678  \n");
        assert!(set.contains("FCW1234"));
        assert!(set.contains("FCW5678"));
    }

    #[test]
    fn test_whitelist_empty() {
        let set = parse_serial_whitelist("# only comments\n\n");
        assert!(set.is_empty());
    }

    // ── ascii_art_response ───────────────────────────────────────────────────

    #[test]
    fn test_ascii_art_contains_serial() {
        let serial = "FCW2345G0AB";
        let body = ascii_art_response(serial);
        assert!(
            body.contains(serial),
            "ASCII art response should contain serial number"
        );
    }

    #[test]
    fn test_ascii_art_nonempty() {
        let body = ascii_art_response("TEST123");
        assert!(!body.trim().is_empty());
    }

    // ── classify_ip ─────────────────────────────────────────────────────────

    #[test]
    fn test_classify_ipv4() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let (is_v4, s) = classify_ip(&ip);
        assert!(is_v4);
        assert_eq!(s, "192.168.1.1");
    }

    #[test]
    fn test_classify_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let (is_v4, s) = classify_ip(&ip);
        assert!(!is_v4);
        assert_eq!(s, "2001:db8::1");
    }

    #[test]
    fn test_classify_ipv4_mapped_ipv6() {
        // ::ffff:192.168.1.1
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let (is_v4, s) = classify_ip(&ip);
        assert!(is_v4, "IPv4-mapped IPv6 should be classified as IPv4");
        assert_eq!(s, "192.168.1.1");
    }

    // ── integration tests ────────────────────────────────────────────────────
    //
    // Because our handler uses ConnectInfo<SocketAddr>, we must use a real
    // TCP transport (not axum-test's mock transport).  We build the app via
    // into_make_service_with_connect_info and use TestServer::builder()
    // .http_transport().build(app).

    fn make_test_state() -> Arc<AppState> {
        let cli = Cli {
            listen_addr: "::".to_string(),
            port: 8080,
            serial_url: "file:///dev/null".to_string(),
            known_url: "file:///dev/null".to_string(),
            unknown_url: "file:///dev/null".to_string(),
            known_save_interval: 60,
        };
        AppState::new(cli)
    }

    fn make_test_server(state: Arc<AppState>) -> axum_test::TestServer {
        let app = build_router(state)
            .into_make_service_with_connect_info::<SocketAddr>();
        axum_test::TestServer::builder()
            .http_transport()
            .build(app)
    }

    #[tokio::test]
    async fn test_unknown_url_returns_404() {
        let state = make_test_state();
        let server = make_test_server(state);
        let resp = server.get("/some/random/path").await;
        assert_eq!(resp.status_code(), 404);
    }

    #[tokio::test]
    async fn test_register_known_device_returns_200() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("FCW1234".to_string());

        let server = make_test_server(state.clone());
        let resp = server
            .get("/Register.aspx/serial=FCW1234/hostname=router1/model=C9300/version=17.03")
            .await;
        assert_eq!(resp.status_code(), 200);
    }

    #[tokio::test]
    async fn test_register_known_device_body_contains_serial() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("FCW1234".to_string());

        let server = make_test_server(state.clone());
        let resp = server
            .get("/Register.aspx/serial=FCW1234/hostname=router1/model=C9300/version=17.03")
            .await;
        let body = resp.text();
        assert!(
            body.contains("FCW1234"),
            "response body should contain serial number"
        );
    }

    #[tokio::test]
    async fn test_register_known_device_stored_in_known_table() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("FCW5678".to_string());

        let server = make_test_server(state.clone());
        server
            .get("/Register.aspx/serial=FCW5678/hostname=sw-floor2/model=C9300-48P/version=17.03.04a")
            .await;

        let known = state.known_devices.read().await;
        assert!(known.contains_key("FCW5678"), "device should be in known table");
        let dev = &known["FCW5678"];
        assert_eq!(dev.hostname, "sw-floor2");
        assert_eq!(dev.model, "C9300-48P");
        assert_eq!(dev.version, "17.03.04a");
    }

    #[tokio::test]
    async fn test_register_unknown_device_stored_in_unknown_table() {
        let state = make_test_state();

        let server = make_test_server(state.clone());
        server
            .get("/Register.aspx/serial=ROGUE001/hostname=rogue/model=ISR4331/version=15.6")
            .await;

        let unknown = state.unknown_devices.read().await;
        assert!(
            unknown.contains_key("ROGUE001"),
            "device should be in unknown table"
        );
    }

    #[tokio::test]
    async fn test_register_unknown_device_not_in_known_table() {
        let state = make_test_state();

        let server = make_test_server(state.clone());
        server
            .get("/Register.aspx/serial=ROGUE002/hostname=rogue/model=ISR4331/version=15.6")
            .await;

        let known = state.known_devices.read().await;
        assert!(
            !known.contains_key("ROGUE002"),
            "unknown device must NOT be in known table"
        );
    }

    #[tokio::test]
    async fn test_register_missing_serial_returns_400() {
        let state = make_test_state();
        let server = make_test_server(state);
        let resp = server
            .get("/Register.aspx/hostname=router1/model=C9300/version=17.03")
            .await;
        assert_eq!(resp.status_code(), 400);
    }

    #[tokio::test]
    async fn test_register_any_parameter_order_accepted() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("FCW9999".to_string());

        let server = make_test_server(state.clone());
        // version first, then model, then hostname, then serial
        let resp = server
            .get("/Register.aspx/version=17.03/model=C9300/hostname=sw1/serial=FCW9999")
            .await;
        assert_eq!(resp.status_code(), 200);

        let known = state.known_devices.read().await;
        assert!(known.contains_key("FCW9999"));
    }

    #[tokio::test]
    async fn test_upsert_known_device_updates_fields() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("FCW0001".to_string());

        let server = make_test_server(state.clone());

        // First registration
        server
            .get("/Register.aspx/serial=FCW0001/hostname=old-name/model=C9300/version=17.01")
            .await;

        // Second registration with updated fields
        server
            .get("/Register.aspx/serial=FCW0001/hostname=new-name/model=C9300/version=17.05")
            .await;

        let known = state.known_devices.read().await;
        let dev = &known["FCW0001"];
        assert_eq!(dev.hostname, "new-name");
        assert_eq!(dev.version, "17.05");
    }

    #[tokio::test]
    async fn test_unknown_device_first_seen_set_on_insert() {
        let state = make_test_state();

        let server = make_test_server(state.clone());
        server
            .get("/Register.aspx/serial=NEWROGUE/hostname=rogue/model=ISR/version=15.6")
            .await;

        let unknown = state.unknown_devices.read().await;
        let dev = &unknown["NEWROGUE"];
        // first_seen and last_seen should be very close to now
        let age = Utc::now() - dev.first_seen;
        assert!(age.num_seconds() < 5, "first_seen should be recent");
    }

    #[tokio::test]
    async fn test_unknown_device_last_seen_updated() {
        let state = make_test_state();

        let server = make_test_server(state.clone());

        server
            .get("/Register.aspx/serial=UPDATEROGUE/hostname=rogue/model=ISR/version=15.6")
            .await;

        let first_seen = {
            let unknown = state.unknown_devices.read().await;
            unknown["UPDATEROGUE"].first_seen
        };

        // Small sleep to ensure timestamps differ
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        server
            .get("/Register.aspx/serial=UPDATEROGUE/hostname=rogue/model=ISR/version=15.6")
            .await;

        let unknown = state.unknown_devices.read().await;
        let dev = &unknown["UPDATEROGUE"];
        assert_eq!(dev.first_seen, first_seen, "first_seen must not change on re-registration");
        // last_seen should be >= first_seen
        assert!(dev.last_seen >= dev.first_seen);
    }

    // ── FIFO eviction ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_eviction_does_not_trigger_below_threshold() {
        let cli = Cli {
            listen_addr: "::".to_string(),
            port: 8080,
            serial_url: "file:///dev/null".to_string(),
            known_url: "file:///dev/null".to_string(),
            unknown_url: "file:///dev/null".to_string(),
            known_save_interval: 60,
        };
        let state = AppState::new(cli);

        // Add one unknown device with a recent last_seen
        {
            let now = Utc::now();
            let mut unknown = state.unknown_devices.write().await;
            unknown.insert(
                "KEEP".to_string(),
                UnknownDevice {
                    serial: "KEEP".to_string(),
                    version: "1".to_string(),
                    hostname: "h".to_string(),
                    model: "m".to_string(),
                    last_ipv4: None,
                    last_ipv6: None,
                    last_seen_ipv4: None,
                    last_seen_ipv6: None,
                    first_seen: now,
                    last_seen: now,
                },
            );
        }

        // 50 requests — well below 10,000 threshold
        for _ in 0..50 {
            maybe_evict_unknown(&state).await;
        }

        let unknown = state.unknown_devices.read().await;
        assert!(unknown.contains_key("KEEP"), "device should NOT be evicted");
    }

    #[tokio::test]
    async fn test_eviction_removes_old_entries_above_threshold() {
        let cli = Cli {
            listen_addr: "::".to_string(),
            port: 8080,
            serial_url: "file:///dev/null".to_string(),
            known_url: "file:///dev/null".to_string(),
            unknown_url: "file:///dev/null".to_string(),
            known_save_interval: 60,
        };
        let state = AppState::new(cli);

        let old_time = Utc::now() - chrono::Duration::minutes(10);
        let recent_time = Utc::now();

        {
            let mut unknown = state.unknown_devices.write().await;
            unknown.insert(
                "OLD".to_string(),
                UnknownDevice {
                    serial: "OLD".to_string(),
                    version: "1".to_string(),
                    hostname: "h".to_string(),
                    model: "m".to_string(),
                    last_ipv4: None,
                    last_ipv6: None,
                    last_seen_ipv4: None,
                    last_seen_ipv6: None,
                    first_seen: old_time,
                    last_seen: old_time,
                },
            );
            unknown.insert(
                "RECENT".to_string(),
                UnknownDevice {
                    serial: "RECENT".to_string(),
                    version: "1".to_string(),
                    hostname: "h".to_string(),
                    model: "m".to_string(),
                    last_ipv4: None,
                    last_ipv6: None,
                    last_seen_ipv4: None,
                    last_seen_ipv6: None,
                    first_seen: recent_time,
                    last_seen: recent_time,
                },
            );
        }

        // Flood 10,001 timestamps to trigger eviction
        {
            let mut ts = state.unknown_request_timestamps.lock().await;
            let now = Instant::now();
            for _ in 0..10_001 {
                ts.push_back(now);
            }
        }

        maybe_evict_unknown(&state).await;

        let unknown = state.unknown_devices.read().await;
        assert!(
            !unknown.contains_key("OLD"),
            "OLD device (10 min old) should be evicted"
        );
        assert!(
            unknown.contains_key("RECENT"),
            "RECENT device should be kept"
        );
    }
}
