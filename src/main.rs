use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use clap::Parser;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use aycallhome::*;

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
        while ts
            .front()
            .map(|t| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
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
    let query = uri.query();

    let params = match parse_callhome_params(path, query) {
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
        let entry = known
            .entry(params.serial.clone())
            .or_insert_with(|| KnownDevice {
                serial: params.serial.clone(),
                version: None,
                hostname: None,
                model: None,
                token: None,
                last_ipv4: None,
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
            });
        if params.version.is_some() {
            entry.version = params.version.clone();
        }
        if params.hostname.is_some() {
            entry.hostname = params.hostname.clone();
        }
        if params.model.is_some() {
            entry.model = params.model.clone();
        }
        if params.token.is_some() {
            entry.token = params.token.clone();
        }
        if is_ipv4 {
            entry.last_ipv4 = Some(ip_str.clone());
            entry.last_seen_ipv4 = Some(now);
        } else {
            entry.last_ipv6 = Some(ip_str.clone());
            entry.last_seen_ipv6 = Some(now);
        }
        // If the device was previously unknown, remove it
        {
            let mut unknown = state.unknown_devices.write().await;
            if unknown.remove(&params.serial).is_some() {
                info!(
                    "promoted device from unknown to known: serial={}",
                    params.serial
                );
                state.unknown_save_notify.notify_one();
            }
        }
        info!(
            "known device registered: serial={} ip={}",
            params.serial, ip_str
        );
    } else {
        {
            let mut unknown = state.unknown_devices.write().await;
            let entry =
                unknown
                    .entry(params.serial.clone())
                    .or_insert_with(|| UnknownDevice {
                        serial: params.serial.clone(),
                        version: None,
                        hostname: None,
                        model: None,
                        token: None,
                        last_ipv4: None,
                        last_ipv6: None,
                        last_seen_ipv4: None,
                        last_seen_ipv6: None,
                        first_seen: now,
                        last_seen: now,
                    });
            if params.version.is_some() {
                entry.version = params.version.clone();
            }
            if params.hostname.is_some() {
                entry.hostname = params.hostname.clone();
            }
            if params.model.is_some() {
                entry.model = params.model.clone();
            }
            if params.token.is_some() {
                entry.token = params.token.clone();
            }
            entry.last_seen = now;
            if is_ipv4 {
                entry.last_ipv4 = Some(ip_str.clone());
                entry.last_seen_ipv4 = Some(now);
            } else {
                entry.last_ipv6 = Some(ip_str.clone());
                entry.last_seen_ipv6 = Some(now);
            }
        }
        warn!(
            "unknown device registered: serial={} ip={}",
            params.serial, ip_str
        );
        state.unknown_save_notify.notify_one();
        maybe_evict_unknown(&state).await;
    }

    let body = ascii_art_response(&params.serial);
    (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
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
        .route("/Register.aspx", get(register_handler))
        .route("/Register.aspx/{*rest}", get(register_handler))
        .fallback(fallback_handler)
        .with_state(state)
}

// ─── Background tasks ────────────────────────────────────────────────────────

async fn refresh_serials_task(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let url = state.config.serial_url.clone();
        let set = load_serial_whitelist(&url).await;
        if !set.is_empty() {
            info!("refreshed {} permitted serials from {}", set.len(), url);
        }
        *state.permitted_serials.write().await = set;
    }
}

async fn save_known_task(state: Arc<AppState>) {
    let interval = state.config.known_save_interval;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
        let url = state.config.known_url.clone();
        let devices = state.known_devices.read().await.clone();
        match save_known_devices(&url, &devices).await {
            Ok(()) => info!("saved known devices to {}", url),
            Err(e) => warn!("{}", e),
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
        let devices = state.unknown_devices.read().await.clone();
        match save_unknown_devices(&url, &devices).await {
            Ok(()) => info!("saved unknown devices to {}", url),
            Err(e) => warn!("{}", e),
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
    let known = load_known_devices(&cli.known_url).await;
    if !known.is_empty() {
        info!("loaded {} known devices", known.len());
    } else {
        info!("starting with empty known-devices table");
    }
    *state.known_devices.write().await = known;

    // Load initial serial whitelist
    let serials = load_serial_whitelist(&cli.serial_url).await;
    info!("loaded {} permitted serials", serials.len());
    *state.permitted_serials.write().await = serials;

    // Spawn background tasks
    tokio::spawn(refresh_serials_task(state.clone()));
    tokio::spawn(save_known_task(state.clone()));
    tokio::spawn(save_unknown_task(state.clone()));

    let router = build_router(state.clone());

    let bind_addr = format!("{}:{}", cli.listen_addr, cli.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| {
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
        let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();
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
            .get(
                "/Register.aspx/serial=FCW5678/hostname=sw-floor2/model=C9300-48P/version=17.03.04a",
            )
            .await;

        let known = state.known_devices.read().await;
        assert!(
            known.contains_key("FCW5678"),
            "device should be in known table"
        );
        let dev = &known["FCW5678"];
        assert_eq!(dev.hostname.as_deref(), Some("sw-floor2"));
        assert_eq!(dev.model.as_deref(), Some("C9300-48P"));
        assert_eq!(dev.version.as_deref(), Some("17.03.04a"));
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
    async fn test_register_via_query_params() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("QRY001".to_string());

        let server = make_test_server(state.clone());
        let resp = server
            .get("/Register.aspx?serial=QRY001&hostname=sw-query&model=C9300&version=17.03")
            .await;
        assert_eq!(resp.status_code(), 200);

        let known = state.known_devices.read().await;
        assert!(known.contains_key("QRY001"));
        let dev = &known["QRY001"];
        assert_eq!(dev.hostname.as_deref(), Some("sw-query"));
        assert_eq!(dev.model.as_deref(), Some("C9300"));
    }

    #[tokio::test]
    async fn test_register_via_mixed_path_and_query() {
        let state = make_test_state();
        state
            .permitted_serials
            .write()
            .await
            .insert("MIX001".to_string());

        let server = make_test_server(state.clone());
        let resp = server
            .get("/Register.aspx/serial=MIX001?hostname=sw-mixed&model=C9300")
            .await;
        assert_eq!(resp.status_code(), 200);

        let known = state.known_devices.read().await;
        assert!(known.contains_key("MIX001"));
        assert_eq!(known["MIX001"].hostname.as_deref(), Some("sw-mixed"));
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
        assert_eq!(dev.hostname.as_deref(), Some("new-name"));
        assert_eq!(dev.version.as_deref(), Some("17.05"));
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
        assert_eq!(
            dev.first_seen, first_seen,
            "first_seen must not change on re-registration"
        );
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
                    version: Some("1".to_string()),
                    hostname: Some("h".to_string()),
                    model: Some("m".to_string()),
                    token: None,
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
    async fn test_device_promoted_from_unknown_to_known_removes_from_unknown() {
        let state = make_test_state();
        let server = make_test_server(state.clone());

        // Step 1: device calls home while NOT in permitted list → lands in unknown
        server
            .get("/Register.aspx/serial=PROMO001/hostname=sw1/model=C9300/version=17.03")
            .await;
        {
            let unknown = state.unknown_devices.read().await;
            assert!(
                unknown.contains_key("PROMO001"),
                "device should be in unknown table after first call-home"
            );
        }

        // Step 2: add the serial to the permitted list (simulates whitelist reload)
        state
            .permitted_serials
            .write()
            .await
            .insert("PROMO001".to_string());

        // Step 3: device calls home again, now it IS permitted
        server
            .get("/Register.aspx/serial=PROMO001/hostname=sw1/model=C9300/version=17.03")
            .await;

        // It should now be in the known table
        {
            let known = state.known_devices.read().await;
            assert!(
                known.contains_key("PROMO001"),
                "device should be in known table after promotion"
            );
        }

        // And it should be REMOVED from the unknown table
        {
            let unknown = state.unknown_devices.read().await;
            assert!(
                !unknown.contains_key("PROMO001"),
                "device should be removed from unknown table after promotion"
            );
        }
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
                    version: Some("1".to_string()),
                    hostname: Some("h".to_string()),
                    model: Some("m".to_string()),
                    token: None,
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
                    version: Some("1".to_string()),
                    hostname: Some("h".to_string()),
                    model: Some("m".to_string()),
                    token: None,
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
