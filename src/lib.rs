use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Device {
    pub serial: String,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub token: Option<String>,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_seen_ipv4: Option<DateTime<Utc>>,
    pub last_seen_ipv6: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
}

impl Device {
    /// Returns the most recent time this device was seen, across IPv4 and IPv6.
    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        match (self.last_seen_ipv4, self.last_seen_ipv6) {
            (Some(v4), Some(v6)) => Some(v4.max(v6)),
            (Some(v4), None) => Some(v4),
            (None, Some(v6)) => Some(v6),
            (None, None) => None,
        }
    }
}

// ─── CallhomeParams (parsed from URL path) ──────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct CallhomeParams {
    pub serial: String,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub token: Option<String>,
}

/// Parse key=value path segments after `/Register.aspx/`.
/// Returns `Ok(CallhomeParams)` or an error string describing what's missing/malformed.
pub fn parse_callhome_path(path: &str) -> Result<CallhomeParams, String> {
    parse_callhome_params(path, None)
}

/// Parse callhome parameters from path segments and/or query string.
///
/// Path segments (`/Register.aspx/serial=X/hostname=Y`) and query parameters
/// (`?serial=X&hostname=Y`) are both supported and can be mixed. When a key
/// appears in both, the query parameter takes precedence.
pub fn parse_callhome_params(path: &str, query: Option<&str>) -> Result<CallhomeParams, String> {
    let mut map: HashMap<String, String> = HashMap::new();

    // Parse path segments after /Register.aspx/
    if let Some(rest) = path.strip_prefix("/Register.aspx/") {
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
    } else if path != "/Register.aspx" {
        return Err(format!("path does not start with /Register.aspx: {}", path));
    }

    // Parse query parameters (override path values)
    if let Some(qs) = query {
        for pair in qs.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                map.insert(k.to_ascii_lowercase(), v.to_string());
            }
        }
    }

    let serial = map
        .remove("serial")
        .ok_or_else(|| "missing required parameter: 'serial'".to_string())?;

    Ok(CallhomeParams {
        serial,
        hostname: map.remove("hostname"),
        model: map.remove("model"),
        version: map.remove("version"),
        token: map.remove("token"),
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

// ─── URL-based load/save helpers ────────────────────────────────────────────

/// Load devices from a URL (JSON array).
/// Returns an empty map if the URL is empty or unreachable.
pub async fn load_devices(url: &str) -> HashMap<String, Device> {
    match ayurl::get(url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) if !text.trim().is_empty() => {
                match serde_json::from_str::<Vec<Device>>(&text) {
                    Ok(devices) => devices.into_iter().map(|d| (d.serial.clone(), d)).collect(),
                    Err(e) => {
                        tracing::warn!("failed to parse devices JSON from {}: {}", url, e);
                        HashMap::new()
                    }
                }
            }
            _ => HashMap::new(),
        },
        Err(e) => {
            tracing::warn!("could not load devices from {}: {}", url, e);
            HashMap::new()
        }
    }
}

/// Load devices from a URL (JSON array), preserving insertion order.
/// Returns an `IndexMap` so callers that need deterministic key ordering get it.
/// Returns an empty map if the URL is empty or unreachable.
pub async fn load_devices_ordered(url: &str) -> IndexMap<String, Device> {
    match ayurl::get(url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) if !text.trim().is_empty() => {
                match serde_json::from_str::<Vec<Device>>(&text) {
                    Ok(devices) => devices.into_iter().map(|d| (d.serial.clone(), d)).collect(),
                    Err(e) => {
                        tracing::warn!("failed to parse devices JSON from {}: {}", url, e);
                        IndexMap::new()
                    }
                }
            }
            _ => IndexMap::new(),
        },
        Err(e) => {
            tracing::warn!("could not load devices from {}: {}", url, e);
            IndexMap::new()
        }
    }
}

/// Load devices from a URL (JSON array), preserving insertion order.
/// Returns `Err` if the URL is empty, the HTTP request fails, or JSON parsing fails.
/// Returns `Ok(empty IndexMap)` if the response body is empty (zero devices registered).
pub async fn try_load_devices_ordered(url: &str) -> Result<IndexMap<String, Device>, String> {
    if url.is_empty() {
        return Err("empty URL".to_string());
    }
    let resp = ayurl::get(url)
        .await
        .map_err(|e| format!("failed to fetch {}: {}", url, e))?;
    let text = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response body from {}: {}", url, e))?;
    if text.trim().is_empty() {
        return Ok(IndexMap::new());
    }
    let devices: Vec<Device> = serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse devices JSON from {}: {}", url, e))?;
    Ok(devices.into_iter().map(|d| (d.serial.clone(), d)).collect())
}

/// Load the serial whitelist from a URL (one serial per line).
/// Returns an empty set if the URL is unreachable.
pub async fn load_serial_whitelist(url: &str) -> HashSet<String> {
    match ayurl::get(url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) => parse_serial_whitelist(&text),
            Err(e) => {
                tracing::warn!("failed to read serial whitelist body from {}: {}", url, e);
                HashSet::new()
            }
        },
        Err(e) => {
            tracing::warn!("could not load serial whitelist from {}: {}", url, e);
            HashSet::new()
        }
    }
}

/// Save devices to a URL as sorted, pretty-printed JSON.
pub async fn save_devices(
    url: &str,
    devices: &HashMap<String, Device>,
) -> Result<(), String> {
    let mut sorted: Vec<&Device> = devices.values().collect();
    sorted.sort_by(|a, b| a.serial.cmp(&b.serial));
    let json = serde_json::to_string_pretty(&sorted)
        .map_err(|e| format!("failed to serialize devices: {}", e))?;
    ayurl::put(url)
        .text(json)
        .await
        .map_err(|e| format!("failed to save devices to {}: {}", url, e))?;
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
        assert_eq!(p.hostname.as_deref(), Some("router1"));
        assert_eq!(p.model.as_deref(), Some("C9300"));
        assert_eq!(p.version.as_deref(), Some("17.03"));
    }

    #[test]
    fn test_parse_any_order() {
        let p = parse_callhome_path(
            "/Register.aspx/version=17.03/model=C9300/serial=FCW1234/hostname=router1",
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname.as_deref(), Some("router1"));
        assert_eq!(p.model.as_deref(), Some("C9300"));
        assert_eq!(p.version.as_deref(), Some("17.03"));
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
    fn test_parse_serial_only() {
        let p = parse_callhome_path("/Register.aspx/serial=FCW1234").unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname, None);
        assert_eq!(p.model, None);
        assert_eq!(p.version, None);
    }

    #[test]
    fn test_parse_partial_params() {
        let p = parse_callhome_path(
            "/Register.aspx/serial=FCW1234/hostname=router1",
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname.as_deref(), Some("router1"));
        assert_eq!(p.model, None);
        assert_eq!(p.version, None);
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
        assert_eq!(p.version.as_deref(), Some("15.6(3)M7"));
    }

    // ── parse_callhome_params with query parameters ───────────────────────

    #[test]
    fn test_parse_query_params_only() {
        let p = parse_callhome_params(
            "/Register.aspx",
            Some("serial=FCW1234&hostname=router1&model=C9300&version=17.03"),
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname.as_deref(), Some("router1"));
        assert_eq!(p.model.as_deref(), Some("C9300"));
        assert_eq!(p.version.as_deref(), Some("17.03"));
    }

    #[test]
    fn test_parse_query_params_serial_only() {
        let p = parse_callhome_params(
            "/Register.aspx",
            Some("serial=FCW1234"),
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname, None);
    }

    #[test]
    fn test_parse_mixed_path_and_query() {
        // Serial in path, rest in query
        let p = parse_callhome_params(
            "/Register.aspx/serial=FCW1234",
            Some("hostname=router1&model=C9300"),
        )
        .unwrap();
        assert_eq!(p.serial, "FCW1234");
        assert_eq!(p.hostname.as_deref(), Some("router1"));
        assert_eq!(p.model.as_deref(), Some("C9300"));
        assert_eq!(p.version, None);
    }

    #[test]
    fn test_parse_query_overrides_path() {
        // hostname in both — query wins
        let p = parse_callhome_params(
            "/Register.aspx/serial=FCW1234/hostname=old",
            Some("hostname=new"),
        )
        .unwrap();
        assert_eq!(p.hostname.as_deref(), Some("new"));
    }

    #[test]
    fn test_parse_query_missing_serial() {
        let err = parse_callhome_params(
            "/Register.aspx",
            Some("hostname=router1"),
        )
        .unwrap_err();
        assert!(err.contains("serial"));
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

    // ── Device::last_seen ─────────────────────────────────────────────────

    #[test]
    fn test_last_seen_both() {
        let earlier = Utc::now() - chrono::Duration::minutes(5);
        let later = Utc::now();
        let dev = Device {
            serial: "X".to_string(),
            version: None,
            hostname: None,
            model: None,
            token: None,
            last_ipv4: None,
            last_ipv6: None,
            last_seen_ipv4: Some(earlier),
            last_seen_ipv6: Some(later),
            first_seen: None,
        };
        assert_eq!(dev.last_seen(), Some(later));
    }

    #[test]
    fn test_last_seen_ipv4_only() {
        let now = Utc::now();
        let dev = Device {
            serial: "X".to_string(),
            version: None,
            hostname: None,
            model: None,
            token: None,
            last_ipv4: None,
            last_ipv6: None,
            last_seen_ipv4: Some(now),
            last_seen_ipv6: None,
            first_seen: None,
        };
        assert_eq!(dev.last_seen(), Some(now));
    }

    #[test]
    fn test_last_seen_neither() {
        let dev = Device {
            serial: "X".to_string(),
            version: None,
            hostname: None,
            model: None,
            token: None,
            last_ipv4: None,
            last_ipv6: None,
            last_seen_ipv4: None,
            last_seen_ipv6: None,
            first_seen: None,
        };
        assert_eq!(dev.last_seen(), None);
    }

    // ── load/save helpers ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_load_devices_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("devices.json");
        let url = format!("file://{}", path.display());

        let mut devices = HashMap::new();
        devices.insert(
            "SN001".to_string(),
            Device {
                serial: "SN001".to_string(),
                version: Some("17.03".to_string()),
                hostname: Some("sw1".to_string()),
                model: Some("C9300".to_string()),
                token: None,
                last_ipv4: Some("10.0.0.1".to_string()),
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
                first_seen: None,
            },
        );

        save_devices(&url, &devices).await.unwrap();
        let loaded = load_devices(&url).await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["SN001"].hostname.as_deref(), Some("sw1"));
    }

    #[tokio::test]
    async fn test_load_devices_with_first_seen_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("devices.json");
        let url = format!("file://{}", path.display());

        let now = Utc::now();
        let mut devices = HashMap::new();
        devices.insert(
            "ROGUE".to_string(),
            Device {
                serial: "ROGUE".to_string(),
                version: Some("15.6".to_string()),
                hostname: Some("rogue".to_string()),
                model: Some("ISR".to_string()),
                token: None,
                last_ipv4: None,
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
                first_seen: Some(now),
            },
        );

        save_devices(&url, &devices).await.unwrap();
        let loaded = load_devices(&url).await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["ROGUE"].hostname.as_deref(), Some("rogue"));
        assert!(loaded["ROGUE"].first_seen.is_some());
    }

    #[tokio::test]
    async fn test_first_seen_omitted_from_json_when_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("no_first_seen.json");
        let url = format!("file://{}", path.display());

        let mut devices = HashMap::new();
        devices.insert(
            "SN001".to_string(),
            Device {
                serial: "SN001".to_string(),
                version: None,
                hostname: None,
                model: None,
                token: None,
                last_ipv4: None,
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
                first_seen: None,
            },
        );

        save_devices(&url, &devices).await.unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        assert!(!json.contains("first_seen"), "first_seen should be omitted when None");
    }

    #[tokio::test]
    async fn test_load_serial_whitelist_from_url() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("serials.txt");
        std::fs::write(&path, "# comment\nFCW001\nFCW002\n").unwrap();
        let url = format!("file://{}", path.display());

        let set = load_serial_whitelist(&url).await;
        assert_eq!(set.len(), 2);
        assert!(set.contains("FCW001"));
        assert!(set.contains("FCW002"));
    }

    #[tokio::test]
    async fn test_load_devices_empty_url() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let url = format!("file://{}", path.display());

        let loaded = load_devices(&url).await;
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_load_devices_ordered_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("ordered.json");
        // Write a JSON array with a specific order: ZZZ, AAA, MMM
        let json = r#"[
            {"serial":"ZZZ","version":null,"hostname":null,"model":null,"token":null,"last_ipv4":null,"last_ipv6":null,"last_seen_ipv4":null,"last_seen_ipv6":null},
            {"serial":"AAA","version":null,"hostname":null,"model":null,"token":null,"last_ipv4":null,"last_ipv6":null,"last_seen_ipv4":null,"last_seen_ipv6":null},
            {"serial":"MMM","version":null,"hostname":null,"model":null,"token":null,"last_ipv4":null,"last_ipv6":null,"last_seen_ipv4":null,"last_seen_ipv6":null}
        ]"#;
        std::fs::write(&path, json).unwrap();
        let url = format!("file://{}", path.display());

        let loaded = load_devices_ordered(&url).await;
        assert_eq!(loaded.len(), 3);

        // Verify insertion order is preserved (ZZZ first, then AAA, then MMM)
        let keys: Vec<&str> = loaded.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["ZZZ", "AAA", "MMM"]);
    }

    // ── try_load_devices_ordered ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_try_load_devices_ordered_empty_url_returns_err() {
        let result = try_load_devices_ordered("").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "empty URL");
    }

    #[tokio::test]
    async fn test_try_load_devices_ordered_empty_body_returns_ok_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let url = format!("file://{}", path.display());

        let result = try_load_devices_ordered(&url).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_try_load_devices_ordered_invalid_json_returns_err() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not valid json").unwrap();
        let url = format!("file://{}", path.display());

        let result = try_load_devices_ordered(&url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse devices JSON"));
    }

    #[tokio::test]
    async fn test_try_load_devices_ordered_valid_returns_ok_with_devices() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("devices.json");
        let json = r#"[
            {"serial":"ZZZ","version":null,"hostname":null,"model":null,"token":null,"last_ipv4":null,"last_ipv6":null,"last_seen_ipv4":null,"last_seen_ipv6":null},
            {"serial":"AAA","version":null,"hostname":null,"model":null,"token":null,"last_ipv4":null,"last_ipv6":null,"last_seen_ipv4":null,"last_seen_ipv6":null}
        ]"#;
        std::fs::write(&path, json).unwrap();
        let url = format!("file://{}", path.display());

        let result = try_load_devices_ordered(&url).await;
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 2);
        let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["ZZZ", "AAA"]);
    }

    #[tokio::test]
    async fn test_try_load_devices_ordered_bad_url_returns_err() {
        let result = try_load_devices_ordered("file:///nonexistent/path/devices.json").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_save_devices_sorted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sorted.json");
        let url = format!("file://{}", path.display());

        let mut devices = HashMap::new();
        for serial in &["ZZZ", "AAA", "MMM"] {
            devices.insert(
                serial.to_string(),
                Device {
                    serial: serial.to_string(),
                    version: Some("1".to_string()),
                    hostname: Some("h".to_string()),
                    model: Some("m".to_string()),
                    token: None,
                    last_ipv4: None,
                    last_ipv6: None,
                    last_seen_ipv4: None,
                    last_seen_ipv6: None,
                    first_seen: None,
                },
            );
        }

        save_devices(&url, &devices).await.unwrap();
        let json = std::fs::read_to_string(&path).unwrap();

        // AAA should appear before MMM, which should appear before ZZZ
        let aaa_pos = json.find("AAA").unwrap();
        let mmm_pos = json.find("MMM").unwrap();
        let zzz_pos = json.find("ZZZ").unwrap();
        assert!(aaa_pos < mmm_pos);
        assert!(mmm_pos < zzz_pos);
    }
}
