use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnownDevice {
    pub serial: String,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_seen_ipv4: Option<DateTime<Utc>>,
    pub last_seen_ipv6: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownDevice {
    pub serial: String,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub model: Option<String>,
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
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
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

    let serial = map
        .remove("serial")
        .ok_or_else(|| "missing required parameter: 'serial'".to_string())?;

    Ok(CallhomeParams {
        serial,
        hostname: map.remove("hostname"),
        model: map.remove("model"),
        version: map.remove("version"),
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

/// Load known devices from a URL (JSON array).
/// Returns an empty map if the URL is empty or unreachable.
pub async fn load_known_devices(url: &str) -> HashMap<String, KnownDevice> {
    match ayurl::get(url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) if !text.trim().is_empty() => {
                match serde_json::from_str::<Vec<KnownDevice>>(&text) {
                    Ok(devices) => devices.into_iter().map(|d| (d.serial.clone(), d)).collect(),
                    Err(e) => {
                        tracing::warn!("failed to parse known devices JSON from {}: {}", url, e);
                        HashMap::new()
                    }
                }
            }
            _ => HashMap::new(),
        },
        Err(e) => {
            tracing::warn!("could not load known devices from {}: {}", url, e);
            HashMap::new()
        }
    }
}

/// Load unknown devices from a URL (JSON array).
/// Returns an empty map if the URL is empty or unreachable.
pub async fn load_unknown_devices(url: &str) -> HashMap<String, UnknownDevice> {
    match ayurl::get(url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) if !text.trim().is_empty() => {
                match serde_json::from_str::<Vec<UnknownDevice>>(&text) {
                    Ok(devices) => devices.into_iter().map(|d| (d.serial.clone(), d)).collect(),
                    Err(e) => {
                        tracing::warn!(
                            "failed to parse unknown devices JSON from {}: {}",
                            url,
                            e
                        );
                        HashMap::new()
                    }
                }
            }
            _ => HashMap::new(),
        },
        Err(e) => {
            tracing::warn!("could not load unknown devices from {}: {}", url, e);
            HashMap::new()
        }
    }
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

/// Save known devices to a URL as sorted, pretty-printed JSON.
pub async fn save_known_devices(
    url: &str,
    devices: &HashMap<String, KnownDevice>,
) -> Result<(), String> {
    let mut sorted: Vec<&KnownDevice> = devices.values().collect();
    sorted.sort_by(|a, b| a.serial.cmp(&b.serial));
    let json = serde_json::to_string_pretty(&sorted)
        .map_err(|e| format!("failed to serialize known devices: {}", e))?;
    ayurl::put(url)
        .text(json)
        .await
        .map_err(|e| format!("failed to save known devices to {}: {}", url, e))?;
    Ok(())
}

/// Save unknown devices to a URL as sorted, pretty-printed JSON.
pub async fn save_unknown_devices(
    url: &str,
    devices: &HashMap<String, UnknownDevice>,
) -> Result<(), String> {
    let mut sorted: Vec<&UnknownDevice> = devices.values().collect();
    sorted.sort_by(|a, b| a.serial.cmp(&b.serial));
    let json = serde_json::to_string_pretty(&sorted)
        .map_err(|e| format!("failed to serialize unknown devices: {}", e))?;
    ayurl::put(url)
        .text(json)
        .await
        .map_err(|e| format!("failed to save unknown devices to {}: {}", url, e))?;
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

    // ── load/save helpers ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_load_known_devices_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("known.json");
        let url = format!("file://{}", path.display());

        let mut devices = HashMap::new();
        devices.insert(
            "SN001".to_string(),
            KnownDevice {
                serial: "SN001".to_string(),
                version: Some("17.03".to_string()),
                hostname: Some("sw1".to_string()),
                model: Some("C9300".to_string()),
                last_ipv4: Some("10.0.0.1".to_string()),
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
            },
        );

        save_known_devices(&url, &devices).await.unwrap();
        let loaded = load_known_devices(&url).await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["SN001"].hostname.as_deref(), Some("sw1"));
    }

    #[tokio::test]
    async fn test_load_unknown_devices_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("unknown.json");
        let url = format!("file://{}", path.display());

        let now = Utc::now();
        let mut devices = HashMap::new();
        devices.insert(
            "ROGUE".to_string(),
            UnknownDevice {
                serial: "ROGUE".to_string(),
                version: Some("15.6".to_string()),
                hostname: Some("rogue".to_string()),
                model: Some("ISR".to_string()),
                last_ipv4: None,
                last_ipv6: None,
                last_seen_ipv4: None,
                last_seen_ipv6: None,
                first_seen: now,
                last_seen: now,
            },
        );

        save_unknown_devices(&url, &devices).await.unwrap();
        let loaded = load_unknown_devices(&url).await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["ROGUE"].hostname.as_deref(), Some("rogue"));
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
    async fn test_load_known_devices_empty_url() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        let url = format!("file://{}", path.display());

        let loaded = load_known_devices(&url).await;
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_save_known_devices_sorted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sorted.json");
        let url = format!("file://{}", path.display());

        let mut devices = HashMap::new();
        for serial in &["ZZZ", "AAA", "MMM"] {
            devices.insert(
                serial.to_string(),
                KnownDevice {
                    serial: serial.to_string(),
                    version: Some("1".to_string()),
                    hostname: Some("h".to_string()),
                    model: Some("m".to_string()),
                    last_ipv4: None,
                    last_ipv6: None,
                    last_seen_ipv4: None,
                    last_seen_ipv6: None,
                },
            );
        }

        save_known_devices(&url, &devices).await.unwrap();
        let json = std::fs::read_to_string(&path).unwrap();

        // AAA should appear before MMM, which should appear before ZZZ
        let aaa_pos = json.find("AAA").unwrap();
        let mmm_pos = json.find("MMM").unwrap();
        let zzz_pos = json.find("ZZZ").unwrap();
        assert!(aaa_pos < mmm_pos);
        assert!(mmm_pos < zzz_pos);
    }
}
