use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ─── App Config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub abuseipdb_key: Option<String>,
    pub abuseipdb_enabled: Option<bool>,
    pub cache_hours: Option<u64>,
    pub threat_score_red: Option<u8>,
    pub threat_score_yellow: Option<u8>,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            abuseipdb_key: None,
            abuseipdb_enabled: Some(false),
            cache_hours: Some(24),
            threat_score_red: Some(50),
            threat_score_yellow: Some(20),
        }
    }
}

fn load_config() -> AppConfig {
    let mut exe_path = std::env::current_exe().unwrap_or_default();
    exe_path.pop();
    let release_config = exe_path.join("resources").join("config.json");

    let dev_config = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string())
    ).join("resources").join("config.json");

    let config_path = if release_config.exists() {
        release_config
    } else if dev_config.exists() {
        dev_config
    } else {
        eprintln!("No config.json found — threat intel disabled");
        return AppConfig::default();
    };

    match std::fs::read_to_string(&config_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
            eprintln!("Failed to parse config.json: {}", e);
            AppConfig::default()
        }),
        Err(e) => {
            eprintln!("Failed to read config.json: {}", e);
            AppConfig::default()
        }
    }
}

// ─── Threat Intel ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub score: u8,
    pub reports: u32,
}

async fn check_abuse_ip(ip: &str, api_key: &str) -> Option<ThreatInfo> {
    if ip.starts_with("127.")
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("100.")
        || ip.starts_with("172.")
        || ip == "0.0.0.0"
    {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", api_key)
        .header("Accept", "application/json")
        .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
        .send()
        .await
        .ok()?;

    let json: serde_json::Value = resp.json().await.ok()?;
    let data = json.get("data")?;

    let score   = data["abuseConfidenceScore"].as_u64().unwrap_or(0) as u8;
    let reports = data["totalReports"].as_u64().unwrap_or(0) as u32;

    Some(ThreatInfo { score, reports })
}

// ─── Connection ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub country_code: String,
    pub country_flag: String,
    pub threat_score: i16,
    pub threat_reports: u32,
}

// ─── Country Flag ─────────────────────────────────────────────────────────────

fn country_flag(code: &str) -> String {
    if code.len() != 2 {
        return "🌐".to_string();
    }
    let bytes = code.as_bytes();
    let c1 = char::from_u32(0x1F1E0 + (bytes[0] - b'A') as u32).unwrap_or('🌐');
    let c2 = char::from_u32(0x1F1E0 + (bytes[1] - b'A') as u32).unwrap_or('🌐');
    format!("{}{}", c1, c2)
}

fn lookup_country(ip: &str, reader: Option<&maxminddb::Reader<Vec<u8>>>) -> (String, String) {
    if ip == "0.0.0.0"
        || ip.starts_with("127.")
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || ip.starts_with("100.")
        || ip.starts_with("172.16.") || ip.starts_with("172.17.")
        || ip.starts_with("172.18.") || ip.starts_with("172.19.")
        || ip.starts_with("172.20.") || ip.starts_with("172.21.")
        || ip.starts_with("172.22.") || ip.starts_with("172.23.")
        || ip.starts_with("172.24.") || ip.starts_with("172.25.")
        || ip.starts_with("172.26.") || ip.starts_with("172.27.")
        || ip.starts_with("172.28.") || ip.starts_with("172.29.")
        || ip.starts_with("172.30.") || ip.starts_with("172.31.")
    {
        return ("LAN".to_string(), "LAN".to_string());
    }

    if ip.starts_with("104.")
        || ip.starts_with("162.158.") || ip.starts_with("162.159.") || ip.starts_with("162.160.")
        || ip.starts_with("172.6") || ip.starts_with("172.7")
        || ip.starts_with("188.114.")
        || ip.starts_with("198.41.") || ip.starts_with("197.234.")
        || ip.starts_with("190.93.")
        || ip.starts_with("103.21.") || ip.starts_with("103.22.") || ip.starts_with("103.31.")
        || ip.starts_with("141.101.")
    {
        return ("CF".to_string(), "CF".to_string());
    }

    if let Some(r) = reader {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if let Ok(record) = r.lookup::<maxminddb::geoip2::Country>(addr) {
                if let Some(country) = record.country {
                    let code = country.iso_code.unwrap_or("??").to_string();
                    let flag = country_flag(&code);
                    return (code, flag);
                }
            }
        }
    }
    ("??".to_string(), "??".to_string())
}

fn get_db_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap_or_default();
    path.pop(); // remove executable name — now at MacOS/ or the exe dir

    // macOS .app bundle: resources are at Contents/Resources/
    // executable is at Contents/MacOS/vigilance
    // so go up one more level to Contents/ then into Resources/
    #[cfg(target_os = "macos")]
    {
        let macos_bundle_path = path
            .parent()                          // up from MacOS/ to Contents/
            .unwrap_or(&path)
            .join("Resources")                 // into Contents/Resources/
            .join("GeoLite2-Country.mmdb");
        if macos_bundle_path.exists() {
            return macos_bundle_path;
        }
    }

    // Windows release path — resources next to exe
    let release_path = path.join("resources").join("GeoLite2-Country.mmdb");
    if release_path.exists() {
        return release_path;
    }

    // Dev mode fallback — use CARGO_MANIFEST_DIR
    std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string())
    ).join("resources").join("GeoLite2-Country.mmdb")
}

// ─── macOS rules file path ────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn get_rules_path() -> std::path::PathBuf {
    // Store in user home directory so it persists across app restarts and is writable without sudo
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".vigilance_rules.json")

}

// Write ALL currently blocked IPs as a single pf anchor load.
// This ensures the full rule set is always in sync — never partial.
#[cfg(target_os = "macos")]
fn apply_pf_rules(ips: &[String]) -> bool {
    if ips.is_empty() {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "pfctl", "-a", "vigilance", "-F", "rules"])
            .output();
        return true;
    }
    let rules: String = ips.iter()
        .map(|ip| format!("block out quick proto tcp from any to {}\n", ip))
        .collect();
    let tmp = "/tmp/vigilance_all_rules.conf";
    if std::fs::write(tmp, &rules).is_err() {
        return false;
    }
    std::process::Command::new("sudo")
        .args(["-n", "pfctl", "-a", "vigilance", "-f", tmp])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── Windows Network ──────────────────────────────────────────────────────────

#[cfg(windows)]
mod windows_net {
    use super::*;
    use std::collections::HashMap;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW,
        ENUM_SERVICE_STATUS_PROCESSW, SC_MANAGER_ENUMERATE_SERVICE,
        SC_ENUM_PROCESS_INFO, SERVICE_STATE_ALL, SERVICE_WIN32,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use std::net::Ipv4Addr;

    fn known_port_name(port: u16) -> Option<&'static str> {
        match port {
            80    => Some("HTTP"),
            443   => Some("HTTPS"),
            135   => Some("Windows RPC"),
            139   => Some("NetBIOS"),
            445   => Some("SMB File Sharing"),
            3389  => Some("Remote Desktop (RDP)"),
            5357  => Some("WS-Discovery"),
            5985  => Some("WinRM HTTP"),
            7680  => Some("Windows Update Delivery Optimization"),
            2179  => Some("Hyper-V VM Bus"),
            1900  => Some("UPnP / SSDP"),
            8883  => Some("MQTT / IoT"),
            1638  => Some("NordVPN Local Proxy"),
            53    => Some("DNS"),
            123   => Some("NTP Time Sync"),
            3306  => Some("MySQL"),
            5432  => Some("PostgreSQL"),
            6379  => Some("Redis"),
            27017 => Some("MongoDB"),
            8080  => Some("HTTP Alt"),
            8443  => Some("HTTPS Alt"),
            9091  => Some("Transmission Web UI"),
            51413 => Some("BitTorrent"),
            _     => None,
        }
    }

    fn build_service_map() -> HashMap<u32, String> {
        let mut map = HashMap::new();
        unsafe {
            let scm = match OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(h) => h,
                Err(_) => return map,
            };
            let mut bytes_needed: u32 = 0;
            let mut services_returned: u32 = 0;
            let mut resume_handle: u32 = 0;

            let _ = EnumServicesStatusExW(
                scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                None, &mut bytes_needed, &mut services_returned,
                Some(&mut resume_handle), None,
            );

            if bytes_needed == 0 { let _ = CloseServiceHandle(scm); return map; }

            let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
            services_returned = 0;
            resume_handle = 0;

            let result = EnumServicesStatusExW(
                scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                Some(&mut buf), &mut bytes_needed, &mut services_returned,
                Some(&mut resume_handle), None,
            );

            if result.is_ok() {
                let services = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    services_returned as usize,
                );
                for svc in services {
                    let pid = svc.ServiceStatusProcess.dwProcessId;
                    if pid == 0 { continue; }
                    let display_name = if !svc.lpDisplayName.is_null() {
                        let mut len = 0;
                        while *svc.lpDisplayName.0.add(len) != 0 { len += 1; }
                        let slice = std::slice::from_raw_parts(svc.lpDisplayName.0, len);
                        String::from_utf16_lossy(slice)
                    } else { continue; };

                    map.entry(pid)
                        .and_modify(|e: &mut String| {
                            if !e.contains(&*display_name) {
                                e.push_str(" + ");
                                e.push_str(&display_name);
                            }
                        })
                        .or_insert(display_name);
                }
            }
            let _ = CloseServiceHandle(scm);
        }
        map
    }

    fn state_name(state: u32) -> &'static str {
        match state {
            1  => "CLOSED",     2  => "LISTEN",
            3  => "SYN_SENT",   4  => "SYN_RCVD",
            5  => "ESTABLISHED",6  => "FIN_WAIT1",
            7  => "FIN_WAIT2",  8  => "CLOSE_WAIT",
            9  => "CLOSING",    10 => "LAST_ACK",
            11 => "TIME_WAIT",  12 => "DELETE_TCB",
            _  => "UNKNOWN",
        }
    }

    fn get_process_name(pid: u32, service_map: &HashMap<u32, String>) -> String {
        match pid {
            0 => return "System Idle Process".to_string(),
            4 => return "Windows Kernel (System)".to_string(),
            _ => {}
        }
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid,
            );
            if let Ok(h) = handle {
                let mut buf = [0u16; 260];
                let len = GetModuleBaseNameW(h, None, &mut buf);
                let _ = CloseHandle(h);
                if len > 0 {
                    return String::from_utf16_lossy(&buf[..len as usize]);
                }
            }
        }
        if let Some(svc_name) = service_map.get(&pid) {
            if svc_name.len() > 60 {
                return format!("{}...", &svc_name[..60]);
            }
            return svc_name.clone();
        }
        format!("System Process (PID:{})", pid)
    }

    pub fn get_tcp_connections(
        reader: &Option<maxminddb::Reader<Vec<u8>>>
    ) -> Vec<Connection> {
        let mut connections = Vec::new();
        let service_map = build_service_map();
        let mut buf_size: u32 = 0;

        unsafe {
            let _ = GetExtendedTcpTable(
                None, &mut buf_size, false,
                AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if buf_size == 0 { return connections; }

            let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
            let result = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _), &mut buf_size, false,
                AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if result != 0 { return connections; }

            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;
            let rows = std::slice::from_raw_parts(
                &table.table[0] as *const MIB_TCPROW_OWNER_PID,
                num_entries,
            );

            for row in rows {
                let local_ip    = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                let remote_ip   = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                let local_port  = u16::from_be(row.dwLocalPort as u16);
                let remote_port = u16::from_be(row.dwRemotePort as u16);
                let pid         = row.dwOwningPid;
                let state       = state_name(row.dwState);
                let mut process_name = get_process_name(pid, &service_map);

                if state == "LISTEN" {
                    if let Some(label) = known_port_name(local_port) {
                        process_name = format!("{} [{}]", process_name, label);
                    }
                }

                let remote_str = remote_ip.to_string();
                let (country_code, country_flag) = lookup_country(&remote_str, reader.as_ref());

                connections.push(Connection {
                    pid,
                    process_name,
                    local_addr: local_ip.to_string(),
                    local_port,
                    remote_addr: remote_str,
                    remote_port,
                    state: state.to_string(),
                    country_code,
                    country_flag,
                    threat_score: -1,
                    threat_reports: 0,
                });
            }
        }

        connections.sort_by(|a, b| a.process_name.cmp(&b.process_name));
        connections
    }
}

// ─── macOS Network ────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_net {
    use super::*;
    use std::process::Command;

    fn build_lsof_process_map(elevated: bool) -> std::collections::HashMap<(String, u16), (u32, String)> {
        let mut map = std::collections::HashMap::new();

        let output = if elevated {
            Command::new("sudo")
                .args(["-n", "lsof", "-i", "TCP", "-n", "-P", "-F", "cpn"])
                .output()
        } else {
            Command::new("lsof")
                .args(["-i", "TCP", "-n", "-P", "-F", "cpn"])
                .output()
        };

        let output = match output {
            Ok(o) => o,
            Err(_) => return map,
        };

        if !output.status.success() {
            return map;
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut current_pid = 0u32;
        let mut current_process = String::new();

        for line in text.lines() {
            if line.starts_with('p') {
                current_pid = line[1..].parse().unwrap_or(0);
            } else if line.starts_with('c') {
                current_process = line[1..].to_string();
            } else if line.starts_with('n') {
                let addr_str = &line[1..];
                let local_endpoint = addr_str.split("->").next().unwrap_or(addr_str);
                if let Some(last_colon) = local_endpoint.rfind(':') {
                    if let Ok(port) = local_endpoint[last_colon + 1..].parse::<u16>() {
                        if current_pid > 0 && !current_process.is_empty() {
                            let ip_raw = &local_endpoint[..last_colon];
                            let ip = if ip_raw.starts_with('[') && ip_raw.ends_with(']') {
                                ip_raw[1..ip_raw.len() - 1].to_string()
                            } else if ip_raw == "*" {
                                "0.0.0.0".to_string()
                            } else {
                                ip_raw.to_string()
                            };
                            map.insert((ip, port), (current_pid, current_process.clone()));
                        }
                    }
                }
            }
        }
        map
    }

    fn parse_addr(addr: &str) -> (String, u16) {
        if addr == "*.*" || addr == "*:*" {
            return ("0.0.0.0".to_string(), 0);
        }
        if let Some(colon_pos) = addr.rfind(':') {
            let port_str = &addr[colon_pos + 1..];
            let ip_str = &addr[..colon_pos];
            if let Ok(port) = port_str.parse::<u16>() {
                let ip = if ip_str == "*" { "0.0.0.0".to_string() } else { ip_str.to_string() };
                return (ip, port);
            }
        }
        if let Some(dot_pos) = addr.rfind('.') {
            let port_str = &addr[dot_pos + 1..];
            let ip_str = &addr[..dot_pos];
            if let Ok(port) = port_str.parse::<u16>() {
                let ip = if ip_str == "*" { "0.0.0.0".to_string() } else { ip_str.to_string() };
                return (ip, port);
            }
        }
        ("0.0.0.0".to_string(), 0)
    }

    fn state_from_str(s: &str) -> &'static str {
        match s.trim().to_uppercase().as_str() {
            "ESTABLISHED"              => "ESTABLISHED",
            "LISTEN"                   => "LISTEN",
            "TIME_WAIT"                => "TIME_WAIT",
            "CLOSE_WAIT"               => "CLOSE_WAIT",
            "SYN_SENT"                 => "SYN_SENT",
            "SYN_RCVD"                 => "SYN_RCVD",
            "FIN_WAIT_1" | "FIN_WAIT1" => "FIN_WAIT1",
            "FIN_WAIT_2" | "FIN_WAIT2" => "FIN_WAIT2",
            "LAST_ACK"                 => "LAST_ACK",
            "CLOSING"                  => "CLOSING",
            "CLOSED"                   => "CLOSED",
            "DELETE_TCB"               => "DELETE_TCB",
            _                          => "UNKNOWN",
        }
    }

    pub fn get_tcp_connections(
        reader: &Option<maxminddb::Reader<Vec<u8>>>
    ) -> Vec<Connection> {
        get_tcp_connections_internal(reader, false)
    }

    pub fn get_tcp_connections_elevated(
        reader: &Option<maxminddb::Reader<Vec<u8>>>
    ) -> Vec<Connection> {
        get_tcp_connections_internal(reader, true)
    }

    fn get_tcp_connections_internal(
        reader: &Option<maxminddb::Reader<Vec<u8>>>,
        elevated: bool,
    ) -> Vec<Connection> {
        let lsof_map = build_lsof_process_map(elevated);
        let mut connections = Vec::new();

        let output = match Command::new("netstat").args(["-anf", "inet"]).output() {
            Ok(o) => o,
            Err(e) => { eprintln!("netstat failed: {}", e); return connections; }
        };

        let text = String::from_utf8_lossy(&output.stdout);

        for line in text.lines() {
            if !line.starts_with("tcp") || line.starts_with("tcp6") { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 { continue; }

            let (local_addr, local_port)   = parse_addr(parts[3]);
            let (remote_addr, remote_port) = parse_addr(parts[4]);
            let state = state_from_str(if parts.len() >= 6 { parts[5] } else { "UNKNOWN" });

            let (pid, process_name) = lsof_map
                .get(&(local_addr.clone(), local_port))
                .cloned()
                .unwrap_or_else(|| (0, format!("Unknown (port {})", local_port)));

            let (country_code, country_flag) = lookup_country(&remote_addr, reader.as_ref());

            connections.push(Connection {
                pid,
                process_name,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state: state.to_string(),
                country_code,
                country_flag,
                threat_score: -1,
                threat_reports: 0,
            });
        }

        connections.sort_by(|a, b| a.process_name.cmp(&b.process_name));
        connections
    }
}

// ─── Tauri Commands ───────────────────────────────────────────────────────────

#[tauri::command]
#[allow(unreachable_code)]
fn get_connections() -> Vec<Connection> {
    let db_path = get_db_path();
    let reader  = maxminddb::Reader::open_readfile(&db_path).ok();
    if reader.is_none() {
        eprintln!("Warning: GeoIP database not found at {:?}", db_path);
    }
    #[cfg(windows)]
    { return windows_net::get_tcp_connections(&reader); }
    #[cfg(target_os = "macos")]
    { return macos_net::get_tcp_connections(&reader); }
    #[cfg(not(any(windows, target_os = "macos")))]
    { vec![] }
}

#[tauri::command]
#[allow(unreachable_code)]
fn get_connections_elevated() -> Result<Vec<Connection>, String> {
    let db_path = get_db_path();
    let reader  = maxminddb::Reader::open_readfile(&db_path).ok();
    #[cfg(target_os = "macos")]
    { return Ok(macos_net::get_tcp_connections_elevated(&reader)); }
    #[cfg(not(target_os = "macos"))]
    { return Err("Elevated connections only supported on macOS".to_string()); }
}

#[tauri::command]
async fn check_threat(ip: String) -> Result<ThreatInfo, String> {
    let config = load_config();
    let key = match config.abuseipdb_key {
        Some(k) if !k.is_empty() && k != "YOUR_ABUSEIPDB_KEY_HERE" => k,
        _ => return Err("No API key configured".to_string()),
    };
    match check_abuse_ip(&ip, &key).await {
        Some(info) => Ok(info),
        None => Ok(ThreatInfo { score: 0, reports: 0 }),
    }
}

#[tauri::command]
#[allow(unreachable_code)]
fn block_ip(ip: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let rule_name = format!("Vigilance_Block_{}", ip);
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out", "action=block",
                &format!("remoteip={}", ip),
                "enable=yes", "profile=any",
            ])
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;
        if output.status.success() {
            return Ok(format!("Blocked {}", ip));
        } else {
            return Err(format!("netsh error: {}", String::from_utf8_lossy(&output.stderr)));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Save to local rules file for UI persistence
        let rules_path = get_rules_path();
        let mut rules: Vec<String> = if rules_path.exists() {
            let content = std::fs::read_to_string(&rules_path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Vec::new()
        };
        if !rules.contains(&ip) {
            rules.push(ip.clone());
            let _ = std::fs::write(&rules_path,
                serde_json::to_string(&rules).unwrap_or_default());
        }

        // Reload the full rule set so existing blocks are not overwritten
        if apply_pf_rules(&rules) {
            return Ok(format!("Blocked {} via pf firewall", ip));
        } else {
            // pf rule failed (likely needs sudo setup) but rule is saved locally
            return Ok(format!("Block saved for {} (pf rule requires sudo privileges)", ip));
        }
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    Err("Blocking not supported on this platform".to_string())
}

#[tauri::command]
#[allow(unreachable_code)]
fn unblock_ip(ip: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let rule_name = format!("Vigilance_Block_{}", ip);
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={}", rule_name),
            ])
            .output()
            .map_err(|e| format!("Failed to run netsh: {}", e))?;
        if output.status.success() {
            return Ok(format!("Unblocked {}", ip));
        } else {
            return Err(format!("netsh error: {}", String::from_utf8_lossy(&output.stderr)));
        }
    }

   #[cfg(target_os = "macos")]
{
    let rules_path = get_rules_path();
    let mut rules: Vec<String> = Vec::new(); // <-- declare rules in outer scope

    if rules_path.exists() {
        let content = std::fs::read_to_string(&rules_path).unwrap_or_default();
        rules = serde_json::from_str(&content).unwrap_or_default();
        rules.retain(|r| r != &ip);

        let _ = std::fs::write(
            &rules_path,
            serde_json::to_string(&rules).unwrap_or_default(),
        );
    }

    // Now rules is always in scope
    apply_pf_rules(&rules);

    return Ok(format!("Unblocked {}", ip));
}


    #[cfg(not(any(windows, target_os = "macos")))]
    Err("Unblocking not supported on this platform".to_string())
}

#[tauri::command]
#[allow(unreachable_code)]
fn clear_all_blocks() -> Result<String, String> {
    #[cfg(windows)]
    {
        let list_output = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"])
            .output()
            .map_err(|e| e.to_string())?;
        let rules_text = String::from_utf8_lossy(&list_output.stdout);
        let mut removed = 0u32;
        for line in rules_text.lines() {
            if line.contains("Vigilance_Block_") {
                if let Some(ip) = line.split("Vigilance_Block_")
                    .nth(1).map(|s| s.trim().to_string()) {
                    let _ = std::process::Command::new("netsh")
                        .args(["advfirewall", "firewall", "delete", "rule",
                            &format!("name=Vigilance_Block_{}", ip)])
                        .output();
                    removed += 1;
                }
            }
        }
        return Ok(format!("Removed {} Vigilance firewall rules", removed));
    }

    #[cfg(target_os = "macos")]
    {
        // Clear pf anchor
        let _ = std::process::Command::new("sudo")
            .args(["-n", "pfctl", "-a", "vigilance", "-F", "rules"])
            .output();
        // Clear local rules file
        let rules_path = get_rules_path();
        let _ = std::fs::write(&rules_path, "[]");
        return Ok("Cleared all Vigilance firewall rules".to_string());
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    Ok("No rules to clear".to_string())
}

#[tauri::command]
#[allow(unreachable_code)]
fn get_blocked_ips() -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        let list_output = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", "dir=out"])
            .output()
            .map_err(|e| e.to_string())?;
        let rules_text = String::from_utf8_lossy(&list_output.stdout);
        let mut ips = Vec::new();
        for line in rules_text.lines() {
            if line.contains("Vigilance_Block_") {
                if let Some(ip) = line.split("Vigilance_Block_")
                    .nth(1).map(|s| s.trim().to_string()) {
                    if !ips.contains(&ip) { ips.push(ip); }
                }
            }
        }
        return Ok(ips);
    }

    #[cfg(target_os = "macos")]
    {
        let rules_path = get_rules_path();
        if rules_path.exists() {
            let content = std::fs::read_to_string(&rules_path)
                .map_err(|e| e.to_string())?;
            let ips: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
            return Ok(ips);
        }
        return Ok(vec![]);
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    Ok(vec![])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_connections,
            get_connections_elevated,
            check_threat,
            block_ip,
            unblock_ip,
            get_blocked_ips,
            clear_all_blocks,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}