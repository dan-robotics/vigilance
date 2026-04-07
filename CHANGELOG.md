# Vigilance — Changelog

All notable changes to this project are documented in this file.

Format: `[Version] — Date — Platform — Category: Description`

---

## [0.1.1] — April 2026

### macOS — New Platform Support
- Added full macOS network capture engine using `netstat` + `lsof`
- Process names resolved via `lsof -F cpn` — shows real app names (Spotify, Chrome, etc.)
- Elevation support — "Refresh with Elevation" button uses `sudo lsof` to resolve system process names
- Cross-platform blocking — macOS uses `pfctl` pf firewall anchor instead of Windows `netsh`
- Blocked IPs persist across restarts via `~/.vigilance_rules.json` on macOS
- `get_blocked_ips` now reads from local JSON file on macOS instead of querying `netsh`
- `clear_all_blocks` now clears pf anchor and local rules file on macOS

### macOS — Bug Fixes
- Fixed GeoIP database not found in built `.app` bundle — corrected `Contents/Resources/resources/` path
- Fixed `load_config` not finding `config.json` in macOS bundle — added bundle path resolution
- Fixed `get_db_path` only looking next to executable — now correctly navigates macOS `.app` bundle structure
- Fixed `parse_addr` wildcard `*.*` mapping to `127.0.0.1` instead of `0.0.0.0` — caused all listeners to appear as loopback

### UI — Filter Bug Fixes
- Fixed state filter buttons having no effect — state filters were wrapped in `if (!isLoopback)` block which excluded all macOS connections since most use `127.0.0.1`
- Fixed `0/28 SHOWN` counter showing zero while connections still visible — caused by duplicate React row keys
- Fixed duplicate row keys — key now includes `remote_addr`, `remote_port` and `state` to ensure uniqueness
- Fixed `filtered.map()` rendering stale rows when `filtered.length === 0` — added `filtered.length > 0` guard
- Fixed loopback definition incorrectly including `0.0.0.0` — wildcard listeners are not loopback connections

### UI — Improvements
- Added `isLoopback` detection that correctly identifies only `127.x ↔ 127.x` connections as loopback
- State filters (Established, Listen, Time Wait etc.) now apply to ALL connections including loopback
- Loopback toggle correctly hides only loopback connections without affecting state filter behaviour
- Added `useRef` for async callbacks to prevent stale closure issues with threat intel checking
- Improved `fetchConnections` — skips fetch when `elevatedResultsAvailable` is true to preserve elevated data
- Added React key uniqueness fix — prevents ghost rows when filter changes rapidly

### Rust — Code Quality
- Added `use std::collections::HashMap` inside `windows_net` module where it is actually needed
- Removed unused `HashMap` and `Ipv4Addr` imports from top-level scope
- Added `#[allow(unreachable_code)]` to all cross-platform Tauri commands to silence warnings
- Added `apply_pf_rules()` helper function for atomic pf rule reloads on macOS
- Fixed `get_rules_path()` to store rules in `~/.vigilance_rules.json` (home directory, always writable)

### Configuration
- Updated `tauri.conf.json` bundle resources — files now placed at root of `Resources/` not in subfolder
- Updated `tauri.conf.json` window title to `Vigilance — Network Monitor`
- Updated `tauri.conf.json` window size to 1400x800
- Added `identifier: com.danrobotics.vigilance` for proper macOS bundle identification
- Version bumped to `0.1.1` in `package.json`, `Cargo.toml`, and `tauri.conf.json`
- Added author information to `Cargo.toml`

### GitHub
- Fixed git repository corruption — re-initialized from remote
- Fixed GitHub Actions macOS builds charging against free tier — Actions disabled, builds now done locally
- Added `CHANGELOG.md` to track all changes going forward

---

## [0.1.0] — March 2026 — Initial Release

### Windows — Features
- Live TCP connection monitor via `GetExtendedTcpTable` Windows API
- Real process name resolution using `OpenProcess` + `GetModuleBaseNameW`
- Windows Service name resolution via Service Control Manager (`EnumServicesStatusExW`)
- Known port name annotations (HTTP, HTTPS, RPC, SMB, NordVPN, etc.)
- One-click blocking via `netsh advfirewall firewall add rule`
- One-click unblocking — instant rule removal
- Clear All Blocks button — removes all `Vigilance_Block_*` firewall rules
- Persistent blocked IPs — rules survive app restart, loaded on startup via `get_blocked_ips`

### All Platforms — Features
- GeoIP country lookup using MaxMind GeoLite2 local database (offline, no API calls)
- Cloudflare Anycast IP detection — shows `CF` badge instead of `??` for Cloudflare IPs
- Threat intelligence via AbuseIPDB API — 0-100% threat score per IP
- Config file system — API keys stored in `config.json`, never hardcoded
- Sortable columns — click any column header to sort ascending/descending
- Filter bar — search by process name, IP, port, state, or country code
- State toggle buttons — hide/show Loopback, Listeners, Established, Time Wait, Close Wait, SYN, Other
- Threats Only toggle — show only IPs with threat score ≥ 20%
- Pause/Resume live updates
- Reset Filters button
- Real-time stats header — Established, Listening, Blocked, Threats counts
- Country badges — LAN (green), CF (orange), country code (blue), unknown (grey)
- Threat score badges — 🔴 High (≥50%), 🟡 Medium (≥20%), ✅ Clean (0%)
- Row highlighting — red background for high threat, amber for medium threat

---

## Planned — [0.2.0]

- Persistent rules database (SQLite) — blocked IPs survive reinstall
- Export connection log to CSV
- Raspberry Pi 4 ARM64 headless daemon with web UI
- IPv6 connection support
- macOS blocking without sudo requirement (proper Network Extension entitlement)
- Windows x64 installer code signing
- Screenshot and app icon design

---

*Built from scratch. No code borrowed from LittleSnitch, GlassWire, or any other commercial product.*
*License: GNU General Public License v3.0*
