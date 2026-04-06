# 🐾 Vigilance — Network Firewall Monitor

> Free, open-source, cross-platform network firewall monitor for Windows and macOS.

![License](https://img.shields.io/badge/license-GPL--v3-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS-lightgrey)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![UI](https://img.shields.io/badge/UI-Tauri%20%2B%20React-cyan)

---

## What is Vigilance?

Vigilance gives you **full visibility into every network connection on your machine** — which process made it, where it is going, what country it is in, and whether the remote IP has been flagged as malicious.

It provides capabilities previously only available in expensive commercial tools like LittleSnitch ($70) or GlassWire Pro ($40+/year) — **completely free for home users**.

---

## Screenshots

> Real-time connection table with process names, GeoIP, threat scores and one-click blocking.

---

## Features

| Feature | Description |
|---|---|
| 🔴 **Live Connection Table** | Real-time active TCP connections on your machine |
| 🔍 **Process Identification** | Exact process name and PID for every connection |
| 🌍 **Geo-IP Enrichment** | Country lookup via MaxMind GeoLite2 (offline, no API calls) |
| ☁ **Cloudflare Detection** | Automatically identifies Cloudflare Anycast IPs |
| 🛡 **Threat Intelligence** | AbuseIPDB integration — flags malicious IPs with a 0-100% score |
| ⛔ **One-Click Blocking** | Instantly block any IP via Windows Firewall (netsh advfirewall) |
| ✅ **One-Click Unblock** | Instantly revert any block — no manual firewall editing |
| 🔎 **Advanced Filtering** | Filter by process, IP, port, state, country, or threat score |
| 📊 **Sortable Columns** | Sort by any column including threat score |
| 🏠 **Loopback Toggle** | Hide/show local loopback traffic with one click |
| ⏸ **Pause / Resume** | Freeze the live table to inspect connections without them jumping |
| 🟡 **Threats Only Mode** | Isolate only flagged IPs instantly |

---

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| Windows 10/11 x64 | ✅ Full support | Blocking via Windows Firewall (netsh) |
| macOS Intel | 🔜 Planned | Built via GitHub Actions | - Not working currently
| macOS Apple Silicon | 🔜 Planned | Universal binary | - Not working currently
| Raspberry Pi 4 ARM64 | 🔜 Planned | Headless web UI daemon |
| Linux x64 | 🔜 Planned | |

---

## Prerequisites

To build locally you need:

- [Node.js](https://nodejs.org/) LTS
- [Rust](https://rustup.rs/) latest stable
- **Windows only**: Visual Studio Build Tools 2022 with the **Desktop development with C++** workload
- **macOS only**: Xcode Command Line Tools (`xcode-select --install`)

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/dan-robotics/vigilance
cd vigilance
```

### 2. Install frontend dependencies

```bash
npm install
```

### 3. Download GeoIP database (free)

- Register at [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Download **GeoLite2-Country** (Binary `.mmdb` format)
- Place the file at:

```
src-tauri/resources/GeoLite2-Country.mmdb
```

### 4. Configure API keys (optional)

Copy the example config and add your keys:

```bash
cp src-tauri/resources/config.example.json src-tauri/resources/config.json
```

Edit `config.json`:

```json
{
  "abuseipdb_key": "YOUR_ABUSEIPDB_KEY_HERE",
  "abuseipdb_enabled": true,
  "cache_hours": 24,
  "threat_score_red": 50,
  "threat_score_yellow": 20
}
```

> Get a free AbuseIPDB API key at [abuseipdb.com](https://www.abuseipdb.com/register) — 1,000 free checks/day.
> The app works without a key — threat intel column will show `—` for all IPs.

### 5. Run in development mode

```bash
npm run tauri dev
```

> **Windows**: Run VS Code or your terminal as Administrator for firewall blocking to work.

---

## Building for Production

```bash
npm run tauri build
```

Output binaries are in:

```
src-tauri/target/release/bundle/
  ├── msi/          ← Windows installer
  ├── nsis/         ← Windows executable
  └── macos/        ← macOS .app bundle
```

---

## Automated Builds (GitHub Actions)

Every push to `main` automatically builds:

- ✅ Windows x64 `.msi` installer
- ✅ macOS Universal Binary `.dmg` (Intel + Apple Silicon)

Releases are published as **draft releases** on the [Releases page](../../releases).

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                VIGILANCE                        │
├─────────────────────────────────────────────────┤
│  [React + TypeScript UI]                        │
│       ↕ Tauri IPC (JSON)                        │
│  [Rust Backend Engine]                          │
│       ├── Windows: GetExtendedTcpTable API      │
│       ├── Process name lookup (SCM + OpenProc.) │
│       ├── GeoIP lookup (MaxMind local DB)       │
│       ├── Threat Intel (AbuseIPDB async)        │
│       ├── Firewall rules (netsh advfirewall)    │
│       └── Config loader (config.json)           │
└─────────────────────────────────────────────────┘
```

| Layer | Technology |
|---|---|
| Backend engine | Rust 1.75+ |
| App framework | Tauri 2.x |
| Frontend | React 18 + TypeScript |
| Styling | CSS |
| Packet data | Windows: `GetExtendedTcpTable` API |
| GeoIP | MaxMind GeoLite2 (local, offline) |
| Threat Intel | AbuseIPDB REST API |
| Database | SQLite (planned for persistent rules) |
| CI/CD | GitHub Actions |

---

## Security & Privacy

- **All data stays local** — no telemetry, no cloud sync, no account required
- **API keys stored locally** in `config.json` — never hardcoded, never pushed to GitHub
- **GeoIP lookups are offline** — the MaxMind database runs entirely on your machine
- **AbuseIPDB calls are one-way** — only the remote IP is sent, nothing about you

---

## Business Model

| Tier | Price | Who |
|---|---|---|
| Home | **Free forever** | Personal use, home networks |
| Business | Coming soon | Multi-device, SIEM integration, compliance reports |

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large pull request.

```bash
# Fork the repo, create a branch, make your changes, open a PR
git checkout -b feature/your-feature-name
```

---

## License

**GNU General Public License v3.0** — free to use, modify, and distribute.
See [LICENSE](LICENSE) for full terms.

---

## Acknowledgements

- [MaxMind GeoLite2](https://dev.maxmind.com/) — free GeoIP database
- [AbuseIPDB](https://www.abuseipdb.com/) — free threat intelligence API
- [Tauri](https://tauri.app/) — lightweight cross-platform app framework
- [Rust](https://www.rust-lang.org/) — systems programming language

---

*Built from scratch. No code borrowed from LittleSnitch, GlassWire, or any other commercial product.*
