# Zaslon Browser

Zaslon is an open-source, privacy-first desktop web browser built on Electron and hardened Chromium. It is designed for users who want granular control over their network traffic, identity, and data footprint without relying on third-party cloud synchronization.

The browser integrates container-level isolation, built-in Deep Packet Inspection (DPI) circumvention, managed Tor routing with per-domain circuit isolation, DNS-over-HTTPS (DoH), and an offline meta-search engine.

---

## Key Concepts and Architecture

### 1. Tab Containers and Session Isolation

Tabs in Zaslon do not share a single global browser state. Every tab belongs to a container:

- **Personal (`Kişisel`):** Standard container with persistent cookies and local storage.
- **Banking / Work (`Banka/İş`):** Isolated session partition for sensitive accounts.
- **Social (`Sosyal`):** Sandboxed environment preventing social tracking pixels from following you across the web.
- **Shopping (`Alışveriş`):** Dedicated partition isolating e-commerce tracking and dynamic pricing trackers.
- **Ephemeral (`Geçici`):** RAM-only container. All storage, cookies, and cache are completely cleared when the tab closes.
- **Tor Armored (`Tor Zırhlı`):** Strict RAM-only partition routed exclusively through the local Tor daemon. 

Under the hood, each container uses a separate Electron `partition`. In Tor containers, Zaslon isolates Tor circuits per first-party domain so that browsing on one site cannot be correlated with activity on another.

### 2. Network Security and Anti-Censorship

Zaslon includes a multi-layered network stack designed to bypass censorship and prevent DNS and IP leaks:

- **DNS-over-HTTPS (DoH):** Direct RFC 8484 wireformat resolver supporting Quad9, Cloudflare, Mullvad, and custom endpoints. In Strict mode, Zaslon fails closed: if the configured DoH provider cannot resolve a domain, the browser will never fall back to plaintext ISP DNS.
- **DPI Circumvention:** The built-in DPI engine splits TLS `ClientHello` packets across TCP segments or TLS record boundaries (`sni-frag` and `aggr-frag`). This prevents middlebox firewalls from inspecting Server Name Indication (SNI) hostnames without breaking the handshake. External tools like SpoofDPI and GoodbyeDPI are also supported.
- **Managed Tor Routing:** Zaslon can download, verify, configure, and supervise a local Tor process. It supports pluggable transports (obfs4 bridges), automatically recognizes `Onion-Location` headers, and enforces fail-closed routing for `.onion` domains and Tor-armored tabs.
- **Fail-Closed Protection:** If a connection is set to require Tor and the Tor daemon is offline or disconnected, Zaslon halts the request entirely rather than leaking the query through your real IP address.

### 3. Anti-Fingerprinting and Identity Profiles

To reduce browser fingerprinting, Zaslon applies both Chromium command-line hardening and in-page API spoofing:

- **Identity Modes:** Toggle between a Tor Browser profile (Firefox ESR User-Agent, empty vendor, hidden Client Hints) and a uniform Chromium profile.
- **Canvas and Audio Protection:** Randomizes `readPixels` noise and `AnalyserNode` frequency data per domain.
- **Timing and Animation:** Enforces a 60 Hz `requestAnimationFrame` ceiling and rounds high-resolution performance timers.
- **Letterboxing:** In high-security modes, letterboxing adds margins around the viewport to prevent screen resolution fingerprinting.
- **Security Slider:** Offers Standard, Safer (disables JIT on eligible surfaces), and Safest (disables JavaScript and non-essential media features).

### 4. Zaslon Meta-Search (`zaslon://search`)

Zaslon includes a cookieless, serverless meta-search aggregator:

- Queries multiple search providers in parallel (DuckDuckGo, Brave Search, Wikipedia, and optional SearXNG/Yahoo) directly from your client.
- Sends zero tracking headers, user cookies, or referrer data.
- Strips redirect wrappers (`uddg`, Google/Bing redirect URLs) and tracking parameters locally.
- In Tor containers, searches route through Tor SOCKS5; in clearnet containers, searches use a dedicated ephemeral partition (`zaslon-ephemeral-metasearch`).
- If Tor is required but offline, the user can either wait for Tor to bootstrap or switch to an isolated clearnet session with one click.

### 5. Encrypted Vault and Local Storage

All sensitive user data (saved credentials, bookmarks, reading history, notes) is stored in a local SQLite database (`zaslon-vault.db`):

- **Encryption:** Encrypted at rest using AES-256-GCM.
- **Key Management:** Secured by default through the operating system's credential store (Windows DPAPI / Electron `safeStorage`), with optional Master Password protection.
- **Panic Wipe (`Alt+X`):** Immediately destroys active views, clears memory, truncates SQLite write-ahead logs (WAL) to zero bytes, and shreds temporary caches.

### 6. Cloudless LAN Peer-to-Peer Sync

Zaslon does not use cloud accounts or centralized servers to sync data:

- Discovers companion devices (such as the Zaslon Android app) on your local Wi-Fi network via UDP broadcasts on port `49441`.
- Sync requests run over an authenticated local HTTP endpoint on port `49440`.
- Data payloads are encrypted end-to-end with AES-256-GCM using keys derived from a 6-digit user-confirmed PIN via `scrypt`.
- Allows syncing tabs, bookmarks, and notes directly between your phone and laptop without leaving your local network.

### 7. Media and Usability Utilities

- **SponsorBlock:** Automatically skips sponsor segments, intros, and self-promotion on YouTube videos using 4-character SHA-256 k-anonymity so video IDs are never leaked to external servers.
- **Media Controls:** Global video playback speed control (0.25x to 4.0x) and forced Picture-in-Picture.
- **Local Stream Sniffer & yt-dlp:** Detects streaming audio/video formats and provides download options via yt-dlp without exposing user session cookies.
- **SingleFile Integration:** Save complete, self-contained HTML archives of web pages for offline reading.
- **Reader Mode & Offline RSS:** Distraction-free article view and an offline-first RSS reader that blocks third-party tracking pixels.
- **Local Translation:** Translates pages using offline N-gram detection and local translation engines (LibreTranslate or local Ollama instances like Qwen) with no cloud dependency.

---

## Project Structure

```
zaslon-browser/
├── main.js                  # Electron main process (IPC, session partitioning, lifecycle)
├── ui.html                  # Core browser UI shell (tabs, panels, settings, meta-search)
├── page-preload.js          # Sandboxed WebContents preload (DOM hardening, protections)
├── src/
│   ├── i18n/                # Localization (tr, en, ru, de)
│   ├── network/             # DoH manager, DPI fragmentation engine, Tor supervisor
│   ├── privacy/             # Adblock engine, Chromium flags, URL cleaner
│   ├── search/              # Cookieless meta-search orchestrator and engine scrapers
│   ├── storage/             # SQLite encrypted vault, LAN sync, updater
│   └── translation/         # Offline language detection and local translation pipeline
├── test/                    # Node.js built-in test runner test suite (50+ tests)
└── installer/               # Packaging scripts and deployment assets
```

---

## Getting Started

### Direct Download (Windows)

Download the latest Windows installer (`Zaslon-Setup.exe`) or portable executable (`Zaslon-Portable.exe`) from **[GitHub Releases](https://github.com/BeybarsSamuel/zaslon-browser/releases/latest)**:

- **`Zaslon-Setup.exe`** — Standard Windows setup wizard (supports per-user or system-wide installation, Start Menu & Desktop shortcuts, Windows Search registration, and uninstaller).
- **`Zaslon-Portable.exe`** — Single-file portable build requiring no installation.
- **`SHA256SUMS.txt`** — SHA-256 checksums for verifying binary integrity.

### Building from Source

#### Prerequisites

- Node.js 18.x, 20.x, or 22.x
- npm 9.x or higher
- Git

#### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/BeybarsSamuel/zaslon-browser.git
cd zaslon-browser
npm install
```

### Running in Development

Start the browser:

```bash
npm start
```

### Running the Test Suite

Zaslon uses the Node.js native test runner (`node --test`). All tests are completely offline and do not make external network requests:

```bash
npm test
```

### Building Distributables

To package the desktop application for Windows:

```bash
npm run build:win
```

Packaged binaries and installer executables will be output to the `dist/` directory.

---

## Security and Privacy Principles

1. **No Outbound Telemetry:** Zaslon never pings home servers, collects crash analytics, or tracks feature usage.
2. **Explicit Fallbacks:** When a privacy feature fails (e.g. strict DoH or Tor requirement), Zaslon fails closed by default. The browser will never silently degrade to an insecure path without user consent.
3. **Local First:** All translations, vault storage, ad blocking decisions, and LAN synchronization operate entirely on your own hardware.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
