<h1>Vigilance — Network Firewall Monitor</h1>

<p>Vigilance is a free, open-source, cross-platform network firewall monitor. It provides real-time connection visibility, threat intelligence enrichment, and on-demand blocking capabilities.</p>

<p>Built with Rust for the backend packet engine, and Tauri + React + TypeScript for the frontend UI.</p>

<h2>Core Features</h2>

<ul>
  <li><strong>Live Connection Table</strong>: View real-time active network connections on your machine.</li>
  <li><strong>Process Identification</strong>: See exactly which application (PID / process name) is making the connection.</li>
  <li><strong>Geo-IP Enrichment</strong>: Automatically resolve remote IP addresses to their country of origin using MaxMind GeoLite2.</li>
  <li><strong>Threat Intelligence</strong>: Integrates with AbuseIPDB to flag known malicious IPs and assign a threat score from 0 to 100%.</li>
  <li><strong>One-Click Blocking</strong>: Instantly sever and block connections using native firewall integration, including Windows Defender Firewall / netsh.</li>
  <li><strong>Advanced Filtering</strong>: Filter traffic by state (ESTABLISHED, LISTEN, etc.), hide local/loopback traffic, or isolate flagged threats.</li>
</ul>

<h2>Prerequisites</h2>

<p>To compile and build this project locally, you need:</p>

<ul>
  <li><a href="https://nodejs.org/">Node.js</a> (LTS)</li>
  <li><a href="https://rustup.rs/">Rust</a> (latest stable)</li>
  <li>Visual Studio Build Tools with the C++ workload installed (Windows only)</li>
</ul>

<h2>Installation &amp; Development Setup</h2>

<h3>Clone the repository</h3>

<pre><code>git clone https://github.com/dan-robotics/vigilance
cd vigilance
</code></pre>

<h3>Install frontend dependencies</h3>

<pre><code>npm install
</code></pre>

<h3>Configure the application</h3>

<ol>
  <li>Navigate to the <code>resources/</code> folder.</li>
  <li>Rename or copy <code>config.example.json</code> to <code>config.json</code>.</li>
  <li>Open <code>config.json</code> and insert your API key:</li>
</ol>

<pre><code>{
  "abuseipdb_key": "YOUR_ABUSEIPDB_KEY_HERE",
  "abuseipdb_enabled": true,
  "cache_hours": 24,
  "threat_score_red": 50,
  "threat_score_yellow": 20
}
</code></pre>

<h3>Run in development mode</h3>

<pre><code>npm run tauri dev
</code></pre>

<h2>Building for Production</h2>

<p>To compile the standalone executables and installers, run:</p>

<pre><code>npm run tauri build
</code></pre>

<p>The compiled binaries will be located in:</p>

<pre><code>/src-tauri/target/release/bundle/
</code></pre>

<h2>Architecture Overview</h2>

<ul>
  <li><strong>Frontend</strong>: React + TypeScript, with styling via standard CSS.</li>
  <li><strong>Backend</strong>: Rust. Handles system-level queries (<code>netstat</code>), firewall commands (<code>netsh</code>), and asynchronous external API calls.</li>
  <li><strong>IPC</strong>: Tauri's inter-process communication bridge passes JSON objects between Rust and React.</li>
</ul>

<h2>License</h2>

<p>GNU GPL v3. Open-source and free for personal use.</p>
