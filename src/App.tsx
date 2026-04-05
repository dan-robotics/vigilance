import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

interface Connection {
  pid: number;
  process_name: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state: string;
  country_code: string;
  country_flag: string;
  threat_score: number;
  threat_reports: number;
}

type SortField = "process_name" | "local_addr" | "remote_addr" | "state" | "pid" | "country_code" | "threat_score";
type SortDir = "asc" | "desc";

function stateColor(state: string): string {
  switch (state) {
    case "ESTABLISHED": return "#00ff88";
    case "LISTEN":      return "#4fc3f7";
    case "TIME_WAIT":   return "#ffa726";
    case "CLOSE_WAIT":  return "#ef5350";
    case "CLOSED":      return "#666";
    default:            return "#aaa";
  }
}

function SortIcon({ field, current, dir }: { field: SortField, current: SortField, dir: SortDir }) {
  if (field !== current) return <span style={{ color: "#333", marginLeft: 4 }}>⇅</span>;
  return <span style={{ color: "#58a6ff", marginLeft: 4 }}>{dir === "asc" ? "↑" : "↓"}</span>;
}

export default function App() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [filter, setFilter] = useState("");
  const [lastUpdate, setLastUpdate] = useState("");
  const [blocked, setBlocked] = useState<Set<string>>(new Set());
  const [hideLoopback, setHideLoopback] = useState(false);
  const [hideListen, setHideListen] = useState(false);
  const [hideEstablished, setHideEstablished] = useState(false);
  const [hideTimeWait, setHideTimeWait] = useState(false);
  const [hideCloseWait, setHideCloseWait] = useState(false);
  const [hideSyn, setHideSyn] = useState(false);
  const [hideOther, setHideOther] = useState(false);
  const [sortField, setSortField] = useState<SortField>("process_name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [paused, setPaused] = useState(false);
  const [showThreatsOnly, setShowThreatsOnly] = useState(false);

  // Threat intel state
  const [threatScores, setThreatScores] = useState<Map<string, number>>(new Map());
  const [checkingThreat, setCheckingThreat] = useState<Set<string>>(new Set());

  // Run once on app startup to load existing firewall rules
  useEffect(() => {
    invoke<string[]>("get_blocked_ips")
      .then((ips) => {
        console.log("Loaded blocked IPs from firewall:", ips);
        setBlocked(prev => new Set([...prev, ...ips]));
      })
      .catch((err) => console.error("Failed to load blocked IPs:", err));
  }, []);

  async function checkThreat(ip: string) {
    // Skip private / special IPs
    if (!ip || ip === "0.0.0.0"
      || ip.startsWith("127.")
      || ip.startsWith("192.168.")
      || ip.startsWith("10.")
      || ip.startsWith("100.")
      || ip.startsWith("172.")) return;

    // Skip if already checked or currently checking
    if (threatScores.has(ip) || checkingThreat.has(ip)) return;

    setCheckingThreat(prev => new Set(prev).add(ip));
    try {
      const result = await invoke<{ score: number; reports: number }>(
        "check_threat", { ip }
      );
      setThreatScores(prev => new Map(prev).set(ip, result.score));
    } catch {
      // No API key or network error — silent fail, show nothing
    } finally {
      setCheckingThreat(prev => {
        const next = new Set(prev);
        next.delete(ip);
        return next;
      });
    }
  }

  const fetchConnections = useCallback(async () => {
    if (paused) return;
    try {
      const data = await invoke<Connection[]>("get_connections");
      setConnections(data);
      setLastUpdate(new Date().toLocaleTimeString());

      // Auto-check threat intel for unique external established IPs
      const uniqueIps = [...new Set(
        data
          .filter(c =>
            c.state === "ESTABLISHED" &&
            c.remote_addr !== "0.0.0.0" &&
            !c.remote_addr.startsWith("127.") &&
            !c.remote_addr.startsWith("192.168.") &&
            !c.remote_addr.startsWith("10.") &&
            !c.remote_addr.startsWith("100.")
          )
          .map(c => c.remote_addr)
      )];
      uniqueIps.forEach(ip => checkThreat(ip));
    } catch (e) {
      console.error(e);
    }
  }, [paused]);

  useEffect(() => {
    fetchConnections();
    const interval = setInterval(fetchConnections, 2000);
    return () => clearInterval(interval);
  }, [fetchConnections]);

  function handleSort(field: SortField) {
    if (field === sortField) {
      setSortDir(d => d === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  async function blockConnection(remote_addr: string) {
    try {
      await invoke("block_ip", { ip: remote_addr });
      setBlocked(prev => new Set(prev).add(remote_addr));
    } catch (e) {
      alert(`Failed to block ${remote_addr}: ${e}`);
    }
  }

  async function unblockConnection(remote_addr: string) {
    try {
      await invoke("unblock_ip", { ip: remote_addr });
      setBlocked(prev => {
        const next = new Set(prev);
        next.delete(remote_addr);
        return next;
      });
    } catch (e) {
      alert(`Failed to unblock ${remote_addr}: ${e}`);
    }
  }

  async function clearAllBlocks() {
    try {
      const result = await invoke<string>("clear_all_blocks");
      setBlocked(new Set());
      alert(result);
    } catch (e) {
      alert(`Failed to clear rules: ${e}`);
    }
  }

  // Filter
  let filtered = connections.filter(c => {
    // 1. Process Button Filters FIRST
    const isLoopback = c.remote_addr === "127.0.0.1" || c.local_addr === "127.0.0.1";
    if (hideLoopback && isLoopback) return false;
    
    if (!isLoopback || hideLoopback) {
      if (hideListen && c.state === "LISTEN") return false;
      if (hideEstablished && c.state === "ESTABLISHED") return false;
      if (hideTimeWait && c.state === "TIME_WAIT") return false;
      if (hideCloseWait && c.state === "CLOSE_WAIT") return false;
      if (hideSyn && (c.state === "SYN_SENT" || c.state === "SYN_RCVD")) return false;
      if (hideOther && (
        c.state === "FIN_WAIT1" || c.state === "FIN_WAIT2" ||
        c.state === "CLOSING"   || c.state === "LAST_ACK"  ||
        c.state === "CLOSED"    || c.state === "DELETE_TCB" ||
        c.state === "UNKNOWN"
      )) return false;
    }

    // 2. Process Threat Filter
    if (showThreatsOnly) {
      const score = threatScores.get(c.remote_addr) ?? 0;
      if (score < 20) return false;
    }

    // 3. Process Text Filter LAST
    if (filter === "") return true;
    
    return (
      c.process_name.toLowerCase().includes(filter.toLowerCase()) ||
      c.remote_addr.includes(filter) ||
      c.local_addr.includes(filter) ||
      String(c.remote_port).includes(filter) ||
      String(c.local_port).includes(filter) ||
      c.state.toLowerCase().includes(filter.toLowerCase()) ||
      c.country_code.toLowerCase().includes(filter.toLowerCase())
    );
  });

  // Sort
  filtered = [...filtered].sort((a, b) => {
    // Special case — sort by live threat score from Map
    if (sortField === "threat_score") {
      const sa = threatScores.get(a.remote_addr) ?? -1;
      const sb = threatScores.get(b.remote_addr) ?? -1;
      return sortDir === "asc" ? sa - sb : sb - sa;
    }
    let av = a[sortField];
    let bv = b[sortField];
    if (typeof av === "number" && typeof bv === "number") {
      return sortDir === "asc" ? av - bv : bv - av;
    }
    av = String(av).toLowerCase();
    bv = String(bv).toLowerCase();
    if (av < bv) return sortDir === "asc" ? -1 : 1;
    if (av > bv) return sortDir === "asc" ? 1 : -1;
    return 0;
  });

  const established  = connections.filter(c => c.state === "ESTABLISHED").length;
  const listening    = connections.filter(c => c.state === "LISTEN").length;
  const blockedCount = blocked.size;
  const threatsFound = [...threatScores.values()].filter(s => s >= 20).length;

  return (
    <div className="app">
      {/* Header */}
      <div className="header">
        <div className="header-left">
          <span className="logo-text">🐾 VIGILANCE</span>
          <span className="subtitle">Network Monitor</span>
        </div>
        <div className="header-right">
          <div className="stat-pill green">{established} ESTABLISHED</div>
          <div className="stat-pill blue">{listening} LISTENING</div>
          {blockedCount > 0 && <div className="stat-pill red">{blockedCount} BLOCKED</div>}
          {threatsFound > 0 && <div className="stat-pill orange">{threatsFound} THREATS</div>}
          <div className="stat-pill gray">{filtered.length}/{connections.length} SHOWN</div>
          <div className="last-update">
            {paused ? "⏸ PAUSED" : `Updated: ${lastUpdate}`}
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="🔍  Filter by process, IP, port, state, or country..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <button className={`toggle-btn ${hideLoopback ? "active" : ""}`}
          onClick={() => setHideLoopback(v => !v)} title="Hide 127.0.0.1 loopback">
          {hideLoopback ? "🔴" : "🟢"} Loopback
        </button>
        <button className={`toggle-btn ${hideListen ? "active" : ""}`}
          onClick={() => setHideListen(v => !v)} title="Hide LISTEN ports">
          {hideListen ? "🔴" : "🟢"} Listeners
        </button>
        <button className={`toggle-btn ${hideEstablished ? "active" : ""}`}
          onClick={() => setHideEstablished(v => !v)} title="Hide ESTABLISHED">
          {hideEstablished ? "🔴" : "🟢"} Established
        </button>
        <button className={`toggle-btn ${hideTimeWait ? "active" : ""}`}
          onClick={() => setHideTimeWait(v => !v)} title="Hide TIME_WAIT">
          {hideTimeWait ? "🔴" : "🟢"} Time Wait
        </button>
        <button className={`toggle-btn ${hideCloseWait ? "active" : ""}`}
          onClick={() => setHideCloseWait(v => !v)} title="Hide CLOSE_WAIT">
          {hideCloseWait ? "🔴" : "🟢"} Close Wait
        </button>
        <button className={`toggle-btn ${hideSyn ? "active" : ""}`}
          onClick={() => setHideSyn(v => !v)} title="Hide SYN_SENT and SYN_RCVD">
          {hideSyn ? "🔴" : "🟢"} SYN
        </button>
        <button className={`toggle-btn ${hideOther ? "active" : ""}`}
          onClick={() => setHideOther(v => !v)} title="Hide FIN_WAIT, CLOSING, LAST_ACK">
          {hideOther ? "🔴" : "🟢"} Other
        </button>
        <button
          className={`toggle-btn ${showThreatsOnly ? "active threat-active" : ""}`}
          onClick={() => setShowThreatsOnly(v => !v)}
          title="Show only flagged IPs (score >= 20%)"
        >
          {showThreatsOnly ? "🔴" : "🟡"} Threats Only
        </button>
        <button className={`toggle-btn ${paused ? "active" : ""}`}
          onClick={() => setPaused(v => !v)} title="Pause live updates">
          {paused ? "▶ Resume" : "⏸ Pause"}
        </button>
        <button className="refresh-btn" onClick={fetchConnections}>⟳ Refresh</button>
        <button className="reset-btn" onClick={() => {
          setHideLoopback(false); setHideListen(false);
          setHideEstablished(false); setHideTimeWait(false);
          setHideCloseWait(false); setHideSyn(false);
          setHideOther(false); setShowThreatsOnly(false);
          setFilter("");
        }}>↺ Reset</button>
        {blocked.size > 0 && (
          <button className="clear-btn" onClick={clearAllBlocks}>
            🧹 Clear Blocks ({blocked.size})
          </button>
        )}
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <table className="conn-table">
          <thead>
            <tr>
              <th onClick={() => handleSort("process_name")} className="sortable">
                PROCESS <SortIcon field="process_name" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("pid")} className="sortable">
                PID <SortIcon field="pid" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("local_addr")} className="sortable">
                LOCAL ADDRESS <SortIcon field="local_addr" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("remote_addr")} className="sortable">
                REMOTE ADDRESS <SortIcon field="remote_addr" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("country_code")} className="sortable">
                COUNTRY <SortIcon field="country_code" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("threat_score")} className="sortable">
                  THREAT <SortIcon field="threat_score" current={sortField} dir={sortDir} />
              </th>
              <th onClick={() => handleSort("state")} className="sortable">
                STATE <SortIcon field="state" current={sortField} dir={sortDir} />
              </th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="empty">No connections match your filter</td>
              </tr>
            )}
            {filtered.map((c, i) => {
              // Check against the IP address, since that's what Windows blocks
              const isBlocked = blocked.has(c.remote_addr);
              const score = threatScores.get(c.remote_addr);
              const isChecking = checkingThreat.has(c.remote_addr);
              const isPrivate = c.country_code === "LAN" || c.remote_addr === "0.0.0.0";

              return (
                <tr key={i} className={
                  isBlocked ? "row-blocked" :
                  (score ?? 0) >= 50 ? "row-threat-high" :
                  (score ?? 0) >= 20 ? "row-threat-medium" :
                  ""
                }>
                  <td className="process-name">{c.process_name}</td>
                  <td className="pid">{c.pid}</td>
                  <td className="addr">{c.local_addr}:{c.local_port}</td>
                  <td className="addr">
                    {c.remote_addr === "0.0.0.0" ||
                     (c.remote_addr === "127.0.0.1" && c.state === "LISTEN")
                      ? "—"
                      : `${c.remote_addr}:${c.remote_port}`}
                  </td>
                  <td className="country">
                    {c.country_code === "LAN"
                      ? <span className="badge badge-lan">🏠 LAN</span>
                      : c.country_code === "CF"
                      ? <span className="badge badge-cf">☁ CF</span>
                      : c.country_code === "??"
                      ? <span className="badge badge-unknown">??</span>
                      : <span className="badge badge-country">{c.country_code}</span>
                    }
                  </td>
                  <td className="threat">
                    {isPrivate
                      ? <span className="threat-na">—</span>
                      : isChecking
                      ? <span className="threat-checking">···</span>
                      : score === undefined
                      ? <span className="threat-na">—</span>
                      : score >= 50
                      ? <span className="threat-badge threat-high">🔴 {score}%</span>
                      : score >= 20
                      ? <span className="threat-badge threat-medium">🟡 {score}%</span>
                      : <span className="threat-badge threat-clean">✅ {score}%</span>
                    }
                  </td>
                  <td>
                    <span className="state-badge" style={{ color: isBlocked ? "#f85149" : stateColor(c.state) }}>
                      {isBlocked ? "BLOCKED" : c.state}
                    </span>
                  </td>
                  <td>
                    {c.remote_addr !== "0.0.0.0" && !isBlocked && (
                      <button className="block-btn"
                        onClick={() => blockConnection(c.remote_addr)}>
                        ⛔ Block
                      </button>
                    )}
                    {isBlocked && (
                      <button className="unblock-btn"
                        onClick={() => unblockConnection(c.remote_addr)}>
                        ✅ Unblock
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}