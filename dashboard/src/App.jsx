import { useEffect, useState } from 'react';
import './App.css';

// Point the dashboard at a different proxy with VITE_KORVYR_PROXY_URL.
const PROXY_URL = import.meta.env.VITE_KORVYR_PROXY_URL || 'http://localhost:4873';
const POLL_INTERVAL_MS = 2000;

function App() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function fetchLogs() {
      try {
        const response = await fetch(`${PROXY_URL}/api/logs`);
        const data = await response.json();
        if (!cancelled) setLogs(data);
      } catch (err) {
        console.error('Failed to fetch logs', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    const interval = setInterval(fetchLogs, POLL_INTERVAL_MS);
    fetchLogs();
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const scanLogs = logs.filter(l => l.event === 'scan_complete' || l.event === 'block');
  const blocks = scanLogs.filter(l => l.verdict === 'malicious');
  const clean = scanLogs.filter(l => l.verdict === 'clean');
  
  return (
    <div className="dashboard">
      <header className="header">
        <div className="logo-container">
          <div className="shield-icon">🛡️</div>
          <h1>Korvyr <span>Scan Log</span></h1>
        </div>
        <div className="status-badge pulse">
          <div className="dot"></div>
          Proxy connected
        </div>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Packages scanned</h3>
          <p className="stat-number">{scanLogs.length}</p>
        </div>
        <div className="stat-card clean">
          <h3>Clean</h3>
          <p className="stat-number">{clean.length}</p>
        </div>
        <div className="stat-card danger">
          <h3>Blocked</h3>
          <p className="stat-number">{blocks.length}</p>
        </div>
      </div>

      <div className="main-content">
        <div className="panel">
          <h2>Proxy decisions</h2>
          {loading ? (
            <div className="loading">Loading proxy log...</div>
          ) : scanLogs.length === 0 ? (
            <div className="empty-state">No packages scanned yet.</div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Package</th>
                    <th>Verdict</th>
                    <th>GNN score</th>
                    <th>Decision Path</th>
                  </tr>
                </thead>
                <tbody>
                  {scanLogs.map((log, i) => (
                    <tr key={i} className={`row-${log.verdict}`}>
                      <td className="time">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="package">{log.package}</td>
                      <td>
                        <span className={`badge badge-${log.verdict}`}>
                          {log.verdict.toUpperCase()}
                        </span>
                      </td>
                      <td className="score">
                        {log.gnn_score !== undefined ? log.gnn_score.toFixed(2) : '-'}
                      </td>
                      <td className="decision">{log.decision || log.evidence?.[0] || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
