import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchLogs = async () => {
    try {
      const response = await fetch('http://localhost:4873/api/logs');
      const data = await response.json();
      setLogs(data);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch logs', err);
    }
  };

  const scanLogs = logs.filter(l => l.event === 'scan_complete' || l.event === 'block');
  const blocks = scanLogs.filter(l => l.verdict === 'malicious');
  const clean = scanLogs.filter(l => l.verdict === 'clean');
  
  return (
    <div className="dashboard">
      <header className="header">
        <div className="logo-container">
          <div className="shield-icon">🛡️</div>
          <h1>SupplyGuard <span>Mission Control</span></h1>
        </div>
        <div className="status-badge pulse">
          <div className="dot"></div>
          Active Interceptor
        </div>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Intercepts</h3>
          <p className="stat-number">{scanLogs.length}</p>
        </div>
        <div className="stat-card clean">
          <h3>Clean Packages</h3>
          <p className="stat-number">{clean.length}</p>
        </div>
        <div className="stat-card danger">
          <h3>Malicious Blocks</h3>
          <p className="stat-number">{blocks.length}</p>
        </div>
      </div>

      <div className="main-content">
        <div className="panel">
          <h2>Security Provenance Log</h2>
          {loading ? (
            <div className="loading">Syncing with Agent Sandbox...</div>
          ) : scanLogs.length === 0 ? (
            <div className="empty-state">No agent activity detected yet.</div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Package</th>
                    <th>Verdict</th>
                    <th>Confidence</th>
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
                      <td className="decision">{log.decision || log.evidence?.[0] || 'Clean topological structure'}</td>
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
