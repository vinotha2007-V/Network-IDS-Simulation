
import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [analytics, setAnalytics] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadDashboard() {
    try {
      const [analyticsResponse, alertsResponse] = await Promise.all([
        fetch(`${API}/analytics`),
        fetch(`${API}/alerts?limit=5000`),
      ]);

      if (!analyticsResponse.ok || !alertsResponse.ok) {
        throw new Error("Could not load dashboard data.");
      }

      const analyticsData = await analyticsResponse.json();
      const alertsData = await alertsResponse.json();

      setAnalytics(analyticsData);
      setAlerts(
        Array.isArray(alertsData)
          ? alertsData
          : alertsData.alerts || alertsData.items || []
      );
      setError("");
    } catch (err) {
      setError("Cannot connect to the backend. Please check whether the backend is running.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(loadDashboard, 15000);
    return () => clearInterval(timer);
  }, []);

  const filteredAlerts = alerts.filter((alert) => {
    const query = search.trim().toLowerCase();

    const sourceIP = String(
      alert.source_ip ?? alert.src_ip ?? ""
    ).toLowerCase();

    const destinationIP = String(
      alert.destination_ip ?? alert.dest_ip ?? alert.dst_ip ?? ""
    ).toLowerCase();

    const protocol = String(alert.protocol ?? "").toLowerCase();
    const flowID = String(alert.flow_id ?? alert.id ?? "").toLowerCase();

    const matchesSearch =
      !query ||
      sourceIP.includes(query) ||
      destinationIP.includes(query) ||
      protocol.includes(query) ||
      flowID.includes(query);

    const severity = String(
      alert.severity ?? alert.alert_severity ?? "INFO"
    ).toUpperCase();

    const status = String(alert.status ?? "OPEN").toUpperCase();

    const matchesSeverity =
      severityFilter === "ALL" || severity === severityFilter;

    const matchesStatus =
      statusFilter === "ALL" || status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const totalRecords =
    analytics.total_records ??
    analytics.total_flows ??
    analytics.total_traffic ??
    5000;

  const suspiciousRecords =
    analytics.suspicious_records ??
    analytics.suspicious_count ??
    analytics.suspicious_flows ??
    0;

  const criticalCount = alerts.filter(
    (a) => String(a.severity ?? "").toUpperCase() === "CRITICAL"
  ).length;

  const highCount = alerts.filter(
    (a) => String(a.severity ?? "").toUpperCase() === "HIGH"
  ).length;

  const navigation = [
    { id: "overview", label: "Command Center" },
    { id: "alerts", label: "Threat Alerts" },
    { id: "traffic", label: "Traffic Analysis" },
    { id: "risk", label: "Risk Intelligence" },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">N</div>
          <div>
            <h2>NEURALWATCH</h2>
            <span>NETWORK DEFENSE SYSTEM</span>
          </div>
        </div>

        <p className="nav-heading">SECURITY OPERATIONS</p>

        <nav className="navigation">
          {navigation.map((item) => (
            <button
              key={item.id}
              className={`nav-link ${
                activePage === item.id ? "active" : ""
              }`}
              onClick={() => setActivePage(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          <span>SIMULATION MODE</span>
          <small>Synthetic data only</small>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h1>
              {navigation.find((item) => item.id === activePage)?.label}
            </h1>
          </div>

          <button className="refresh-button" onClick={loadDashboard}>
            ↻ Refresh
          </button>
        </header>

        {error && <div className="error-banner">{error}</div>}

        {loading ? (
          <div className="loading-state">Loading security data...</div>
        ) : (
          <>
            <section className="metrics-grid">
              <MetricCard
                title="Total Traffic Records"
                value={totalRecords.toLocaleString()}
                note="Synthetic network flows"
              />
              <MetricCard
                title="Suspicious Records"
                value={Number(suspiciousRecords).toLocaleString()}
                note="Flagged by simulation"
              />
              <MetricCard
                title="Critical Alerts"
                value={criticalCount.toLocaleString()}
                note="Critical severity records"
                danger
              />
              <MetricCard
                title="High Alerts"
                value={highCount.toLocaleString()}
                note="High severity records"
              />
            </section>

            {activePage === "overview" && (
              <>
                <section className="content-grid">
                  <TrafficPanel analytics={analytics} alerts={alerts} />
                  <SeverityPanel alerts={alerts} />
                </section>
                <AlertsTable
                  alerts={filteredAlerts.slice(0, 8)}
                  search={search}
                  setSearch={setSearch}
                  severityFilter={severityFilter}
                  setSeverityFilter={setSeverityFilter}
                  statusFilter={statusFilter}
                  setStatusFilter={setStatusFilter}
                  showFilters={false}
                />
              </>
            )}

            {activePage === "alerts" && (
              <AlertsTable
                alerts={filteredAlerts}
                search={search}
                setSearch={setSearch}
                severityFilter={severityFilter}
                setSeverityFilter={setSeverityFilter}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                showFilters
              />
            )}

            {activePage === "traffic" && (
              <section className="content-grid">
                <TrafficPanel analytics={analytics} alerts={alerts} />
                <SeverityPanel alerts={alerts} />
              </section>
            )}

            {activePage === "risk" && (
              <>
                <section className="content-grid">
                  <SeverityPanel alerts={alerts} />
                  <div className="panel">
                    <h2>Risk Intelligence</h2>
                    <p>
                      Review simulated traffic records by severity and status.
                    </p>
                    <div className="risk-summary">
                      <p>
                        <span>Critical</span>
                        <strong>{criticalCount}</strong>
                      </p>
                      <p>
                        <span>High</span>
                        <strong>{highCount}</strong>
                      </p>
                      <p>
                        <span>Other records</span>
                        <strong>
                          {Math.max(
                            0,
                            alerts.length - criticalCount - highCount
                          )}
                        </strong>
                      </p>
                    </div>
                  </div>
                </section>
                <AlertsTable
                  alerts={filteredAlerts.slice(0, 8)}
                  search={search}
                  setSearch={setSearch}
                  severityFilter={severityFilter}
                  setSeverityFilter={setSeverityFilter}
                  statusFilter={statusFilter}
                  setStatusFilter={setStatusFilter}
                  showFilters={false}
                />
              </>
            )}
          </>
        )}

        <footer className="app-footer">
          Network IDS Simulation · Educational defensive project · Synthetic data
        </footer>
      </main>
    </div>
  );
}

function MetricCard({ title, value, note, danger = false }) {
  return (
    <div className={`metric-card ${danger ? "danger-card" : ""}`}>
      <p>{title}</p>
      <h2>{value}</h2>
      <span>{note}</span>
    </div>
  );
}

function SeverityPanel({ alerts }) {
  const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  const counts = levels.map((level) => ({
    name: level,
    count: alerts.filter(
      (a) => String(a.severity ?? "").toUpperCase() === level
    ).length,
  }));

  const maxCount = Math.max(1, ...counts.map((item) => item.count));

  return (
    <div className="panel">
      <h2>Severity Distribution</h2>
      <p className="panel-subtitle">Based on returned alert records</p>

      <div className="severity-list">
        {counts.map((item) => (
          <div className="severity-row" key={item.name}>
            <span className={`severity-label ${item.name.toLowerCase()}`}>
              {item.name}
            </span>
            <div className="bar-track">
              <div
                className={`bar-fill ${item.name.toLowerCase()}`}
                style={{ width: `${(item.count / maxCount) * 100}%` }}
              />
            </div>
            <strong>{item.count}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrafficPanel({ analytics, alerts }) {
  return (
    <div className="panel">
      <h2>Traffic Analysis</h2>
      <p className="panel-subtitle">Synthetic network traffic overview</p>

      <div className="traffic-stats">
        <div>
          <span>Records loaded</span>
          <strong>{alerts.length.toLocaleString()}</strong>
        </div>
        <div>
          <span>Protocols observed</span>
          <strong>
            {new Set(alerts.map((a) => a.protocol).filter(Boolean)).size}
          </strong>
        </div>
        <div>
          <span>Analytics fields</span>
          <strong>{Object.keys(analytics).length}</strong>
        </div>
      </div>

      <p className="panel-note">
        This dashboard displays simulated data, not live network traffic.
      </p>
    </div>
  );
}

function AlertsTable({
  alerts,
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  statusFilter,
  setStatusFilter,
  showFilters,
}) {
  return (
    <section className="panel alerts-panel">
      <div className="panel-header">
        <div>
          <h2>Threat Alerts</h2>
          <p className="panel-subtitle">
            {alerts.length} matching record(s)
          </p>
        </div>
      </div>

      {showFilters && (
        <div className="alert-filters">
          <input
            type="text"
            placeholder="Search IP, protocol or flow ID..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search alerts"
          />

          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            aria-label="Filter by severity"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            aria-label="Filter by status"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          <button
            className="clear-button"
            onClick={() => {
              setSearch("");
              setSeverityFilter("ALL");
              setStatusFilter("ALL");
            }}
          >
            Clear
          </button>
        </div>
      )}

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Flow / ID</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Protocol</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan="6" className="empty-state">
                  No matching records found.
                </td>
              </tr>
            ) : (
              alerts.map((alert, index) => {
                const severity = String(
                  alert.severity ?? alert.alert_severity ?? "INFO"
                ).toUpperCase();

                const status = String(alert.status ?? "OPEN").toUpperCase();

                return (
                  <tr key={alert.id ?? alert.flow_id ?? index}>
                    <td>{alert.flow_id ?? alert.id ?? `Record ${index + 1}`}</td>
                    <td>{alert.source_ip ?? alert.src_ip ?? "—"}</td>
                    <td>
                      {alert.destination_ip ??
                        alert.dest_ip ??
                        alert.dst_ip ??
                        "—"}
                    </td>
                    <td>{alert.protocol ?? "—"}</td>
                    <td>
                      <span className={`severity-badge ${severity.toLowerCase()}`}>
                        {severity}
                      </span>
                    </td>
                    <td>
                      <span className="status-badge">
                        {status}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default App;