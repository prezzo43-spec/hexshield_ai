// =============================================================================
// HexShield AI — Activity Logs Page
// Shows all system activity including logins, analysis, and file submissions.
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  LogIn,
  FileSearch,
  Shield,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { api } from "@/services/api";
import { formatDate } from "@/types";

export default function ActivityLogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const fetchLogs = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.get("/api/v1/activity-logs?limit=200");
      setLogs(res.data.logs || []);
    } catch (requestError: any) {
      console.error(requestError);
      setLogs([]);
      setError(
        requestError?.response?.data?.detail ||
          "Activity logs could not be loaded."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let isMounted = true;

    const load = async () => {
      if (!isMounted) {
        return;
      }
      await fetchLogs();
    };

    void load();
    const interval = setInterval(fetchLogs, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const categories = ["ALL", "AUTH", "FILE_ACCESS", "ANALYSIS", "REPORT", "SECURITY", "ERROR"];

  const filtered = logs.filter((log) => {
    const matchCategory = filter === "ALL" || log.event_category === filter;
    const matchSearch =
      !search ||
      (log.investigator_name || "").toLowerCase().includes(search.toLowerCase()) ||
      (log.event_action || "").toLowerCase().includes(search.toLowerCase()) ||
      (log.ip_address || "").includes(search);
    return matchCategory && matchSearch;
  });

  const getEventIcon = (category: string, success: boolean) => {
    if (!success) return <AlertTriangle size={14} color="var(--danger)" />;
    switch (category) {
      case "AUTH":
        return <LogIn size={14} color="var(--success)" />;
      case "ANALYSIS":
        return <FileSearch size={14} color="var(--primary)" />;
      case "REPORT":
        return <Shield size={14} color="var(--accent)" />;
      case "SECURITY":
        return <AlertTriangle size={14} color="var(--warning)" />;
      default:
        return <Activity size={14} color="var(--muted)" />;
    }
  };

  const getCategoryBadge = (category: string) => {
    const colors: Record<string, string> = {
      AUTH: "bg-green-100 text-green-800",
      FILE_ACCESS: "bg-blue-100 text-blue-800",
      ANALYSIS: "bg-purple-100 text-purple-800",
      REPORT: "bg-cyan-100 text-cyan-800",
      SECURITY: "bg-red-100 text-red-800",
      ERROR: "bg-red-100 text-red-800",
      CONFIG: "bg-yellow-100 text-yellow-800",
    };
    return colors[category] || "bg-gray-100 text-gray-500";
  };

  const stats = {
    total: logs.length,
    logins: logs.filter((l) => l.event_action === "LOGIN_SUCCESS").length,
    failed: logs.filter((l) => !l.success).length,
    analysis: logs.filter((l) => l.event_category === "ANALYSIS").length,
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Activity Logs</h1>
          <p className="page-subtitle">
            Real-time monitoring of all system activity and access events
          </p>
        </div>
        <button
          className="btn btn-outline"
          onClick={fetchLogs}
          disabled={loading}
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
          {error}
        </div>
      )}

      {/* Stats */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <div className="stat-card">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{stats.total}</div>
          <div className="stat-sub">Last 200 events</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Successful Logins</div>
          <div className="stat-value" style={{ color: "var(--success)" }}>
            {stats.logins}
          </div>
          <div className="stat-sub">Authenticated sessions</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Failed Events</div>
          <div className="stat-value" style={{ color: "var(--danger)" }}>
            {stats.failed}
          </div>
          <div className="stat-sub">Errors and failures</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Analysis Events</div>
          <div className="stat-value" style={{ color: "var(--primary)" }}>
            {stats.analysis}
          </div>
          <div className="stat-sub">Forensic analysis runs</div>
        </div>
      </div>

      {/* Filters */}
      <div
        style={{
          display: "flex",
          gap: "0.75rem",
          marginBottom: "1.5rem",
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap" }}>
          {categories.map((cat) => (
            <button
              key={cat}
              className={`btn ${filter === cat ? "btn-primary" : "btn-outline"}`}
              style={{ padding: "0.25rem 0.75rem", fontSize: "0.75rem" }}
              onClick={() => setFilter(cat)}
            >
              {cat}
            </button>
          ))}
        </div>
        <input
          className="input"
          style={{ maxWidth: 260, fontSize: "0.875rem" }}
          placeholder="Search by name, action, IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Logs Table */}
      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            Loading activity logs...
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <Activity size={40} className="empty-state-icon" />
            <div>No activity logs found</div>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Category</th>
                  <th>Action</th>
                  <th>Investigator</th>
                  <th>IP Address</th>
                  <th>Details</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => (
                  <tr key={log.id}>
                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "0.375rem",
                        }}
                      >
                        {getEventIcon(log.event_category, log.success)}
                        <span
                          style={{
                            fontSize: "0.75rem",
                            color: log.success
                              ? "var(--success)"
                              : "var(--danger)",
                          }}
                        >
                          {log.success ? "OK" : "FAIL"}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span
                        className={`badge ${getCategoryBadge(log.event_category)}`}
                      >
                        {log.event_category}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "monospace",
                          fontSize: "0.8125rem",
                          color: "var(--foreground)",
                        }}
                      >
                        {log.event_action}
                      </span>
                    </td>
                    <td>
                      {log.investigator_name ? (
                        <div>
                          <div style={{ fontSize: "0.875rem", fontWeight: 500 }}>
                            {log.investigator_name}
                          </div>
                          {log.badge_number && (
                            <div
                              style={{
                                fontSize: "0.75rem",
                                color: "var(--muted)",
                                fontFamily: "monospace",
                              }}
                            >
                              {log.badge_number}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
                          Anonymous
                        </span>
                      )}
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "monospace",
                          fontSize: "0.8125rem",
                          color: "var(--muted)",
                        }}
                      >
                        {log.ip_address || "—"}
                      </span>
                    </td>
                    <td style={{ maxWidth: 300 }}>
                      <div
                        style={{
                          fontSize: "0.8125rem",
                          color: log.success ? "var(--muted)" : "var(--danger)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          maxWidth: 280,
                        }}
                        title={log.event_description || log.error_message || ""}
                      >
                        {log.event_description || log.error_message || "—"}
                      </div>
                    </td>
                    <td
                      style={{
                        color: "var(--muted)",
                        fontSize: "0.8125rem",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {formatDate(log.occurred_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}