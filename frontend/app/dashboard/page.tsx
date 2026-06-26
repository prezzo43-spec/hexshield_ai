// =============================================================================
// HexShield AI — Dashboard Home Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  FolderOpen,
  FileSearch,
  AlertTriangle,
  CheckCircle,
  Activity,
  Upload,
  FileText,
} from "lucide-react";
import Link from "next/link";
import { listCases, listInvestigators, checkDetailedHealth } from "@/services/api";
import { CASE_STATUS_BG, formatDate } from "@/types";

export default function DashboardPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [investigators, setInvestigators] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      listCases().catch(() => ({ cases: [] })),
      listInvestigators().catch(() => ({ investigators: [] })),
      checkDetailedHealth().catch(() => null),
    ]).then(([casesData, investData, healthData]) => {
      setCases(casesData.cases || []);
      setInvestigators(investData.investigators || []);
      setHealth(healthData);
      setLoading(false);
    });
  }, []);

  const openCases = cases.filter((c) => c.status === "OPEN").length;
  const underAnalysis = cases.filter(
    (c) => c.status === "UNDER_ANALYSIS"
  ).length;
  const closedCases = cases.filter((c) => c.status === "CLOSED").length;

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "60vh",
          gap: "1rem",
          color: "var(--muted)",
        }}
      >
        <div className="loading-spinner" />
        Loading dashboard...
      </div>
    );
  }

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Forensic Dashboard</h1>
          <p className="page-subtitle">
            HexShield AI — Digital Evidence Analysis Platform
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <Link href="/dashboard/submit" className="btn btn-primary">
            <Upload size={16} />
            Submit Evidence
          </Link>
          <Link href="/dashboard/cases" className="btn btn-outline">
            <FolderOpen size={16} />
            View Cases
          </Link>
        </div>
      </div>

      {/* System Health Banner */}
      {health && (
        <div
          className={`alert ${
            health.status === "healthy" ? "alert-success" : "alert-warning"
          }`}
          style={{ marginBottom: "1.5rem" }}
        >
          <Activity size={16} style={{ marginTop: 2, flexShrink: 0 }} />
          <div>
            <strong>System Status: {health.status.toUpperCase()}</strong>
            <span style={{ marginLeft: "1rem", fontSize: "0.8125rem" }}>
              Database: {health.components?.database?.status} | Hex Engine:{" "}
              {health.components?.hex_engine?.status} | AI Engine:{" "}
              {health.components?.ai_engine?.status}
            </span>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "1rem",
          marginBottom: "2rem",
        }}
      >
        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <FolderOpen size={18} color="var(--primary)" />
            <span className="stat-label">Total Cases</span>
          </div>
          <div className="stat-value">{cases.length}</div>
          <div className="stat-sub">{openCases} open</div>
        </div>

        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <FileSearch size={18} color="var(--secondary)" />
            <span className="stat-label">Under Analysis</span>
          </div>
          <div className="stat-value">{underAnalysis}</div>
          <div className="stat-sub">Active investigations</div>
        </div>

        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle size={18} color="var(--success)" />
            <span className="stat-label">Closed Cases</span>
          </div>
          <div className="stat-value">{closedCases}</div>
          <div className="stat-sub">Completed</div>
        </div>

        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Shield size={18} color="var(--accent)" />
            <span className="stat-label">Investigators</span>
          </div>
          <div className="stat-value">{investigators.length}</div>
          <div className="stat-sub">Active analysts</div>
        </div>
      </div>

      {/* Recent Cases */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "1rem",
          }}
        >
          <h2 className="section-title" style={{ margin: 0 }}>
            Recent Cases
          </h2>
          <Link
            href="/dashboard/cases"
            style={{
              fontSize: "0.8125rem",
              color: "var(--primary)",
              textDecoration: "none",
            }}
          >
            View all
          </Link>
        </div>

        {cases.length === 0 ? (
          <div className="empty-state">
            <FolderOpen size={40} className="empty-state-icon" />
            <div>No cases found</div>
            <Link href="/dashboard/cases" className="btn btn-primary">
              Open First Case
            </Link>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Case Reference</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Lead Investigator</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {cases.slice(0, 5).map((c) => (
                  <tr key={c.id}>
                    <td>
                      <Link
                        href={`/dashboard/cases/${c.id}`}
                        style={{
                          color: "var(--primary)",
                          textDecoration: "none",
                          fontWeight: 500,
                          fontFamily: "monospace",
                        }}
                      >
                        {c.case_reference}
                      </Link>
                    </td>
                    <td>{c.case_title}</td>
                    <td>
                      <span
                        className={`badge ${
                          CASE_STATUS_BG[
                            c.status as keyof typeof CASE_STATUS_BG
                          ] || "bg-gray-100 text-gray-800"
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td>{c.lead_investigator_name}</td>
                    <td style={{ color: "var(--muted)" }}>
                      {formatDate(c.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "1rem",
        }}
      >
        <Link
          href="/dashboard/cases"
          style={{ textDecoration: "none" }}
        >
          <div
            className="card"
            style={{
              cursor: "pointer",
              transition: "border-color 0.15s",
              display: "flex",
              alignItems: "center",
              gap: "1rem",
            }}
          >
            <div
              style={{
                width: 44,
                height: 44,
                background: "rgba(59, 130, 246, 0.1)",
                borderRadius: 10,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <FolderOpen size={22} color="var(--primary)" />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.9375rem" }}>
                Manage Cases
              </div>
              <div style={{ fontSize: "0.8125rem", color: "var(--muted)" }}>
                Open, view and manage forensic cases
              </div>
            </div>
          </div>
        </Link>

        <Link
          href="/dashboard/submit"
          style={{ textDecoration: "none" }}
        >
          <div
            className="card"
            style={{
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "1rem",
            }}
          >
            <div
              style={{
                width: 44,
                height: 44,
                background: "rgba(99, 102, 241, 0.1)",
                borderRadius: 10,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <Upload size={22} color="var(--secondary)" />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.9375rem" }}>
                Submit Evidence
              </div>
              <div style={{ fontSize: "0.8125rem", color: "var(--muted)" }}>
                Upload files for forensic analysis
              </div>
            </div>
          </div>
        </Link>

        <Link
          href="/dashboard/reports"
          style={{ textDecoration: "none" }}
        >
          <div
            className="card"
            style={{
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "1rem",
            }}
          >
            <div
              style={{
                width: 44,
                height: 44,
                background: "rgba(6, 182, 212, 0.1)",
                borderRadius: 10,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <FileText size={22} color="var(--accent)" />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.9375rem" }}>
                Forensic Reports
              </div>
              <div style={{ fontSize: "0.8125rem", color: "var(--muted)" }}>
                Generate and download court-ready reports
              </div>
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}