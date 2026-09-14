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
import {
  listCases,
  listInvestigators,
  checkDetailedHealth,
  getEvaluationSummary,
} from "@/services/api";
import { CASE_STATUS_BG, formatDate } from "@/types";
import { useAuth } from "@/contexts/AuthContext";

export default function DashboardPage() {
  const { investigator } = useAuth();
  const isAdmin = investigator?.role === "SYSTEM_ADMIN";
  const [cases, setCases] = useState<any[]>([]);
  const [investigators, setInvestigators] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [evaluation, setEvaluation] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      listCases().catch(() => ({ cases: [] })),
      isAdmin
        ? listInvestigators().catch(() => ({ investigators: [] }))
        : Promise.resolve({ investigators: [] }),
      checkDetailedHealth().catch(() => null),
      isAdmin ? getEvaluationSummary().catch(() => null) : Promise.resolve(null),
    ]).then(([casesData, investData, healthData, evaluationData]) => {
      setCases(casesData.cases || []);
      setInvestigators(investData.investigators || []);
      setHealth(healthData);
      setEvaluation(evaluationData);
      setLoading(false);
    });
  }, [isAdmin]);

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
          <div className="eyebrow" style={{ marginBottom: "0.45rem" }}>
            Secure Evidence Operations / East Africa Desk
          </div>
          <h1 className="page-title">Forensic Dashboard</h1>
          <p className="page-subtitle">
            Command overview for active investigations, evidence integrity, and examiner review.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          {!isAdmin && (
            <Link href="/dashboard/submit" className="btn btn-primary">
              <Upload size={16} />
              Submit Evidence
            </Link>
          )}
          <Link href="/dashboard/cases" className="btn btn-outline">
            <FolderOpen size={16} />
            View Cases
          </Link>
        </div>
      </div>

      <div className="command-strip">
        <div style={{ display: "flex", alignItems: "center", gap: "0.65rem" }}>
          <span style={{ color: "var(--success)", fontSize: "0.8rem" }}>●</span>
          <span style={{ fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", fontSize: "0.72rem", letterSpacing: "0.08em" }}>
            OPERATIONS STATUS / NOMINAL
          </span>
        </div>
        <div style={{ color: "var(--muted)", fontSize: "0.75rem" }}>
          Evidence controls active • Session tier: {investigator?.role || "RESTRICTED"}
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

      {isAdmin && evaluation && (
        <div className="command-strip" style={{ marginBottom: "1.5rem" }}>
          <div>
            <div className="eyebrow" style={{ marginBottom: "0.35rem" }}>
              Evaluation Readiness / Layer 1
            </div>
            <div style={{ fontSize: "0.82rem" }}>
              {evaluation.dataset_size} labelled files • prototype benchmark
            </div>
          </div>
          <div style={{ display: "flex", gap: "1.2rem", fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", fontSize: "0.72rem" }}>
            <span>ACC {evaluation.metrics?.accuracy_percent ?? "--"}%</span>
            <span>F1 {evaluation.metrics?.f1_score_percent ?? "--"}%</span>
            <span style={{ color: "var(--warning)" }}>FPR {evaluation.metrics?.false_positive_rate_percent ?? "--"}%</span>
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
            <span className="stat-label">Assigned Cases</span>
          </div>
          <div className="stat-value">{cases.length}</div>
          <div className="stat-sub">{openCases} open</div>
        </div>

        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <FileSearch size={18} color="var(--secondary)" />
            <span className="stat-label">Active Analysis</span>
          </div>
          <div className="stat-value">{underAnalysis}</div>
          <div className="stat-sub">Active investigations</div>
        </div>

        <div className="stat-card">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle size={18} color="var(--success)" />
            <span className="stat-label">Closed Dossiers</span>
          </div>
          <div className="stat-value">{closedCases}</div>
          <div className="stat-sub">Completed</div>
        </div>

        {isAdmin && (
          <div className="stat-card">
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Shield size={18} color="var(--accent)" />
              <span className="stat-label">Investigators</span>
            </div>
            <div className="stat-value">{investigators.length}</div>
            <div className="stat-sub">Active analysts</div>
          </div>
        )}
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
            Recent Case Activity
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
                  <th>Case Custodian</th>
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

        {!isAdmin && (
          <Link href="/dashboard/submit" style={{ textDecoration: "none" }}>
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
        )}

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