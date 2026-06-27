// =============================================================================
// HexShield AI — Reports Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import { FileText, Download, CheckCircle, Clock } from "lucide-react";
import { listCases, listReports, getReportDownloadUrl } from "@/services/api";
import { formatDate } from "@/types";

export default function ReportsPage() {
  const [allReports, setAllReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const casesData = await listCases();
        const cases = casesData.cases || [];
        const reportsArrays = await Promise.all(
          cases.map((c: any) =>
            listReports(c.id)
              .then((r) =>
                (r.reports || []).map((rep: any) => ({
                  ...rep,
                  case_reference: c.case_reference,
                  case_title: c.case_title,
                }))
              )
              .catch(() => [])
          )
        );
        setAllReports(reportsArrays.flat());
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const filtered = allReports.filter((r) => {
    if (filter === "ALL") return true;
    if (filter === "PDF") return r.report_format === "PDF";
    if (filter === "JSON") return r.report_format === "JSON";
    if (filter === "COURT_READY") return r.is_court_ready;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Forensic Reports</h1>
          <p className="page-subtitle">
            Court-ready and machine-readable forensic analysis reports
          </p>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <div className="stat-card">
          <div className="stat-label">Total Reports</div>
          <div className="stat-value">{allReports.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">PDF Reports</div>
          <div className="stat-value">
            {allReports.filter((r) => r.report_format === "PDF").length}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">JSON Reports</div>
          <div className="stat-value">
            {allReports.filter((r) => r.report_format === "JSON").length}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Court Ready</div>
          <div className="stat-value">
            {allReports.filter((r) => r.is_court_ready).length}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem" }}>
        {["ALL", "PDF", "JSON", "COURT_READY"].map((f) => (
          <button
            key={f}
            className={`btn ${filter === f ? "btn-primary" : "btn-outline"}`}
            style={{ padding: "0.375rem 0.875rem", fontSize: "0.8125rem" }}
            onClick={() => setFilter(f)}
          >
            {f.replace("_", " ")}
          </button>
        ))}
      </div>

      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            Loading reports...
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <FileText size={40} className="empty-state-icon" />
            <div>No reports found</div>
            <p
              style={{
                fontSize: "0.875rem",
                color: "var(--muted)",
                maxWidth: 320,
                textAlign: "center",
              }}
            >
              Generate reports from the Analysis page after completing hex
              and AI analysis on submitted evidence.
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Report Filename</th>
                  <th>Case</th>
                  <th>Format</th>
                  <th>Type</th>
                  <th>Size</th>
                  <th>Court Ready</th>
                  <th>Generated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div
                        style={{
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          maxWidth: 260,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {r.report_filename}
                      </div>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "monospace",
                          fontSize: "0.8125rem",
                          color: "var(--primary)",
                        }}
                      >
                        {r.case_reference}
                      </span>
                    </td>
                    <td>
                      <span
                        className={
                          r.report_format === "PDF"
                            ? "badge bg-red-100 text-red-800"
                            : "badge bg-blue-100 text-blue-800"
                        }
                      >
                        {r.report_format}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.8125rem", color: "var(--muted)" }}>
                      {r.report_type}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
                      {(r.file_size_bytes / 1024).toFixed(1)} KB
                    </td>
                    <td>
                      {r.is_court_ready ? (
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.375rem",
                            color: "var(--success)",
                            fontSize: "0.8125rem",
                          }}
                        >
                          <CheckCircle size={14} />
                          Certified
                        </div>
                      ) : (
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.375rem",
                            color: "var(--muted)",
                            fontSize: "0.8125rem",
                          }}
                        >
                          <Clock size={14} />
                          Pending
                        </div>
                      )}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
                      {formatDate(r.generated_at)}
                    </td>
                    <td>
                      <button
                        className="btn btn-outline"
                        onClick={() => window.open(getReportDownloadUrl(r.id), "_blank")}
                      >
                        <Download size={13} />
                        Download
                      </button>
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