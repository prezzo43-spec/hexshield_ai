// =============================================================================
// HexShield AI — Analysis List Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Cpu, Search, FolderOpen } from "lucide-react";
import { listCases, listSubmissions } from "@/services/api";
import { formatDate, formatFileSize, RISK_LEVEL_BG } from "@/types";

export default function AnalysisPage() {
  const [allSubmissions, setAllSubmissions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const casesData = await listCases();
        const cases = casesData.cases || [];

        const subsArrays = await Promise.all(
          cases.map((c: any) =>
            listSubmissions(c.id)
              .then((r) =>
                (r.submissions || []).map((s: any) => ({
                  ...s,
                  case_reference: c.case_reference,
                  case_title: c.case_title,
                }))
              )
              .catch(() => [])
          )
        );

        setAllSubmissions(subsArrays.flat());
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const filtered = allSubmissions.filter(
    (s) =>
      !search ||
      s.original_filename.toLowerCase().includes(search.toLowerCase()) ||
      s.case_reference.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Analysis Queue</h1>
          <p className="page-subtitle">
            View and trigger forensic analysis on submitted evidence
          </p>
        </div>
      </div>

      {/* Search */}
      <div style={{ position: "relative", maxWidth: 360, marginBottom: "1.5rem" }}>
        <Search
          size={16}
          style={{
            position: "absolute",
            left: 12,
            top: "50%",
            transform: "translateY(-50%)",
            color: "var(--muted)",
          }}
        />
        <input
          className="input"
          style={{ paddingLeft: 36 }}
          placeholder="Search by filename or case..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="card">
        {loading ? (
          <div className="empty-state">
            <div className="loading-spinner" />
            Loading submissions...
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <Cpu size={40} className="empty-state-icon" />
            <div>No submissions found</div>
            <Link href="/dashboard/submit" className="btn btn-primary">
              Submit Evidence
            </Link>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Case</th>
                  <th>Size</th>
                  <th>Hex Analysis</th>
                  <th>AI Analysis</th>
                  <th>Report</th>
                  <th>Submitted</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((sub) => (
                  <tr key={sub.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>
                        {sub.original_filename}
                      </div>
                      <div
                        style={{
                          fontSize: "0.75rem",
                          color: "var(--muted)",
                          fontFamily: "monospace",
                        }}
                      >
                        {sub.id.slice(0, 8)}...
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
                        {sub.case_reference}
                      </span>
                    </td>
                    <td style={{ color: "var(--muted)" }}>
                      {formatFileSize(sub.file_size_bytes)}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          sub.hex_analysis_complete
                            ? "bg-green-100 text-green-800"
                            : "bg-gray-100 text-gray-500"
                        }`}
                      >
                        {sub.hex_analysis_complete ? "Done" : "Pending"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          sub.ai_analysis_complete
                            ? "bg-green-100 text-green-800"
                            : "bg-gray-100 text-gray-500"
                        }`}
                      >
                        {sub.ai_analysis_complete ? "Done" : "Pending"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          sub.report_generated
                            ? "bg-blue-100 text-blue-800"
                            : "bg-gray-100 text-gray-500"
                        }`}
                      >
                        {sub.report_generated ? "Generated" : "None"}
                      </span>
                    </td>
                    <td
                      style={{
                        color: "var(--muted)",
                        fontSize: "0.8125rem",
                      }}
                    >
                      {formatDate(sub.ingestion_timestamp)}
                    </td>
                    <td>
                      <Link
                        href={`/dashboard/analysis/${sub.id}`}
                        className="btn btn-outline"
                        style={{
                          padding: "0.25rem 0.75rem",
                          fontSize: "0.8125rem",
                        }}
                      >
                        Open
                      </Link>
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