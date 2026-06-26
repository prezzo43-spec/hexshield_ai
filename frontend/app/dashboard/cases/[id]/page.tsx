// =============================================================================
// HexShield AI — Case Detail Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  FolderOpen,
  Upload,
  FileSearch,
  Shield,
  Calendar,
  User,
  Hash,
  AlertTriangle,
  CheckCircle,
  Clock,
} from "lucide-react";
import {
  getCase,
  listSubmissions,
  updateCaseStatus,
} from "@/services/api";
import {
  CASE_STATUS_BG,
  RISK_LEVEL_BG,
  formatDate,
  formatFileSize,
  truncateHash,
} from "@/types";

export default function CaseDetailPage() {
  const params = useParams();
  const router = useRouter();
  const caseId = params.id as string;

  const [caseData, setCaseData] = useState<any>(null);
  const [submissions, setSubmissions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatingStatus, setUpdatingStatus] = useState(false);

  useEffect(() => {
    fetchData();
  }, [caseId]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [caseRes, subsRes] = await Promise.all([
        getCase(caseId),
        listSubmissions(caseId),
      ]);
      setCaseData(caseRes);
      setSubmissions(subsRes.submissions || []);
    } catch (e) {
      setError("Failed to load case data.");
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdate = async (newStatus: string) => {
    setUpdatingStatus(true);
    try {
      await updateCaseStatus(caseId, newStatus);
      fetchData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to update status.");
    } finally {
      setUpdatingStatus(false);
    }
  };

  if (loading) {
    return (
      <div className="empty-state" style={{ height: "60vh" }}>
        <div className="loading-spinner" />
        Loading case...
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="empty-state" style={{ height: "60vh" }}>
        <AlertTriangle size={40} className="empty-state-icon" />
        <div>{error || "Case not found"}</div>
        <button className="btn btn-outline" onClick={() => router.back()}>
          Go Back
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* Back Button */}
      <button
        className="btn btn-outline"
        style={{ marginBottom: "1.5rem" }}
        onClick={() => router.back()}
      >
        <ArrowLeft size={16} />
        Back to Cases
      </button>

      {/* Case Header */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: "1rem",
          }}
        >
          <div style={{ flex: 1 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                marginBottom: "0.5rem",
              }}
            >
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: "1rem",
                  color: "var(--primary)",
                  fontWeight: 600,
                }}
              >
                {caseData.case_reference}
              </span>
              <span
                className={`badge ${
                  CASE_STATUS_BG[
                    caseData.status as keyof typeof CASE_STATUS_BG
                  ] || ""
                }`}
              >
                {caseData.status}
              </span>
              <span
                className="badge"
                style={{
                  background: "rgba(100,116,139,0.15)",
                  color: "var(--muted)",
                }}
              >
                {caseData.classification}
              </span>
            </div>
            <h1
              style={{
                fontSize: "1.375rem",
                fontWeight: 700,
                marginBottom: "0.5rem",
              }}
            >
              {caseData.case_title}
            </h1>
            {caseData.description && (
              <p
                style={{
                  color: "var(--muted)",
                  fontSize: "0.875rem",
                  lineHeight: 1.6,
                }}
              >
                {caseData.description}
              </p>
            )}
          </div>

          {/* Status Actions */}
          <div style={{ display: "flex", gap: "0.5rem", flexShrink: 0 }}>
            {caseData.status === "OPEN" && (
              <button
                className="btn btn-outline"
                onClick={() => handleStatusUpdate("UNDER_ANALYSIS")}
                disabled={updatingStatus}
              >
                Start Analysis
              </button>
            )}
            {caseData.status === "UNDER_ANALYSIS" && (
              <button
                className="btn btn-outline"
                onClick={() => handleStatusUpdate("PENDING_REVIEW")}
                disabled={updatingStatus}
              >
                Mark for Review
              </button>
            )}
            {caseData.status === "PENDING_REVIEW" && (
              <button
                className="btn btn-outline"
                onClick={() => handleStatusUpdate("CLOSED")}
                disabled={updatingStatus}
              >
                Close Case
              </button>
            )}
            <Link
              href={`/dashboard/submit?case_id=${caseId}`}
              className="btn btn-primary"
            >
              <Upload size={16} />
              Submit Evidence
            </Link>
          </div>
        </div>

        <div className="divider" />

        {/* Case Metadata Grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "1rem",
          }}
        >
          <div>
            <div className="stat-label">Lead Investigator</div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                marginTop: 4,
              }}
            >
              <User size={14} color="var(--muted)" />
              <span style={{ fontSize: "0.9375rem", fontWeight: 500 }}>
                {caseData.lead_investigator_name}
              </span>
            </div>
          </div>
          <div>
            <div className="stat-label">Jurisdiction</div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                marginTop: 4,
              }}
            >
              <Shield size={14} color="var(--muted)" />
              <span style={{ fontSize: "0.9375rem" }}>
                {caseData.jurisdiction}
              </span>
            </div>
          </div>
          <div>
            <div className="stat-label">Opened</div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                marginTop: 4,
              }}
            >
              <Calendar size={14} color="var(--muted)" />
              <span style={{ fontSize: "0.9375rem" }}>
                {formatDate(caseData.created_at)}
              </span>
            </div>
          </div>
          {caseData.applicable_law && (
            <div style={{ gridColumn: "1 / -1" }}>
              <div className="stat-label">Applicable Law</div>
              <div style={{ fontSize: "0.875rem", marginTop: 4 }}>
                {caseData.applicable_law}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Evidence Submissions */}
      <div className="card">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "1rem",
          }}
        >
          <h2 className="section-title" style={{ margin: 0 }}>
            Evidence Submissions ({submissions.length})
          </h2>
          <Link
            href={`/dashboard/submit?case_id=${caseId}`}
            className="btn btn-primary"
            style={{ fontSize: "0.8125rem", padding: "0.375rem 0.875rem" }}
          >
            <Upload size={14} />
            Submit File
          </Link>
        </div>

        {submissions.length === 0 ? (
          <div className="empty-state">
            <FileSearch size={40} className="empty-state-icon" />
            <div>No evidence submitted yet</div>
            <Link
              href={`/dashboard/submit?case_id=${caseId}`}
              className="btn btn-primary"
            >
              Submit First File
            </Link>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>SHA-256</th>
                  <th>Hex Analysis</th>
                  <th>AI Analysis</th>
                  <th>Submitted</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {submissions.map((sub) => (
                  <tr key={sub.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>
                        {sub.original_filename}
                      </div>
                      {sub.mime_type_detected &&
                        sub.mime_type_detected !== sub.mime_type_declared && (
                          <div
                            style={{
                              fontSize: "0.75rem",
                              color: "var(--warning)",
                              marginTop: 2,
                            }}
                          >
                            MIME mismatch detected
                          </div>
                        )}
                    </td>
                    <td style={{ color: "var(--muted)" }}>
                      {formatFileSize(sub.file_size_bytes)}
                    </td>
                    <td>
                      <span className="hash-text">
                        {truncateHash(sub.sha256_hash)}
                      </span>
                    </td>
                    <td>
                      {sub.hex_analysis_complete ? (
                        <CheckCircle size={16} color="var(--success)" />
                      ) : (
                        <Clock size={16} color="var(--muted)" />
                      )}
                    </td>
                    <td>
                      {sub.ai_analysis_complete ? (
                        <CheckCircle size={16} color="var(--success)" />
                      ) : (
                        <Clock size={16} color="var(--muted)" />
                      )}
                    </td>
                    <td style={{ color: "var(--muted)", fontSize: "0.8125rem" }}>
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
                        Analyze
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