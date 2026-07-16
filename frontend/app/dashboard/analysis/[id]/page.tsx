// =============================================================================
// HexShield AI — Analysis Detail Page
// =============================================================================

"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Shield,
  Cpu,
  FileText,
  AlertTriangle,
  CheckCircle,
  Clock,
  Download,
  Hash,
  Activity,
} from "lucide-react";
import {
  getSubmission,
  triggerHexAnalysis,
  triggerAIAnalysis,
  getHexResults,
  getAIResults,
  getCustodyChain,
  generateReport,
  getReportDownloadUrl,
  listReports,
} from "@/services/api";
import {
  RISK_LEVEL_BG,
  AI_VERDICT_BG,
  ENTROPY_VERDICT_BG,
  formatDate,
  formatFileSize,
  truncateHash,
} from "@/types";

export default function AnalysisDetailPage() {
  const params = useParams();
  const router = useRouter();
  const submissionId = params.id as string;

  const [submission, setSubmission] = useState<any>(null);
  const [hexResults, setHexResults] = useState<any>(null);
  const [aiResults, setAIResults] = useState<any>(null);
  const [custody, setCustody] = useState<any>(null);
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [runningHex, setRunningHex] = useState(false);
  const [runningAI, setRunningAI] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [actionError, setActionError] = useState("");
  const [actionSuccess, setActionSuccess] = useState("");

  useEffect(() => {
    fetchAll();
  }, [submissionId]);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const sub = await getSubmission(submissionId);
      setSubmission(sub);

      const [hexRes, aiRes, custodyRes, reportsRes] = await Promise.allSettled([
        getHexResults(submissionId),
        getAIResults(submissionId),
        getCustodyChain(submissionId),
        listReports(sub.case_id),
      ]);

      if (hexRes.status === "fulfilled") setHexResults(hexRes.value);
      if (aiRes.status === "fulfilled") setAIResults(aiRes.value);
      if (custodyRes.status === "fulfilled") setCustody(custodyRes.value);
      if (reportsRes.status === "fulfilled")
        setReports(reportsRes.value.reports || []);
    } catch (e) {
      setError("Failed to load submission data.");
    } finally {
      setLoading(false);
    }
  };

  const handleHexAnalysis = async () => {
    setRunningHex(true);
    setActionError("");
    setActionSuccess("");
    try {
      await triggerHexAnalysis(submissionId);
      setActionSuccess("Hex triage analysis completed successfully.");
      fetchAll();
    } catch (e: any) {
      setActionError(e?.response?.data?.detail || "Hex analysis failed.");
    } finally {
      setRunningHex(false);
    }
  };

  const handleAIAnalysis = async () => {
    setRunningAI(true);
    setActionError("");
    setActionSuccess("");
    try {
      await triggerAIAnalysis(submissionId);
      setActionSuccess("AI deepfake analysis completed successfully.");
      fetchAll();
    } catch (e: any) {
      setActionError(e?.response?.data?.detail || "AI analysis failed.");
    } finally {
      setRunningAI(false);
    }
  };

  const handleGenerateReport = async (format: "JSON" | "PDF") => {
    setGeneratingReport(true);
    setActionError("");
    setActionSuccess("");
    try {
      console.log("Generating report for submission:", submissionId, "format:", format);
      // Typecast the returned object to any to resolve Vercel build typecheck errors
      const res = (await generateReport(submissionId, format)) as any;
      console.log("Report generated:", res);
      setActionSuccess(
        `${format} report generated successfully. File: ${res.report_filename}`
      );
      fetchAll();
    } catch (e: any) {
      console.error("Report generation error:", e);
      setActionError(
        e?.response?.data?.detail ||
        e?.message ||
        "Report generation failed. Check console for details."
      );
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="empty-state" style={{ height: "60vh" }}>
        <div className="loading-spinner" />
        Loading analysis...
      </div>
    );
  }

  if (error || !submission) {
    return (
      <div className="empty-state" style={{ height: "60vh" }}>
        <AlertTriangle size={40} className="empty-state-icon" />
        <div>{error || "Submission not found"}</div>
        <button className="btn btn-outline" onClick={() => router.back()}>
          Go Back
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* Back */}
      <button
        className="btn btn-outline"
        style={{ marginBottom: "1.5rem" }}
        onClick={() => router.back()}
      >
        <ArrowLeft size={16} />
        Back
      </button>

      {actionError && (
        <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
          <AlertTriangle size={16} style={{ flexShrink: 0 }} />
          {actionError}
        </div>
      )}
      {actionSuccess && (
        <div className="alert alert-success" style={{ marginBottom: "1rem" }}>
          <CheckCircle size={16} style={{ flexShrink: 0 }} />
          {actionSuccess}
        </div>
      )}

      {/* Evidence Summary */}
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
            Evidence Record
          </h2>
          <span
            style={{
              fontFamily: "monospace",
              fontSize: "0.8125rem",
              color: "var(--muted)",
            }}
          >
            {submission.case_reference}
          </span>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "1rem",
            marginBottom: "1rem",
          }}
        >
          <div>
            <div className="stat-label">Original Filename</div>
            <div style={{ fontWeight: 500, marginTop: 4 }}>
              {submission.original_filename}
            </div>
          </div>
          <div>
            <div className="stat-label">File Size</div>
            <div style={{ marginTop: 4 }}>
              {formatFileSize(submission.file_size_bytes)}
            </div>
          </div>
          <div>
            <div className="stat-label">Ingested</div>
            <div style={{ marginTop: 4 }}>
              {formatDate(submission.ingestion_timestamp)}
            </div>
          </div>
          <div>
            <div className="stat-label">Declared MIME</div>
            <div
              style={{
                marginTop: 4,
                fontFamily: "monospace",
                fontSize: "0.8125rem",
              }}
            >
              {submission.mime_type_declared || "N/A"}
            </div>
          </div>
          <div>
            <div className="stat-label">Detected MIME</div>
            <div
              style={{
                marginTop: 4,
                fontFamily: "monospace",
                fontSize: "0.8125rem",
                color:
                  submission.mime_type_detected &&
                  submission.mime_type_detected !== submission.mime_type_declared
                    ? "var(--warning)"
                    : "inherit",
              }}
            >
              {submission.mime_type_detected || "Pending analysis"}
            </div>
          </div>
          <div>
            <div className="stat-label">Submitted By</div>
            <div style={{ marginTop: 4 }}>{submission.submitted_by_name}</div>
          </div>
        </div>

        <div>
          <div className="stat-label">SHA-256 Hash</div>
          <div className="hash-text" style={{ marginTop: 4 }}>
            {submission.sha256_hash}
          </div>
        </div>
      </div>

      {/* Analysis Actions */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Hex Analysis */}
        <div className="card">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.75rem",
              marginBottom: "0.75rem",
            }}
          >
            <Shield size={20} color="var(--primary)" />
            <h3 style={{ fontWeight: 600 }}>Layer 1: Hex Triage</h3>
            {submission.hex_analysis_complete && (
              <CheckCircle size={16} color="var(--success)" />
            )}
          </div>

          {hexResults ? (
            <div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  marginBottom: "0.5rem",
                }}
              >
                <span
                  className={`badge ${
                    RISK_LEVEL_BG[
                      hexResults.overall_risk_level as keyof typeof RISK_LEVEL_BG
                    ] || ""
                  }`}
                >
                  {hexResults.overall_risk_level}
                </span>
                <span
                  className={`badge ${
                    ENTROPY_VERDICT_BG[
                      hexResults.entropy_verdict as keyof typeof ENTROPY_VERDICT_BG
                    ] || ""
                  }`}
                >
                  Entropy: {hexResults.entropy_verdict}
                </span>
              </div>
              <div
                style={{
                  fontSize: "0.8125rem",
                  color: "var(--muted)",
                  marginBottom: "0.5rem",
                }}
              >
                Shannon Entropy:{" "}
                <strong style={{ color: "var(--foreground)" }}>
                  {hexResults.shannon_entropy?.toFixed(6)}
                </strong>
              </div>
              {hexResults.mime_spoof_detected && (
                <div
                  className="alert alert-warning"
                  style={{ padding: "0.5rem 0.75rem", fontSize: "0.8125rem" }}
                >
                  <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                  MIME Spoofing Detected
                </div>
              )}
              <div
                style={{
                  fontSize: "0.75rem",
                  color: "var(--muted)",
                  marginTop: "0.5rem",
                }}
              >
                Engine v{hexResults.engine_version} •{" "}
                {formatDate(hexResults.analyzed_at)}
              </div>
            </div>
          ) : (
            <div>
              <p
                style={{
                  fontSize: "0.875rem",
                  color: "var(--muted)",
                  marginBottom: "0.75rem",
                }}
              >
                Analyzes magic bytes, Shannon Entropy, and MIME spoofing.
              </p>
              <button
                className="btn btn-primary"
                onClick={handleHexAnalysis}
                disabled={runningHex}
                style={{ width: "100%" }}
              >
                {runningHex ? (
                  <>
                    <div className="loading-spinner" />
                    Running...
                  </>
                ) : (
                  <>
                    <Shield size={15} />
                    Run Hex Triage
                  </>
                )}
              </button>
            </div>
          )}
        </div>

        {/* AI Analysis */}
        <div className="card">
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.75rem",
              marginBottom: "0.75rem",
            }}
          >
            <Cpu size={20} color="var(--secondary)" />
            <h3 style={{ fontWeight: 600 }}>Layer 2: AI Deepfake</h3>
            {submission.ai_analysis_complete && (
              <CheckCircle size={16} color="var(--success)" />
            )}
          </div>

          {aiResults ? (
            <div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  marginBottom: "0.5rem",
                }}
              >
                <span
                  className={`badge ${
                    AI_VERDICT_BG[
                      aiResults.verdict as keyof typeof AI_VERDICT_BG
                    ] || ""
                  }`}
                >
                  {aiResults.verdict}
                </span>
                <span
                  className="badge"
                  style={{
                    background: "rgba(100,116,139,0.15)",
                    color: "var(--muted)",
                  }}
                >
                  {aiResults.media_type}
                </span>
              </div>
              <div
                style={{ fontSize: "0.8125rem", color: "var(--muted)" }}
              >
                Authenticity:{" "}
                <strong style={{ color: "var(--foreground)" }}>
                  {(aiResults.authenticity_score * 100).toFixed(1)}%
                </strong>
              </div>
              <div
                style={{ fontSize: "0.8125rem", color: "var(--muted)" }}
              >
                Manipulation:{" "}
                <strong style={{ color: "var(--foreground)" }}>
                  {(aiResults.manipulation_confidence * 100).toFixed(1)}%
                </strong>
              </div>
              <div
                style={{
                  fontSize: "0.75rem",
                  color: "var(--muted)",
                  marginTop: "0.5rem",
                }}
              >
                {aiResults.model_name} v{aiResults.model_version}
              </div>
            </div>
          ) : (
            <div>
              <p
                style={{
                  fontSize: "0.875rem",
                  color: "var(--muted)",
                  marginBottom: "0.75rem",
                }}
              >
                Detects deepfake manipulation in images, video, and audio.
              </p>
              <button
                className="btn btn-primary"
                onClick={handleAIAnalysis}
                disabled={runningAI}
                style={{
                  width: "100%",
                  background: "var(--secondary)",
                }}
              >
                {runningAI ? (
                  <>
                    <div className="loading-spinner" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Cpu size={15} />
                    Run AI Analysis
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Report Generation */}
      {(submission.hex_analysis_complete ||
        submission.ai_analysis_complete) && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <h2 className="section-title">Generate Forensic Report</h2>
          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              className="btn btn-outline"
              onClick={() => handleGenerateReport("JSON")}
              disabled={generatingReport}
            >
              {generatingReport ? (
                <div className="loading-spinner" />
              ) : (
                <FileText size={15} />
              )}
              Generate JSON Report
            </button>
            <button
              className="btn btn-outline"
              onClick={() => handleGenerateReport("PDF")}
              disabled={generatingReport}
            >
              {generatingReport ? (
                <div className="loading-spinner" />
              ) : (
                <FileText size={15} />
              )}
              Generate PDF Report
            </button>
          </div>

          {/* Existing Reports */}
          {reports.length > 0 && (
            <div style={{ marginTop: "1rem" }}>
              <div
                className="stat-label"
                style={{ marginBottom: "0.5rem" }}
              >
                Generated Reports
              </div>
              {reports.map((r) => (
                <div
                  key={r.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.625rem 0",
                    borderBottom: "1px solid var(--card-border)",
                  }}
                >
                  <div>
                    <span
                      style={{
                        fontSize: "0.8125rem",
                        fontFamily: "monospace",
                      }}
                    >
                      {r.report_filename}
                    </span>
                    <div
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--muted)",
                        marginTop: 2,
                      }}
                    >
                      {r.report_format} • {formatDate(r.generated_at)}
                    </div>
                  </div>
                  
                    <button
                    className="btn btn-outline"
                    onClick={() => window.open(getReportDownloadUrl(r.id), "_blank")}
                  >
                    <Download size={13} />
                    Download
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Chain of Custody */}
      {custody && custody.custody_chain?.length > 0 && (
        <div className="card">
          <h2 className="section-title">
            Chain of Custody ({custody.total_events} events)
          </h2>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {custody.custody_chain.map((event: any) => (
              <div
                key={event.id}
                style={{
                  padding: "0.875rem",
                  background: "var(--background)",
                  borderRadius: 8,
                  border: "1px solid var(--card-border)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: "0.375rem",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "0.5rem",
                    }}
                  >
                    <span
                      style={{
                        fontWeight: 600,
                        color: "var(--primary)",
                        fontSize: "0.8125rem",
                      }}
                    >
                      #{event.event_sequence}
                    </span>
                    <span
                      className="badge"
                      style={{
                        background: "rgba(59,130,246,0.1)",
                        color: "var(--primary)",
                      }}
                    >
                      {event.event_type}
                    </span>
                    {event.hash_verified && (
                      <CheckCircle size={14} color="var(--success)" />
                    )}
                  </div>
                  <span
                    style={{
                      fontSize: "0.75rem",
                      color: "var(--muted)",
                    }}
                  >
                    {formatDate(event.event_timestamp)}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: "0.8125rem",
                    color: "var(--foreground)",
                    marginBottom: "0.375rem",
                    lineHeight: 1.5,
                  }}
                >
                  {event.event_description}
                </div>
                <div
                  style={{
                    fontSize: "0.75rem",
                    color: "var(--muted)",
                  }}
                >
                  {event.actor_name}
                  {event.actor_badge && ` • Badge: ${event.actor_badge}`}
                  {" • "}
                  <span className="hash-text">
                    {truncateHash(event.hash_at_event || "", 12)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}