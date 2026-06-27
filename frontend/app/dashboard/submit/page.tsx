// =============================================================================
// HexShield AI — Submit Evidence Page
// =============================================================================

"use client";

import { useEffect, useState, useRef } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  Upload,
  FileText,
  Shield,
  AlertTriangle,
  CheckCircle,
  Hash,
} from "lucide-react";
import { listCases, listInvestigators, submitFile } from "@/services/api";
import { formatFileSize } from "@/types";

export default function SubmitEvidencePage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const fileRef = useRef<HTMLInputElement>(null);

  const preselectedCaseId = searchParams.get("case_id") || "";

  const [cases, setCases] = useState<any[]>([]);
  const [investigators, setInvestigators] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<any>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [form, setForm] = useState({
    case_id: preselectedCaseId,
    submitted_by: "",
    source_description: "",
    submission_notes: "",
  });

  useEffect(() => {
    Promise.all([listCases(), listInvestigators()])
      .then(([casesData, investData]) => {
        setCases(casesData.cases || []);
        setInvestigators(investData.investigators || []);
      })
      .finally(() => setLoading(false));
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setSelectedFile(file);
  };

  const handleSubmit = async () => {
    setError("");
    setResult(null);

    if (!form.case_id) {
      setError("Please select a case.");
      return;
    }
    if (!form.submitted_by) {
      setError("Please select the submitting investigator.");
      return;
    }
    if (!selectedFile) {
      setError("Please select a file to submit.");
      return;
    }

    setSubmitting(true);
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("submitted_by", form.submitted_by);
      if (form.source_description) {
        formData.append("source_description", form.source_description);
      }
      if (form.submission_notes) {
        formData.append("submission_notes", form.submission_notes);
      }

      const res = await submitFile(form.case_id, formData);
      setResult(res);
      setSelectedFile(null);
      if (fileRef.current) fileRef.current.value = "";
    } catch (e: any) {
      setError(e?.response?.data?.detail || "File submission failed.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="empty-state" style={{ height: "60vh" }}>
        <div className="loading-spinner" />
        Loading...
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 720 }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Submit Evidence</h1>
          <p className="page-subtitle">
            Securely ingest digital evidence for forensic analysis
          </p>
        </div>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: "1rem" }}>
          <AlertTriangle size={16} style={{ flexShrink: 0 }} />
          {error}
        </div>
      )}

      {/* Success Result */}
      {result && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.75rem",
              marginBottom: "1rem",
            }}
          >
            <CheckCircle size={22} color="var(--success)" />
            <h2
              style={{
                fontSize: "1.0625rem",
                fontWeight: 600,
                color: "var(--success)",
              }}
            >
              Evidence Submitted Successfully
            </h2>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "0.75rem",
              fontSize: "0.875rem",
            }}
          >
            <div>
              <div className="stat-label">Submission ID</div>
              <div
                style={{
                  fontFamily: "monospace",
                  fontSize: "0.8125rem",
                  marginTop: 2,
                }}
              >
                {result.submission_id}
              </div>
            </div>
            <div>
              <div className="stat-label">Case Reference</div>
              <div style={{ fontWeight: 500, marginTop: 2 }}>
                {result.case_reference}
              </div>
            </div>
            <div>
              <div className="stat-label">Original Filename</div>
              <div style={{ marginTop: 2 }}>{result.original_filename}</div>
            </div>
            <div>
              <div className="stat-label">File Size</div>
              <div style={{ marginTop: 2 }}>
                {formatFileSize(result.file_size_bytes)}
              </div>
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <div className="stat-label">SHA-256 Hash (Integrity Baseline)</div>
              <div className="hash-text" style={{ marginTop: 4 }}>
                {result.sha256_hash}
              </div>
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <div className="stat-label">SHA-512 Hash</div>
              <div className="hash-text" style={{ marginTop: 4 }}>
                {result.sha512_hash}
              </div>
            </div>
          </div>

          <div className="divider" />

          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button
              className="btn btn-primary"
              onClick={() =>
                router.push(`/dashboard/analysis/${result.submission_id}`)
              }
            >
              <Shield size={16} />
              Run Analysis
            </button>
            <button
              className="btn btn-outline"
              onClick={() => setResult(null)}
            >
              Submit Another File
            </button>
          </div>
        </div>
      )}

      {/* Submission Form */}
      {!result && (
        <div className="card">
          <h2 className="section-title">Evidence Submission Form</h2>

          <div className="form-row">
            <div className="form-group">
              <label className="label">Forensic Case *</label>
              <select
                className="input"
                value={form.case_id}
                onChange={(e) =>
                  setForm({ ...form, case_id: e.target.value })
                }
              >
                <option value="">Select case...</option>
                {cases
                  .filter((c) => !["CLOSED", "ARCHIVED"].includes(c.status))
                  .map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.case_reference} — {c.case_title}
                    </option>
                  ))}
              </select>
            </div>
            <div className="form-group">
              <label className="label">Submitting Investigator *</label>
              <select
                className="input"
                value={form.submitted_by}
                onChange={(e) =>
                  setForm({ ...form, submitted_by: e.target.value })
                }
              >
                <option value="">Select investigator...</option>
                {investigators.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.full_name} — {inv.badge_number || inv.role}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* File Upload */}
          <div className="form-group">
            <label className="label">Evidence File *</label>
            <div
              style={{
                border: "2px dashed var(--card-border)",
                borderRadius: 8,
                padding: "2rem",
                textAlign: "center",
                cursor: "pointer",
                transition: "border-color 0.15s",
              }}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const file = e.dataTransfer.files?.[0];
                if (file) setSelectedFile(file);
              }}
            >
              <input
                ref={fileRef}
                type="file"
                style={{ display: "none" }}
                onChange={handleFileChange}
              />
              {selectedFile ? (
                <div>
                  <FileText
                    size={32}
                    color="var(--primary)"
                    style={{ margin: "0 auto 0.5rem" }}
                  />
                  <div style={{ fontWeight: 500 }}>{selectedFile.name}</div>
                  <div
                    style={{
                      fontSize: "0.8125rem",
                      color: "var(--muted)",
                      marginTop: 4,
                    }}
                  >
                    {formatFileSize(selectedFile.size)}
                  </div>
                </div>
              ) : (
                <div>
                  <Upload
                    size={32}
                    color="var(--muted)"
                    style={{ margin: "0 auto 0.5rem" }}
                  />
                  <div style={{ fontWeight: 500, color: "var(--foreground)" }}>
                    Click to select or drag and drop
                  </div>
                  <div
                    style={{
                      fontSize: "0.8125rem",
                      color: "var(--muted)",
                      marginTop: 4,
                    }}
                  >
                    Maximum file size: 500 MB
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="form-group">
            <label className="label">Source Description</label>
            <input
              className="input"
              placeholder="e.g. Seized from suspect laptop during search and seizure"
              value={form.source_description}
              onChange={(e) =>
                setForm({ ...form, source_description: e.target.value })
              }
            />
          </div>

          <div className="form-group">
            <label className="label">Submission Notes</label>
            <textarea
              className="input"
              rows={3}
              placeholder="Any additional notes about this evidence item"
              value={form.submission_notes}
              onChange={(e) =>
                setForm({ ...form, submission_notes: e.target.value })
              }
              style={{ resize: "vertical" }}
            />
          </div>

          {/* ISO Notice */}
          <div
            className="alert alert-warning"
            style={{ marginBottom: "1rem" }}
          >
            <Shield size={16} style={{ flexShrink: 0, marginTop: 1 }} />
            <div style={{ fontSize: "0.8125rem" }}>
              SHA-256 and SHA-512 hashes are computed immediately at ingestion
              and form the cryptographic integrity baseline for this evidence
              item under ISO/IEC 27037 standards. An ACQUISITION custody event
              is recorded automatically.
            </div>
          </div>

          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={submitting}
            style={{ width: "100%" }}
          >
            {submitting ? (
              <>
                <div className="loading-spinner" />
                Submitting and computing hashes...
              </>
            ) : (
              <>
                <Upload size={16} />
                Submit Evidence File
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}