// =============================================================================
// HexShield AI — Frontend API Service
// Centralizes all HTTP calls to the FastAPI backend.
// =============================================================================

import axios from "axios";

// 1. Get raw string value from environment or use local fallback
let rawUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// 2. Parse out markdown link formatting [text](url) or clean bracket artifacts if present
if (rawUrl.includes("[")) {
  const match = rawUrl.match(/\((https?:\/\/[^\)]+)\)/);
  if (match && match[1]) {
    rawUrl = match[1];
  } else {
    rawUrl = rawUrl.replace(/[\[\]]/g, "").split("]")[0];
  }
}

// 3. Remove trailing slashes to keep endpoint routing paths clean
const BASE_URL = rawUrl.replace(/\/+$/, "");

export const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 60000,
  withCredentials: true,
});

// =============================================================================
// TYPES
// =============================================================================

export interface Investigator {
  id: string;
  full_name: string;
  email: string;
  badge_number: string | null;
  organization: string;
  department: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface Case {
  id: string;
  case_reference: string;
  case_title: string;
  status: string;
  classification: string;
  jurisdiction: string;
  incident_date: string | null;
  created_at: string;
  lead_investigator_name: string;
  total_submissions?: number;
}

export interface Submission {
  id: string;
  case_id: string;
  original_filename: string;
  file_extension: string | null;
  file_size_bytes: number;
  mime_type_declared: string | null;
  mime_type_detected: string | null;
  sha256_hash: string;
  hex_analysis_complete: boolean;
  ai_analysis_complete: boolean;
  report_generated: boolean;
  ingestion_timestamp: string;
  submitted_by_name: string;
}

export interface HexAnalysisResult {
  id: string;
  submission_id: string;
  shannon_entropy: number;
  entropy_verdict: string;
  mime_spoof_detected: boolean;
  mime_spoof_details: string | null;
  overall_risk_level: string;
  risk_summary: string;
  magic_bytes_extracted: string;
  file_header_valid: boolean;
  header_anomalies_detected: boolean;
  engine_version: string;
  analyzed_at: string;
  original_filename: string;
  sha256_hash: string;
}

export interface AIAnalysisResult {
  id: string;
  submission_id: string;
  media_type: string;
  verdict: string;
  authenticity_score: number;
  manipulation_confidence: number;
  model_name: string;
  model_version: string;
  processing_duration_ms: number | null;
  analyzed_at: string;
  original_filename: string;
}

export interface CustodyEvent {
  id: string;
  event_type: string;
  event_sequence: number;
  event_description: string;
  hash_at_event: string;
  hash_verified: boolean;
  is_verified: boolean;
  notes: string | null;
  event_timestamp: string;
  actor_name: string;
  actor_badge: string | null;
  actor_role: string;
}

export interface ForensicReport {
  id: string;
  report_type: string;
  report_format: string;
  report_filename: string;
  report_hash: string;
  file_size_bytes: number;
  is_court_ready: boolean;
  generated_at: string;
  generated_by_name: string;
}

// =============================================================================
// API FUNCTIONS
// =============================================================================

// Health
export const checkHealth = () =>
  api.get("/api/health").then((r) => r.data);

export const checkDetailedHealth = () =>
  api.get("/api/health/detailed").then((r) => r.data);

// Investigators
export const listInvestigators = () =>
  api.get("/api/v1/investigators").then((r) => r.data);

export const getInvestigator = (id: string) =>
  api.get(`/api/v1/investigators/${id}`).then((r) => r.data);

export const createInvestigator = (data: Record<string, unknown>) =>
  api.post("/api/v1/investigators", data).then((r) => r.data);

// Cases
export const listCases = (status?: string) =>
  api
    .get("/api/v1/cases", { params: status ? { status_filter: status } : {} })
    .then((r) => r.data);

export const getCase = (id: string) =>
  api.get(`/api/v1/cases/${id}`).then((r) => r.data);

export const createCase = (data: Record<string, unknown>) =>
  api.post("/api/v1/cases", data).then((r) => r.data);

export const updateCaseStatus = (id: string, status: string) =>
  api.patch(`/api/v1/cases/${id}/status`, { status }).then((r) => r.data);

// Submissions
export const listSubmissions = (caseId: string) =>
  api.get(`/api/v1/cases/${caseId}/submissions`).then((r) => r.data);

export const getSubmission = (id: string) =>
  api.get(`/api/v1/submissions/${id}`).then((r) => r.data);

export const submitFile = (
  caseId: string,
  formData: FormData
) =>
  api
    .post(`/api/v1/cases/${caseId}/submissions`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    })
    .then((r) => r.data);

// Analysis
export const triggerHexAnalysis = (submissionId: string) =>
  api
    .post(`/api/v1/submissions/${submissionId}/analyze/hex`)
    .then((r) => r.data);

export const triggerAIAnalysis = (submissionId: string) =>
  api
    .post(`/api/v1/submissions/${submissionId}/analyze/ai`)
    .then((r) => r.data);

export const getHexResults = (submissionId: string) =>
  api
    .get(`/api/v1/submissions/${submissionId}/results/hex`)
    .then((r) => r.data);

export const getAIResults = (submissionId: string) =>
  api
    .get(`/api/v1/submissions/${submissionId}/results/ai`)
    .then((r) => r.data);

export const getCustodyChain = (submissionId: string) =>
  api
    .get(`/api/v1/submissions/${submissionId}/custody`)
    .then((r) => r.data);

// Reports
export const generateReport = (
  submissionId: string,
  format: "JSON" | "PDF",
  examinerNotes?: string
): Promise<{ report_id: string; status: string }> => {
  const params = new URLSearchParams({
        report_format: format,
    ...(examinerNotes && { examiner_notes: examinerNotes }),
  });
  return fetch(`${BASE_URL}/api/v1/submissions/${submissionId}/reports?${params}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  }).then(async (res) => {
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  });
};

export const fetchReport = (
  reportId: string
): Promise<{ report_id: string; report_generated: boolean }> => {
  return fetch(`${BASE_URL}/api/v1/reports/${reportId}`).then(async (res) => {
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    const data = await res.json();
    return {
      report_id: reportId,
      report_generated: data.report_generated || false,
    };
  });
};
export const listReports = (caseId: string) =>
  api.get(`/api/v1/cases/${caseId}/reports`).then((r) => r.data);

export const getReportDownloadUrl = (reportId: string) =>
  `${BASE_URL}/api/v1/reports/${reportId}/download`;

