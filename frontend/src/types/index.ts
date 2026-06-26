// =============================================================================
// HexShield AI — Shared TypeScript Types
// =============================================================================

export type RiskLevel = "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN";
export type EntropyVerdict = "NORMAL" | "ELEVATED" | "CRITICAL";
export type AIVerdict = "AUTHENTIC" | "SUSPICIOUS" | "MANIPULATED" | "INCONCLUSIVE";
export type CaseStatus = "OPEN" | "UNDER_ANALYSIS" | "PENDING_REVIEW" | "CLOSED" | "ARCHIVED" | "REFERRED";
export type CaseClassification = "UNCLASSIFIED" | "CONFIDENTIAL" | "RESTRICTED" | "TOP_SECRET";
export type InvestigatorRole = "SYSTEM_ADMIN" | "LEAD_INVESTIGATOR" | "FORENSIC_ANALYST" | "REVIEWING_OFFICER" | "PROSECUTOR" | "RESEARCHER" | "READ_ONLY";
export type MediaType = "IMAGE" | "VIDEO" | "AUDIO" | "UNKNOWN";
export type ReportFormat = "JSON" | "PDF";
export type CustodyEventType = "ACQUISITION" | "TRANSFER" | "ANALYSIS" | "STORAGE" | "EXPORT" | "VERIFICATION" | "DUPLICATION" | "DISPOSITION";

export const RISK_LEVEL_COLORS: Record<RiskLevel, string> = {
  CLEAN:      "text-green-600",
  SUSPICIOUS: "text-yellow-600",
  MALICIOUS:  "text-red-600",
  UNKNOWN:    "text-gray-500",
};

export const RISK_LEVEL_BG: Record<RiskLevel, string> = {
  CLEAN:      "bg-green-100 text-green-800",
  SUSPICIOUS: "bg-yellow-100 text-yellow-800",
  MALICIOUS:  "bg-red-100 text-red-800",
  UNKNOWN:    "bg-gray-100 text-gray-800",
};

export const AI_VERDICT_BG: Record<AIVerdict, string> = {
  AUTHENTIC:    "bg-green-100 text-green-800",
  SUSPICIOUS:   "bg-yellow-100 text-yellow-800",
  MANIPULATED:  "bg-red-100 text-red-800",
  INCONCLUSIVE: "bg-gray-100 text-gray-800",
};

export const CASE_STATUS_BG: Record<CaseStatus, string> = {
  OPEN:           "bg-blue-100 text-blue-800",
  UNDER_ANALYSIS: "bg-purple-100 text-purple-800",
  PENDING_REVIEW: "bg-yellow-100 text-yellow-800",
  CLOSED:         "bg-gray-100 text-gray-800",
  ARCHIVED:       "bg-gray-100 text-gray-500",
  REFERRED:       "bg-orange-100 text-orange-800",
};

export const ENTROPY_VERDICT_BG: Record<EntropyVerdict, string> = {
  NORMAL:   "bg-green-100 text-green-800",
  ELEVATED: "bg-yellow-100 text-yellow-800",
  CRITICAL: "bg-red-100 text-red-800",
};

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString("en-KE", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncateHash(hash: string, chars: number = 16): string {
  return `${hash.slice(0, chars)}...`;
}