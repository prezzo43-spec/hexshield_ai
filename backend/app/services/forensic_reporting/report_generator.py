# =============================================================================
# HexShield AI — Forensic Report Generator
# Layer 3: Forensic Preservation and Reporting Module
#
# Generates court-ready forensic reports from analysis results.
# Supports JSON (machine-readable) and PDF (court submission) formats.
#
# Compliance:
#   - ISO/IEC 27037 Digital Evidence Standards
#   - Computer Misuse and Cybercrimes Act, 2018 (Kenya)
# =============================================================================

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Native Pydantic serialization support
from pydantic.dataclasses import dataclass
from dataclasses import field

from app.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# REPORT DATA CLASSES
# =============================================================================

@dataclass
class InvestigatorInfo:
    id: str
    full_name: str
    email: str
    organization: str
    badge_number: Optional[str]
    role: str


@dataclass
class CaseInfo:
    id: str
    case_reference: str
    case_title: str
    jurisdiction: str
    applicable_law: Optional[str]
    classification: str
    lead_investigator: InvestigatorInfo


@dataclass
class SubmissionInfo:
    id: str
    original_filename: str
    file_size_bytes: int
    sha256_hash: str
    sha512_hash: str
    mime_type_declared: Optional[str]
    mime_type_detected: Optional[str]
    ingestion_timestamp: str
    submitted_by: InvestigatorInfo


@dataclass
class HexAnalysisSummary:
    analysis_id: str
    shannon_entropy: float
    entropy_verdict: str
    mime_spoof_detected: bool
    mime_spoof_details: Optional[str]
    file_format_identified: str
    threat_relevance: str
    overall_risk_level: str
    risk_summary: str
    magic_bytes_extracted: str
    suspicious_sections_count: int
    engine_version: str
    analyzed_at: str


@dataclass
class AIAnalysisSummary:
    analysis_id: str
    media_type: str
    verdict: str
    authenticity_score: float
    manipulation_confidence: float
    model_name: str
    model_version: str
    processing_duration_ms: Optional[int]
    analyzed_at: str


@dataclass
class CustodyEvent:
    event_sequence: int
    event_type: str
    event_description: str
    actor_name: str
    actor_badge: Optional[str]
    actor_role: str
    hash_at_event: Optional[str]
    hash_verified: Optional[bool]
    event_timestamp: str
    notes: Optional[str]


@dataclass
class ForensicReportData:
    """
    Complete data package for forensic report generation.
    Assembled from database records before rendering.
    """
    report_id: str
    report_type: str
    generated_at: str
    issuing_authority: str
    jurisdiction: str

    case: CaseInfo
    submission: SubmissionInfo
    hex_analysis: Optional[HexAnalysisSummary] = None
    ai_analysis: Optional[AIAnalysisSummary] = None
    custody_chain: List[CustodyEvent] = field(default_factory=list)

    examiner_notes: Optional[str] = None
    additional_findings: List[str] = field(default_factory=list)


# =============================================================================
# REPORT ASSEMBLER
# =============================================================================

class ForensicReportAssembler:
    """
    Assembles ForensicReportData from database query results.
    Separates data collection from report rendering.
    """

    @staticmethod
    def assemble(
        submission_row: Dict,
        case_row: Dict,
        investigator_row: Dict,
        submitter_row: Dict,
        hex_row: Optional[Dict],
        ai_row: Optional[Dict],
        custody_rows: List[Dict],
        report_type: str = "FULL_FORENSIC",
        examiner_notes: Optional[str] = None,
    ) -> ForensicReportData:
        """
        Assemble a ForensicReportData object from database rows.
        """

        lead_investigator = InvestigatorInfo(
            id=str(investigator_row["id"]),
            full_name=investigator_row["full_name"],
            email=investigator_row["email"],
            organization=investigator_row["organization"],
            badge_number=investigator_row.get("badge_number"),
            role=investigator_row["role"],
        )

        submitter = InvestigatorInfo(
            id=str(submitter_row["id"]),
            full_name=submitter_row["full_name"],
            email=submitter_row["email"],
            organization=submitter_row["organization"],
            badge_number=submitter_row.get("badge_number"),
            role=submitter_row["role"],
        )

        case = CaseInfo(
            id=str(case_row["id"]),
            case_reference=case_row["case_reference"],
            case_title=case_row["case_title"],
            jurisdiction=case_row["jurisdiction"],
            applicable_law=case_row.get("applicable_law"),
            classification=case_row["classification"],
            lead_investigator=lead_investigator,
        )

        submission = SubmissionInfo(
            id=str(submission_row["id"]),
            original_filename=submission_row["original_filename"],
            file_size_bytes=submission_row["file_size_bytes"],
            sha256_hash=submission_row["sha256_hash"],
            sha512_hash=submission_row["sha512_hash"],
            mime_type_declared=submission_row.get("mime_type_declared"),
            mime_type_detected=submission_row.get("mime_type_detected"),
            ingestion_timestamp=str(submission_row["ingestion_timestamp"]),
            submitted_by=submitter,
        )

        hex_summary = None
        if hex_row:
            hex_summary = HexAnalysisSummary(
                analysis_id=str(hex_row["id"]),
                shannon_entropy=float(hex_row["shannon_entropy"]),
                entropy_verdict=hex_row["entropy_verdict"],
                mime_spoof_detected=bool(hex_row["mime_spoof_detected"]),
                mime_spoof_details=hex_row.get("mime_spoof_details"),
                file_format_identified=hex_row.get(
                    "file_format_identified", "Unknown"
                ),
                threat_relevance=hex_row.get("threat_relevance", "UNKNOWN"),
                overall_risk_level=hex_row["overall_risk_level"],
                risk_summary=hex_row["risk_summary"],
                magic_bytes_extracted=hex_row["magic_bytes_extracted"],
                suspicious_sections_count=len(
                    hex_row.get("suspicious_sections_json") or []
                ),
                engine_version=hex_row["engine_version"],
                analyzed_at=str(hex_row["analyzed_at"]),
            )

        ai_summary = None
        if ai_row:
            ai_summary = AIAnalysisSummary(
                analysis_id=str(ai_row["id"]),
                media_type=ai_row["media_type"],
                verdict=ai_row["verdict"],
                authenticity_score=float(ai_row["authenticity_score"]),
                manipulation_confidence=float(
                    ai_row["manipulation_confidence"]
                ),
                model_name=ai_row["model_name"],
                model_version=ai_row["model_version"],
                processing_duration_ms=ai_row.get("processing_duration_ms"),
                analyzed_at=str(ai_row["analyzed_at"]),
            )

        custody_events = [
            CustodyEvent(
                event_sequence=row["event_sequence"],
                event_type=row["event_type"],
                event_description=row["event_description"],
                actor_name=row["actor_name"],
                actor_badge=row.get("actor_badge"),
                actor_role=row["actor_role"],
                hash_at_event=row.get("hash_at_event"),
                hash_verified=row.get("hash_verified"),
                event_timestamp=str(row["event_timestamp"]),
                notes=row.get("notes"),
            )
            for row in custody_rows
        ]

        return ForensicReportData(
            report_id=str(uuid.uuid4()),
            report_type=report_type,
            generated_at=datetime.now(timezone.utc).isoformat(),
            issuing_authority=settings.REPORT_ISSUING_AUTHORITY,
            jurisdiction=settings.REPORT_JURISDICTION,
            case=case,
            submission=submission,
            hex_analysis=hex_summary,
            ai_analysis=ai_summary,
            custody_chain=custody_events,
            examiner_notes=examiner_notes,
        )


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def compute_report_hash(report_content: bytes) -> str:
    """Compute SHA-256 hash of report file content."""
    return hashlib.sha256(report_content).hexdigest()


def ensure_reports_dir() -> Path:
    """Ensure the reports storage directory exists."""
    reports_dir = Path(settings.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def ensure_report_filepath(report_filename: str) -> Path:
    """
    Given a report filename recursively resolves and creates all parent 
    directories inside the storage path.
    """
    base_dir = ensure_reports_dir()
    full_path = base_dir / report_filename
    full_path.parent.mkdir(parents=True, exist_ok=True)
    return full_path


def determine_overall_verdict(
    hex_risk: Optional[str],
    ai_verdict: Optional[str],
) -> str:
    """
    Determine the combined forensic verdict from both analysis layers.
    """
    if hex_risk == "MALICIOUS" or ai_verdict == "MANIPULATED":
        return "MALICIOUS"
    elif hex_risk == "SUSPICIOUS" or ai_verdict == "SUSPICIOUS":
        return "SUSPICIOUS"
    elif hex_risk == "CLEAN" and ai_verdict == "AUTHENTIC":
        return "CLEAN"
    elif hex_risk == "CLEAN" and ai_verdict is None:
        return "CLEAN"
    elif hex_risk is None and ai_verdict == "AUTHENTIC":
        return "AUTHENTIC"
    else:
        return "INCONCLUSIVE"