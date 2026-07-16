# =============================================================================
# HexShield AI — Forensic Report Generator (Pydantic Dataclasses Patch)
# Layer 3: Forensic Preservation and Reporting Module
# =============================================================================

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# CHANGE: Import dataclass from pydantic instead of standard library
from pydantic.dataclasses import dataclass
from dataclasses import field

from app.config import settings

logger = logging.getLogger(__name__)

# =============================================================================
# REPORT DATA CLASSES (Now natively serializable by FastAPI!)
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