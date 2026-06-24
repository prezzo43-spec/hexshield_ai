# =============================================================================
# HexShield AI — Analysis Router
# Handles triggering and retrieving Layer 1 and Layer 2 analysis.
# =============================================================================

import uuid
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.services.hex_engine import HexTriageEngine

router = APIRouter()


# =============================================================================
# LAYER 1 — HEX TRIAGE ANALYSIS
# =============================================================================

@router.post("/submissions/{submission_id}/analyze/hex")
def trigger_hex_analysis(
    submission_id: str,
    db: Session = Depends(get_db),
):
    """
    Trigger Layer 1 hex triage analysis on a submitted file.

    This endpoint:
    1. Retrieves the file submission record
    2. Reads the file from storage
    3. Runs the HexTriageEngine on the file bytes
    4. Persists results to hex_analysis_results table
    5. Updates the submission status flag
    6. Records an ANALYSIS custody event
    """

    # Step 1 — Retrieve submission record
    submission = db.execute(
        text("""
            SELECT
                fs.id,
                fs.case_id,
                fs.original_filename,
                fs.storage_path,
                fs.mime_type_declared,
                fs.sha256_hash,
                fs.hex_analysis_complete,
                fs.submitted_by,
                i.role AS submitter_role,
                i.badge_number AS submitter_badge
            FROM file_submissions fs
            JOIN investigators i ON fs.submitted_by = i.id
            WHERE fs.id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    if not submission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    if submission["hex_analysis_complete"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Hex analysis already completed for submission {submission_id}. "
                f"Retrieve existing results at "
                f"GET /api/v1/submissions/{submission_id}/results/hex"
            ),
        )

    # Step 2 — Verify file exists on storage
    storage_path = Path(submission["storage_path"])
    if not storage_path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Evidence file not found at storage path. "
                f"Storage integrity may be compromised."
            ),
        )

    # Step 3 — Run hex triage engine
    engine = HexTriageEngine()
    result = engine.analyze_file(
        file_path=str(storage_path),
        declared_mime_type=submission["mime_type_declared"],
    )

    # Step 4 — Persist results to database
    analysis_id = str(uuid.uuid4())

    db.execute(
        text("""
            INSERT INTO hex_analysis_results (
                id,
                submission_id,
                shannon_entropy,
                entropy_threshold_used,
                entropy_verdict,
                magic_bytes_extracted,
                mime_spoof_detected,
                mime_spoof_details,
                file_header_valid,
                header_anomalies_detected,
                header_anomaly_details,
                byte_distribution_json,
                suspicious_sections_json,
                overall_risk_level,
                risk_summary,
                analysis_duration_ms,
                engine_version,
                analyzed_by
            ) VALUES (
                :id,
                :submission_id,
                :shannon_entropy,
                :entropy_threshold_used,
                :entropy_verdict,
                :magic_bytes_extracted,
                :mime_spoof_detected,
                :mime_spoof_details,
                :file_header_valid,
                :header_anomalies_detected,
                :header_anomaly_details,
                :byte_distribution_json,
                :suspicious_sections_json,
                :overall_risk_level,
                :risk_summary,
                :analysis_duration_ms,
                :engine_version,
                :analyzed_by
            )
        """),
        {
            "id": analysis_id,
            "submission_id": submission_id,
            "shannon_entropy": result.entropy_result.entropy_value,
            "entropy_threshold_used": result.entropy_result.elevated_threshold,
            "entropy_verdict": result.entropy_result.verdict,
            "magic_bytes_extracted": result.magic_bytes_hex,
            "mime_spoof_detected": result.mime_spoof_detected,
            "mime_spoof_details": result.mime_spoof_details,
            "file_header_valid": result.file_header_valid,
            "header_anomalies_detected": result.header_anomalies_detected,
            "header_anomaly_details": result.header_anomaly_details,
            "byte_distribution_json": json.dumps(result.entropy_result.byte_distribution),
            "suspicious_sections_json": json.dumps(result.suspicious_sections),
            "overall_risk_level": result.overall_risk_level,
            "risk_summary": result.risk_summary,
            "analysis_duration_ms": result.analysis_duration_ms,
            "engine_version": result.engine_version,
            "analyzed_by": submission["submitted_by"],
        },
    )

    # Step 5 — Update mime_type_detected on file_submissions
    db.execute(
        text("""
            UPDATE file_submissions
            SET
                mime_type_detected = :mime_detected,
                hex_analysis_complete = TRUE
            WHERE id = :id
        """),
        {
            "mime_detected": result.mime_type_detected,
            "id": submission_id,
        },
    )

    # Step 6 — Get current custody sequence number
    seq_result = db.execute(
        text("""
            SELECT COALESCE(MAX(event_sequence), 0) + 1 AS next_seq
            FROM chain_of_custody_events
            WHERE submission_id = :submission_id
        """),
        {"submission_id": submission_id},
    ).fetchone()
    next_seq = seq_result[0] if seq_result else 2

    # Step 7 — Record ANALYSIS custody event
    custody_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO chain_of_custody_events (
                id,
                case_id,
                submission_id,
                event_type,
                event_sequence,
                actor_id,
                actor_role,
                actor_badge_number,
                event_description,
                hash_at_event,
                hash_verified,
                notes
            ) VALUES (
                :id,
                :case_id,
                :submission_id,
                'ANALYSIS',
                :event_sequence,
                :actor_id,
                :actor_role,
                :actor_badge_number,
                :event_description,
                :hash_at_event,
                TRUE,
                :notes
            )
        """),
        {
            "id": custody_id,
            "case_id": submission["case_id"],
            "submission_id": submission_id,
            "event_sequence": next_seq,
            "actor_id": submission["submitted_by"],
            "actor_role": submission["submitter_role"],
            "actor_badge_number": submission["submitter_badge"],
            "event_description": (
                f"Layer 1 hex triage analysis completed by HexShield AI Engine "
                f"v{result.engine_version}. "
                f"Risk verdict: {result.overall_risk_level}. "
                f"Shannon Entropy: {result.entropy_result.entropy_value:.4f}. "
                f"MIME spoof detected: {result.mime_spoof_detected}."
            ),
            "hash_at_event": submission["sha256_hash"],
            "notes": result.risk_summary,
        },
    )

    db.commit()

    return {
        "message": "Hex triage analysis completed successfully.",
        "analysis_id": analysis_id,
        "submission_id": submission_id,
        "results": {
            "overall_risk_level": result.overall_risk_level,
            "risk_summary": result.risk_summary,
            "shannon_entropy": result.entropy_result.entropy_value,
            "entropy_verdict": result.entropy_result.verdict,
            "mime_spoof_detected": result.mime_spoof_detected,
            "mime_spoof_details": result.mime_spoof_details,
            "file_format_identified": (
                result.matched_signature.format_name
                if result.matched_signature else "Unknown"
            ),
            "threat_relevance": (
                result.matched_signature.threat_relevance
                if result.matched_signature else "UNKNOWN"
            ),
            "suspicious_sections_count": len(result.suspicious_sections),
            "analysis_duration_ms": result.analysis_duration_ms,
            "engine_version": result.engine_version,
        },
    }


@router.get("/submissions/{submission_id}/results/hex")
def get_hex_analysis_results(
    submission_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve existing hex triage analysis results for a submission.
    """
    result = db.execute(
        text("""
            SELECT
                h.id,
                h.submission_id,
                h.shannon_entropy,
                h.entropy_threshold_used,
                h.entropy_verdict,
                h.magic_bytes_extracted,
                h.mime_spoof_detected,
                h.mime_spoof_details,
                h.file_header_valid,
                h.header_anomalies_detected,
                h.header_anomaly_details,
                h.overall_risk_level,
                h.risk_summary,
                h.suspicious_sections_json,
                h.analysis_duration_ms,
                h.engine_version,
                h.analyzed_at,
                fs.original_filename,
                fs.sha256_hash
            FROM hex_analysis_results h
            JOIN file_submissions fs ON h.submission_id = fs.id
            WHERE h.submission_id = :submission_id
        """),
        {"submission_id": submission_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No hex analysis results found for submission {submission_id}. "
                f"Trigger analysis at POST /api/v1/submissions/{submission_id}/analyze/hex"
            ),
        )

    return dict(result)


# =============================================================================
# LAYER 2 — AI MEDIA ANALYSIS (Stub — implemented in Step 6)
# =============================================================================

@router.post("/submissions/{submission_id}/analyze/ai")
def trigger_ai_analysis(
    submission_id: str,
    db: Session = Depends(get_db),
):
    """
    Trigger Layer 2 AI deepfake detection analysis.
    Full implementation in Step 6.
    """
    submission = db.execute(
        text("SELECT id FROM file_submissions WHERE id = :id"),
        {"id": submission_id},
    ).fetchone()

    if not submission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    return {
        "message": "AI analysis engine is being integrated in Step 6.",
        "submission_id": submission_id,
        "status": "PENDING",
    }


@router.get("/submissions/{submission_id}/custody")
def get_chain_of_custody(
    submission_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve the complete chain of custody for a file submission.
    Returns all custody events in chronological order.
    """
    submission = db.execute(
        text("SELECT id FROM file_submissions WHERE id = :id"),
        {"id": submission_id},
    ).fetchone()

    if not submission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    result = db.execute(
        text("""
            SELECT
                c.id,
                c.event_type,
                c.event_sequence,
                c.event_description,
                c.location_description,
                c.hash_at_event,
                c.hash_verified,
                c.is_verified,
                c.notes,
                c.event_timestamp,
                i.full_name AS actor_name,
                i.badge_number AS actor_badge,
                c.actor_role
            FROM chain_of_custody_events c
            JOIN investigators i ON c.actor_id = i.id
            WHERE c.submission_id = :submission_id
            ORDER BY c.event_sequence ASC
        """),
        {"submission_id": submission_id},
    )

    rows = result.mappings().all()

    return {
        "submission_id": submission_id,
        "total_events": len(rows),
        "custody_chain": [dict(row) for row in rows],
    }