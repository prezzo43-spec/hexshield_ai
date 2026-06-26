# =============================================================================
# HexShield AI — Reports Router
# Layer 3: Forensic Preservation and Reporting Module
#
# Handles forensic report generation and retrieval endpoints.
# Supports JSON (machine-readable) and PDF (court-ready) formats.
# =============================================================================

import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.services.forensic_reporting import (
    ForensicReportAssembler,
    JSONReportGenerator,
    PDFReportGenerator,
    ensure_reports_dir,
)

router = APIRouter()


# =============================================================================
# HELPER — Fetch all data needed for report generation
# =============================================================================

def _fetch_report_data(submission_id: str, db: Session) -> dict:
    """
    Fetch all database records needed to generate a forensic report.
    Returns a dict of all rows or raises HTTPException if missing.
    """
    # Submission
    submission = db.execute(
        text("""
            SELECT
                fs.id,
                fs.case_id,
                fs.original_filename,
                fs.file_size_bytes,
                fs.sha256_hash,
                fs.sha512_hash,
                fs.mime_type_declared,
                fs.mime_type_detected,
                fs.storage_path,
                fs.submitted_by,
                fs.ingestion_timestamp,
                fs.hex_analysis_complete,
                fs.ai_analysis_complete
            FROM file_submissions fs
            WHERE fs.id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    if not submission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    # Case
    case = db.execute(
        text("""
            SELECT
                id, case_reference, case_title, classification,
                jurisdiction, applicable_law, lead_investigator_id
            FROM cases
            WHERE id = :id
        """),
        {"id": submission["case_id"]},
    ).mappings().first()

    # Lead investigator
    investigator = db.execute(
        text("""
            SELECT id, full_name, email, organization,
                   badge_number, role
            FROM investigators
            WHERE id = :id
        """),
        {"id": case["lead_investigator_id"]},
    ).mappings().first()

    # Submitter
    submitter = db.execute(
        text("""
            SELECT id, full_name, email, organization,
                   badge_number, role
            FROM investigators
            WHERE id = :id
        """),
        {"id": submission["submitted_by"]},
    ).mappings().first()

    # Hex analysis results
    hex_row = db.execute(
        text("""
            SELECT
                h.id,
                h.shannon_entropy,
                h.entropy_verdict,
                h.mime_spoof_detected,
                h.mime_spoof_details,
                h.overall_risk_level,
                h.risk_summary,
                h.magic_bytes_extracted,
                h.suspicious_sections_json,
                h.engine_version,
                h.analyzed_at,
                COALESCE(m.format_name, 'Unknown') AS file_format_identified,
                COALESCE(m.threat_relevance::text, 'UNKNOWN') AS threat_relevance
            FROM hex_analysis_results h
            LEFT JOIN magic_byte_signatures m
                ON h.matched_signature_id = m.id
            WHERE h.submission_id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    # AI analysis results
    ai_row = db.execute(
        text("""
            SELECT
                id,
                media_type,
                verdict,
                authenticity_score,
                manipulation_confidence,
                model_name,
                model_version,
                processing_duration_ms,
                analyzed_at
            FROM ai_media_analysis_results
            WHERE submission_id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    # Chain of custody
    custody_rows = db.execute(
        text("""
            SELECT
                c.event_sequence,
                c.event_type,
                c.event_description,
                c.hash_at_event,
                c.hash_verified,
                c.notes,
                c.event_timestamp,
                i.full_name AS actor_name,
                i.badge_number AS actor_badge,
                c.actor_role
            FROM chain_of_custody_events c
            JOIN investigators i ON c.actor_id = i.id
            WHERE c.submission_id = :id
            ORDER BY c.event_sequence ASC
        """),
        {"id": submission_id},
    ).mappings().all()

    return {
        "submission": dict(submission),
        "case": dict(case),
        "investigator": dict(investigator),
        "submitter": dict(submitter),
        "hex_row": dict(hex_row) if hex_row else None,
        "ai_row": dict(ai_row) if ai_row else None,
        "custody_rows": [dict(r) for r in custody_rows],
    }


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post(
    "/submissions/{submission_id}/reports",
    status_code=status.HTTP_201_CREATED,
)
def generate_report(
    submission_id: str,
    report_format: str = Query(
        default="JSON",
        description="Report format: JSON or PDF",
    ),
    examiner_notes: Optional[str] = Query(
        default=None,
        description="Optional examiner notes to include in the report",
    ),
    db: Session = Depends(get_db),
):
    """
    Generate a forensic report for a file submission.

    Supports JSON (machine-readable) and PDF (court-ready) formats.
    The report hash is stored in the database for integrity verification.
    """
    report_format = report_format.upper()
    if report_format not in ("JSON", "PDF"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="report_format must be JSON or PDF.",
        )

    # Fetch all data
    data = _fetch_report_data(submission_id, db)

    # Check at least one analysis has been performed
    if not data["submission"]["hex_analysis_complete"] and \
       not data["submission"]["ai_analysis_complete"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "No analysis has been performed on this submission. "
                "Run hex analysis and/or AI analysis before generating a report."
            ),
        )

    # Assemble report data
    report_data = ForensicReportAssembler.assemble(
        submission_row=data["submission"],
        case_row=data["case"],
        investigator_row=data["investigator"],
        submitter_row=data["submitter"],
        hex_row=data["hex_row"],
        ai_row=data["ai_row"],
        custody_rows=data["custody_rows"],
        report_type="FULL_FORENSIC",
        examiner_notes=examiner_notes,
    )

    # Generate report
    try:
        if report_format == "JSON":
            generator = JSONReportGenerator()
        else:
            generator = PDFReportGenerator()

        report_bytes, report_filename, report_hash = generator.generate(
            report_data
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )

    # Persist report record to database
    report_id = report_data.report_id
    storage_path = str(
        ensure_reports_dir() / report_filename
    )

    db.execute(
        text("""
            INSERT INTO forensic_reports (
                id,
                submission_id,
                case_id,
                report_type,
                report_format,
                report_filename,
                storage_path,
                file_size_bytes,
                report_hash,
                generated_by,
                covers_hex_analysis,
                covers_ai_analysis,
                covers_chain_of_custody
            ) VALUES (
                :id,
                :submission_id,
                :case_id,
                :report_type,
                :report_format,
                :report_filename,
                :storage_path,
                :file_size_bytes,
                :report_hash,
                :generated_by,
                :covers_hex,
                :covers_ai,
                :covers_custody
            )
        """),
        {
            "id": report_id,
            "submission_id": submission_id,
            "case_id": data["submission"]["case_id"],
            "report_type": "FULL_FORENSIC",
            "report_format": report_format,
            "report_filename": report_filename,
            "storage_path": storage_path,
            "file_size_bytes": len(report_bytes),
            "report_hash": report_hash,
            "generated_by": data["submission"]["submitted_by"],
            "covers_hex": data["submission"]["hex_analysis_complete"],
            "covers_ai": data["submission"]["ai_analysis_complete"],
            "covers_custody": True,
        },
    )

    # Update submission flag
    db.execute(
        text("""
            UPDATE file_submissions
            SET report_generated = TRUE
            WHERE id = :id
        """),
        {"id": submission_id},
    )

    db.commit()

    return {
        "message": f"{report_format} forensic report generated successfully.",
        "report_id": report_id,
        "report_filename": report_filename,
        "report_format": report_format,
        "file_size_bytes": len(report_bytes),
        "report_hash": report_hash,
        "report_hash_algorithm": "SHA-256",
        "download_url": f"/api/v1/reports/{report_id}/download",
        "submission_id": submission_id,
    }


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """
    Download a generated forensic report file.
    Verifies the file hash before serving.
    """
    report = db.execute(
        text("""
            SELECT
                id,
                report_filename,
                storage_path,
                report_format,
                report_hash
            FROM forensic_reports
            WHERE id = :id
        """),
        {"id": report_id},
    ).mappings().first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found.",
        )

    report_path = Path(report["storage_path"])
    if not report_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found on storage.",
        )

    # Verify hash before serving
    from app.services.forensic_reporting import compute_report_hash
    current_hash = compute_report_hash(report_path.read_bytes())
    if current_hash != report["report_hash"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Report integrity check failed. "
                "The report file hash does not match the stored hash. "
                "This report may have been tampered with."
            ),
        )

    media_type = (
        "application/pdf"
        if report["report_format"] == "PDF"
        else "application/json"
    )

    return FileResponse(
        path=str(report_path),
        filename=report["report_filename"],
        media_type=media_type,
    )


@router.get("/cases/{case_id}/reports")
def list_case_reports(case_id: str, db: Session = Depends(get_db)):
    """
    List all forensic reports generated for a case.
    """
    case = db.execute(
        text("SELECT id FROM cases WHERE id = :id"),
        {"id": case_id},
    ).fetchone()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found.",
        )

    result = db.execute(
        text("""
            SELECT
                r.id,
                r.report_type,
                r.report_format,
                r.report_filename,
                r.report_hash,
                r.file_size_bytes,
                r.is_court_ready,
                r.covers_hex_analysis,
                r.covers_ai_analysis,
                r.covers_chain_of_custody,
                r.generated_at,
                i.full_name AS generated_by_name
            FROM forensic_reports r
            JOIN investigators i ON r.generated_by = i.id
            WHERE r.case_id = :case_id
            ORDER BY r.generated_at DESC
        """),
        {"case_id": case_id},
    )

    rows = result.mappings().all()

    return {
        "case_id": case_id,
        "total": len(rows),
        "reports": [dict(row) for row in rows],
    }


@router.get("/reports/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    """
    Retrieve metadata for a single forensic report.
    """
    result = db.execute(
        text("""
            SELECT
                r.id,
                r.case_id,
                r.submission_id,
                r.report_type,
                r.report_format,
                r.report_filename,
                r.file_size_bytes,
                r.report_hash,
                r.report_hash_algorithm,
                r.is_court_ready,
                r.covers_hex_analysis,
                r.covers_ai_analysis,
                r.covers_chain_of_custody,
                r.generation_notes,
                r.generated_at,
                r.reviewed_at,
                r.court_ready_at,
                i.full_name AS generated_by_name,
                c.case_reference
            FROM forensic_reports r
            JOIN investigators i ON r.generated_by = i.id
            JOIN cases c ON r.case_id = c.id
            WHERE r.id = :id
        """),
        {"id": report_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found.",
        )

    return dict(result)


@router.patch("/reports/{report_id}/certify")
def certify_court_ready(
    report_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    """
    Certify a report as court-ready.
    Must be performed by a senior investigator.
    Once certified, the report hash is the legal baseline.
    """
    report = db.execute(
        text("SELECT id, is_court_ready FROM forensic_reports WHERE id = :id"),
        {"id": report_id},
    ).mappings().first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found.",
        )

    if report["is_court_ready"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report is already certified as court-ready.",
        )

    certifier_id = payload.get("certifier_id")
    if not certifier_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="certifier_id is required.",
        )

    certifier = db.execute(
        text("""
            SELECT id, role FROM investigators
            WHERE id = :id AND is_active = TRUE
        """),
        {"id": certifier_id},
    ).mappings().first()

    if not certifier:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {certifier_id} not found or inactive.",
        )

    authorized_roles = {
        "SYSTEM_ADMIN",
        "LEAD_INVESTIGATOR",
        "REVIEWING_OFFICER",
        "PROSECUTOR",
    }
    if certifier["role"] not in authorized_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{certifier['role']}' is not authorized to certify "
                f"court-ready reports. Required roles: {authorized_roles}"
            ),
        )

    from datetime import datetime, timezone
    db.execute(
        text("""
            UPDATE forensic_reports
            SET
                is_court_ready = TRUE,
                court_ready_certified_by = :certifier_id,
                court_ready_at = :certified_at
            WHERE id = :id
        """),
        {
            "certifier_id": certifier_id,
            "certified_at": datetime.now(timezone.utc),
            "id": report_id,
        },
    )
    db.commit()

    return {
        "message": "Report certified as court-ready.",
        "report_id": report_id,
        "certified_by": certifier_id,
        "is_court_ready": True,
    }