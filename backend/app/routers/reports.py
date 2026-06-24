# =============================================================================
# HexShield AI — Reports Router
# Handles forensic report generation and retrieval endpoints.
# Full implementation in Step 7.
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db

router = APIRouter()


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
                r.is_court_ready,
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
                r.storage_path,
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


@router.post("/submissions/{submission_id}/reports")
def generate_report(
    submission_id: str,
    db: Session = Depends(get_db),
):
    """
    Generate a forensic report for a file submission.
    Full implementation in Step 7.
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
        "message": "Forensic report generation is being implemented in Step 7.",
        "submission_id": submission_id,
        "status": "PENDING",
    }