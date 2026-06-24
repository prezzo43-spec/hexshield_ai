# =============================================================================
# HexShield AI — Cases Router
# Handles forensic case management endpoints.
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
import uuid
from datetime import datetime

from app.database import get_db

router = APIRouter()


@router.get("/cases")
def list_cases(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    List all forensic cases.
    Optionally filter by status (OPEN, CLOSED, etc.)
    """
    if status_filter:
        result = db.execute(
            text("""
                SELECT
                    c.id,
                    c.case_reference,
                    c.case_title,
                    c.status,
                    c.classification,
                    c.jurisdiction,
                    c.incident_date,
                    c.created_at,
                    i.full_name AS lead_investigator_name
                FROM cases c
                JOIN investigators i ON c.lead_investigator_id = i.id
                WHERE c.status = :status
                ORDER BY c.created_at DESC
            """),
            {"status": status_filter.upper()},
        )
    else:
        result = db.execute(
            text("""
                SELECT
                    c.id,
                    c.case_reference,
                    c.case_title,
                    c.status,
                    c.classification,
                    c.jurisdiction,
                    c.incident_date,
                    c.created_at,
                    i.full_name AS lead_investigator_name
                FROM cases c
                JOIN investigators i ON c.lead_investigator_id = i.id
                ORDER BY c.created_at DESC
            """)
        )

    rows = result.mappings().all()
    return {
        "total": len(rows),
        "cases": [dict(row) for row in rows],
    }


@router.get("/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    """
    Retrieve a single case by ID including submission count.
    """
    result = db.execute(
        text("""
            SELECT
                c.id,
                c.case_reference,
                c.case_title,
                c.description,
                c.status,
                c.classification,
                c.jurisdiction,
                c.applicable_law,
                c.court_reference,
                c.incident_location,
                c.incident_date,
                c.created_at,
                c.closed_at,
                i.full_name AS lead_investigator_name,
                i.email AS lead_investigator_email,
                COUNT(fs.id) AS total_submissions
            FROM cases c
            JOIN investigators i ON c.lead_investigator_id = i.id
            LEFT JOIN file_submissions fs ON fs.case_id = c.id
            WHERE c.id = :id
            GROUP BY c.id, i.full_name, i.email
        """),
        {"id": case_id},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found.",
        )
    return dict(row)


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(payload: dict, db: Session = Depends(get_db)):
    """
    Open a new forensic case.
    """
    required_fields = [
        "case_reference",
        "case_title",
        "lead_investigator_id",
    ]
    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required field: {field}",
            )

    # Verify case reference is unique
    existing = db.execute(
        text("SELECT id FROM cases WHERE case_reference = :ref"),
        {"ref": payload["case_reference"]},
    ).fetchone()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case reference '{payload['case_reference']}' already exists.",
        )

    # Verify lead investigator exists
    investigator = db.execute(
        text("SELECT id FROM investigators WHERE id = :id AND is_active = TRUE"),
        {"id": payload["lead_investigator_id"]},
    ).fetchone()
    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {payload['lead_investigator_id']} not found or inactive.",
        )

    case_id = str(uuid.uuid4())

    db.execute(
        text("""
            INSERT INTO cases (
                id,
                case_reference,
                case_title,
                description,
                status,
                classification,
                jurisdiction,
                applicable_law,
                lead_investigator_id,
                incident_location,
                incident_date
            ) VALUES (
                :id,
                :case_reference,
                :case_title,
                :description,
                :status,
                :classification,
                :jurisdiction,
                :applicable_law,
                :lead_investigator_id,
                :incident_location,
                :incident_date
            )
        """),
        {
            "id": case_id,
            "case_reference": payload["case_reference"],
            "case_title": payload["case_title"],
            "description": payload.get("description"),
            "status": payload.get("status", "OPEN"),
            "classification": payload.get("classification", "CONFIDENTIAL"),
            "jurisdiction": payload.get("jurisdiction", "Republic of Kenya"),
            "applicable_law": payload.get("applicable_law"),
            "lead_investigator_id": payload["lead_investigator_id"],
            "incident_location": payload.get("incident_location"),
            "incident_date": payload.get("incident_date"),
        },
    )
    db.commit()

    return {
        "message": "Case opened successfully.",
        "case_id": case_id,
        "case_reference": payload["case_reference"],
    }


@router.patch("/cases/{case_id}/status")
def update_case_status(
    case_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    """
    Update the status of a forensic case.
    """
    valid_statuses = [
        "OPEN",
        "UNDER_ANALYSIS",
        "PENDING_REVIEW",
        "CLOSED",
        "ARCHIVED",
        "REFERRED",
    ]

    new_status = payload.get("status", "").upper()
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status. Must be one of: {valid_statuses}",
        )

    # Check case exists
    result = db.execute(
        text("SELECT id FROM cases WHERE id = :id"),
        {"id": case_id},
    )
    if not result.fetchone():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found.",
        )

    closed_at = datetime.utcnow() if new_status == "CLOSED" else None

    db.execute(
        text("""
            UPDATE cases
            SET status = :status,
                closed_at = :closed_at
            WHERE id = :id
        """),
        {
            "status": new_status,
            "closed_at": closed_at,
            "id": case_id,
        },
    )
    db.commit()

    return {
        "message": f"Case status updated to {new_status}.",
        "case_id": case_id,
        "new_status": new_status,
    }