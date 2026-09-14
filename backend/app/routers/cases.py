# app/routers/cases.py
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.schemas.requests import CaseCreatePayload, CaseStatusUpdatePayload
from app.routers.auth import get_auth_investigator, require_role

router = APIRouter(prefix="/cases", tags=["Forensic Cases"])

def log_system_event(db: Session, request: Request, category: str, action: str, description: str, investigator_id: str = None, success: bool = True, error_message: str = None, status_code: int = 200):
    """Logs administrative mutations directly to the system_audit_log table."""
    try:
        db.execute(
            text("""
                INSERT INTO system_audit_log (
                    event_category, event_action, event_description, investigator_id,
                    ip_address, user_agent, success, error_message, http_method,
                    endpoint_path, response_status_code
                ) VALUES (
                    :category, :action, :description, :investigator_id,
                    :ip, :ua, :success, :error_message, :method, :path, :status_code
                )
            """),
            {
                "category": category,
                "action": action,
                "description": description,
                "investigator_id": investigator_id,
                "ip": request.client.host if request.client else "UNKNOWN",
                "ua": request.headers.get("user-agent", "UNKNOWN"),
                "success": success,
                "error_message": error_message,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code
            }
        )
        db.commit()
    except Exception:
        db.rollback()  # Protect execution state if audit tracking fails

@router.post("", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreatePayload,
    request: Request,
    db: Session = Depends(get_db),
    current_investigator: dict = Depends(
        require_role("LEAD_INVESTIGATOR", "FORENSIC_ANALYST")
    )
):
    """
    Open a new forensic case container. 
    Restricted to System Administrators and Lead Investigators.
    """
    # 1. Enforce Case Reference Uniqueness
    existing_case = db.execute(
        text("SELECT id FROM cases WHERE case_reference = :ref"),
        {"ref": payload.case_reference},
    ).fetchone()
    
    if existing_case:
        error_msg = f"Case reference '{payload.case_reference}' already exists."
        log_system_event(
            db, request, "CASE_MANAGEMENT", "CREATE_CASE_FAILURE", 
            f"Attempted to create duplicate case reference: {payload.case_reference}",
            investigator_id=current_investigator.get("id"), success=False, 
            error_message=error_msg, status_code=409
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=error_msg,
        )

    # 2. Verify Target Lead Investigator Existence and Operational Status
    target_investigator = db.execute(
        text("SELECT id, is_active FROM investigators WHERE id = :id"),
        {"id": current_investigator["id"]},
    ).fetchone()
    
    if not target_investigator:
        error_msg = "The authenticated investigator does not exist."
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_msg)
        
    if not target_investigator.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Cannot assign an inactive investigator as a case lead."
        )

    # 3. Persist Case Entry
    case_id = str(uuid.uuid4())
    try:
        db.execute(
            text("""
                INSERT INTO cases (
                    id, case_reference, case_title, description, status,
                    classification, jurisdiction, applicable_law,
                    lead_investigator_id, incident_location, incident_date, created_at
                ) VALUES (
                    :id, :case_reference, :case_title, :description, :status,
                    :classification, :jurisdiction, :applicable_law,
                    :lead_investigator_id, :incident_location, :incident_date, :created_at
                )
            """),
            {
                "id": case_id,
                "case_reference": payload.case_reference,
                "case_title": payload.case_title,
                "description": payload.description,
                "status": payload.status.upper(),
                "classification": payload.classification.upper(),
                "jurisdiction": payload.jurisdiction,
                "applicable_law": payload.applicable_law,
                "lead_investigator_id": current_investigator["id"],
                "incident_location": payload.incident_location,
                "incident_date": payload.incident_date,
                "created_at": datetime.utcnow()
            },
        )
        db.commit()
        
        log_system_event(
            db, request, "CASE_MANAGEMENT", "CREATE_CASE_SUCCESS", 
            f"Successfully opened case {payload.case_reference}: '{payload.case_title}'",
            investigator_id=current_investigator.get("id"), status_code=201
        )
        
        return {
            "status": "success",
            "message": "Forensic case environment established.",
            "case_id": case_id,
            "case_reference": payload.case_reference,
        }
        
    except Exception as e:
        db.rollback()
        log_system_event(
            db, request, "CASE_MANAGEMENT", "CREATE_CASE_INTERNAL_ERROR", 
            "Database insertion failure during case instantiation.",
            investigator_id=current_investigator.get("id"), success=False, 
            error_message=str(e), status_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record case data in target repository."
        )

@router.get("", status_code=status.HTTP_200_OK)
def list_cases(
    db: Session = Depends(get_db),
    current_investigator: dict = Depends(get_auth_investigator)
):
    """
    Retrieve all operational forensic cases. Normalizes database rows
    explicitly to ensure accurate client-side browser delivery.
    """
    raw_results = db.execute(
        text("""
            SELECT 
                c.id, c.case_reference, c.case_title, c.description, c.status,
                c.classification, c.jurisdiction, c.applicable_law, c.court_reference,
                c.suspect_reference, c.lead_investigator_id, c.incident_location,
                c.incident_date, c.created_at, c.closed_at,
                i.full_name as lead_investigator_name, i.badge_number 
            FROM cases c
            LEFT JOIN investigators i ON CAST(c.lead_investigator_id AS TEXT) = CAST(i.id AS TEXT)
            WHERE (:is_admin = TRUE OR c.lead_investigator_id = :investigator_id)
            ORDER BY c.created_at DESC
        """),
        {
            "is_admin": current_investigator["role"] == "SYSTEM_ADMIN",
            "investigator_id": current_investigator["id"],
        },
    ).mappings().all()
    
    cases_list = []
    for row in raw_results:
        cases_list.append({
            "id": str(row["id"]),
            "case_reference": row["case_reference"],
            "case_title": row["case_title"],
            "description": row["description"] or "",
            "status": row["status"],
            "classification": row["classification"],
            "jurisdiction": row["jurisdiction"],
            "applicable_law": row["applicable_law"],
            "court_reference": row["court_reference"],
            "suspect_reference": row["suspect_reference"],
            "lead_investigator_id": str(row["lead_investigator_id"]) if row["lead_investigator_id"] else None,
            "incident_location": row["incident_location"] or "",
            "incident_date": str(row["incident_date"]) if row["incident_date"] else None,
            "created_at": str(row["created_at"]),
            "closed_at": str(row["closed_at"]) if row["closed_at"] else None,
            "lead_investigator_name": row["lead_investigator_name"],
            "badge_number": row["badge_number"]
        })
    
    return {"status": "success", "count": len(cases_list), "data": cases_list}

@router.get("/{case_id}", status_code=status.HTTP_200_OK)
def get_case_by_id(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_investigator: dict = Depends(get_auth_investigator)
):
    """
    Fetch granular details for a specific case including associated file metadata summaries.
    """
    row = db.execute(
        text("""
            SELECT c.*, i.full_name as lead_investigator_name, i.badge_number
            FROM cases c
            LEFT JOIN investigators i ON CAST(c.lead_investigator_id AS TEXT) = CAST(i.id AS TEXT)
            WHERE c.id = :id
              AND (:is_admin = TRUE OR c.lead_investigator_id = :investigator_id)
        """),
        {
            "id": str(case_id),
            "is_admin": current_investigator["role"] == "SYSTEM_ADMIN",
            "investigator_id": current_investigator["id"],
        }
    ).mappings().fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic case context with ID '{case_id}' not found."
        )

    # Clean the single case structure mapping explicitly
    normalized_case = {
        "id": str(row["id"]),
        "case_reference": row["case_reference"],
        "case_title": row["case_title"],
        "description": row["description"] or "",
        "status": row["status"],
        "classification": row["classification"],
        "jurisdiction": row["jurisdiction"],
        "applicable_law": row["applicable_law"],
        "court_reference": row["court_reference"],
        "suspect_reference": row["suspect_reference"],
        "lead_investigator_id": str(row["lead_investigator_id"]) if row["lead_investigator_id"] else None,
        "incident_location": row["incident_location"] or "",
        "incident_date": str(row["incident_date"]) if row["incident_date"] else None,
        "created_at": str(row["created_at"]),
        "closed_at": str(row["closed_at"]) if row["closed_at"] else None,
        "lead_investigator_name": row["lead_investigator_name"],
        "badge_number": row["badge_number"]
    }

    # Fetch summary of evidence registered inside the case file
    evidence_submissions = db.execute(
        text("""
            SELECT id, original_filename, file_size_bytes, sha256_hash, 
                   hex_analysis_complete, ai_analysis_complete, ingestion_timestamp
            FROM file_submissions
            WHERE case_id = :case_id
            ORDER BY ingestion_timestamp ASC
        """),
        {"case_id": str(case_id)}
    ).mappings().all()

    normalized_evidence = [
        {
            "id": str(e["id"]),
            "original_filename": e["original_filename"],
            "file_size_bytes": e["file_size_bytes"],
            "sha256_hash": e["sha256_hash"],
            "hex_analysis_complete": e["hex_analysis_complete"],
            "ai_analysis_complete": e["ai_analysis_complete"],
            "ingestion_timestamp": str(e["ingestion_timestamp"])
        }
        for e in evidence_submissions
    ]

    return {
        "status": "success",
        "case": normalized_case,
        "evidence_inventory": {
            "total_count": len(normalized_evidence),
            "items": normalized_evidence
        }
    }

@router.patch("/{case_id}/status", status_code=status.HTTP_200_OK)
def update_case_status(
    case_id: uuid.UUID,
    payload: CaseStatusUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
    current_investigator: dict = Depends(
        require_role("LEAD_INVESTIGATOR", "FORENSIC_ANALYST")
    )
):
    """
    Modify operational case status states. Automatically sets closure windows for final verifications.
    """
    case_record = db.execute(
        text("SELECT id, case_reference, status FROM cases WHERE id = :id"),
        {"id": str(case_id)}
    ).fetchone()

    if not case_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target forensic case '{case_id}' does not exist."
        )

    closed_at_value = None
    if payload.status == "CLOSED":
        closed_at_value = datetime.utcnow()

    try:
        db.execute(
            text("""
                UPDATE cases 
                SET status = :status, closed_at = :closed_at 
                WHERE id = :id
            """),
            {
                "status": payload.status,
                "closed_at": closed_at_value,
                "id": str(case_id)
            }
        )
        db.commit()

        log_system_event(
            db, request, "CASE_MANAGEMENT", "UPDATE_CASE_STATUS", 
            f"Case {case_record.case_reference} transition: {case_record.status} -> {payload.status}",
            investigator_id=current_investigator.get("id"), status_code=200
        )

        return {
            "status": "success",
            "message": f"Case processing phase updated to {payload.status}.",
            "case_id": str(case_id),
            "current_status": payload.status
        }
    except Exception as e:
        db.rollback()
        log_system_event(
            db, request, "CASE_MANAGEMENT", "UPDATE_CASE_STATUS_FAILURE", 
            f"Failed transitioning case status state for execution context: {case_id}",
            investigator_id=current_investigator.get("id"), success=False, 
            error_message=str(e), status_code=500
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error writing status state mutations to target table."
        )