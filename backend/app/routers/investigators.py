# =============================================================================
# HexShield AI — Investigators Router
# Handles investigator account management endpoints.
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List
import uuid

from app.database import get_db

router = APIRouter()


@router.get("/investigators")
def list_investigators(db: Session = Depends(get_db)):
    """
    List all active investigators in the system.
    """
    result = db.execute(
        text("""
            SELECT
                id,
                full_name,
                email,
                badge_number,
                organization,
                department,
                role,
                is_active,
                created_at,
                last_login_at
            FROM investigators
            WHERE is_active = TRUE
            ORDER BY created_at DESC
        """)
    )
    rows = result.mappings().all()
    return {
        "total": len(rows),
        "investigators": [dict(row) for row in rows],
    }


@router.get("/investigators/{investigator_id}")
def get_investigator(investigator_id: str, db: Session = Depends(get_db)):
    """
    Retrieve a single investigator by ID.
    """
    result = db.execute(
        text("""
            SELECT
                id,
                full_name,
                email,
                badge_number,
                organization,
                department,
                role,
                is_active,
                created_at,
                last_login_at
            FROM investigators
            WHERE id = :id
        """),
        {"id": investigator_id},
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {investigator_id} not found.",
        )
    return dict(row)


@router.post("/investigators", status_code=status.HTTP_201_CREATED)
def create_investigator(payload: dict, db: Session = Depends(get_db)):
    """
    Register a new investigator in the system.
    """
    required_fields = ["full_name", "email", "organization", "role"]
    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required field: {field}",
            )

    # Check for duplicate email
    existing = db.execute(
        text("SELECT id FROM investigators WHERE email = :email"),
        {"email": payload["email"]},
    ).fetchone()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An investigator with email '{payload['email']}' already exists.",
        )

    investigator_id = str(uuid.uuid4())

    db.execute(
        text("""
            INSERT INTO investigators (
                id, full_name, email, badge_number,
                organization, department, role
            ) VALUES (
                :id, :full_name, :email, :badge_number,
                :organization, :department, :role
            )
        """),
        {
            "id": investigator_id,
            "full_name": payload["full_name"],
            "email": payload["email"],
            "badge_number": payload.get("badge_number"),
            "organization": payload["organization"],
            "department": payload.get("department"),
            "role": payload["role"],
        },
    )
    db.commit()

    return {
        "message": "Investigator registered successfully.",
        "investigator_id": investigator_id,
    }


@router.patch("/investigators/{investigator_id}/deactivate")
def deactivate_investigator(investigator_id: str, db: Session = Depends(get_db)):
    """
    Deactivate an investigator account.
    Records are never deleted — only deactivated.
    """
    result = db.execute(
        text("SELECT id FROM investigators WHERE id = :id"),
        {"id": investigator_id},
    )
    if not result.fetchone():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {investigator_id} not found.",
        )

    db.execute(
        text("""
            UPDATE investigators
            SET is_active = FALSE
            WHERE id = :id
        """),
        {"id": investigator_id},
    )
    db.commit()

    return {
        "message": "Investigator deactivated successfully.",
        "investigator_id": investigator_id,
    }