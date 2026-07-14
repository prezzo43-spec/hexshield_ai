# =============================================================================
# HexShield AI — Investigators Router
# Handles investigator account management endpoints.
# Only SYSTEM_ADMIN can create, verify, and manage investigator accounts.
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List
import uuid

from app.database import get_db
from app.services.auth import hash_password, validate_password_strength

router = APIRouter()


@router.get("/investigators")
def list_investigators(db: Session = Depends(get_db)):
    """
    List all investigators in the system.
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
                is_badge_verified,
                first_login,
                failed_login_count,
                locked_until,
                created_at,
                last_login_at,
                last_login_ip
            FROM investigators
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
                is_badge_verified,
                first_login,
                failed_login_count,
                locked_until,
                created_at,
                last_login_at,
                last_login_ip
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
    Admin sets a temporary password. Investigator must change it on first login.
    """
    required_fields = ["full_name", "email", "organization", "role", "temporary_password"]
    for field in required_fields:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required field: {field}",
            )

    # Validate password strength
    valid, msg = validate_password_strength(payload["temporary_password"])
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Temporary password too weak: {msg}",
        )

    # Check for duplicate email
    existing_email = db.execute(
        text("SELECT id FROM investigators WHERE email = :email"),
        {"email": payload["email"]},
    ).fetchone()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An investigator with email '{payload['email']}' already exists.",
        )

    # Check for duplicate badge number
    if payload.get("badge_number"):
        existing_badge = db.execute(
            text("SELECT id FROM investigators WHERE badge_number = :badge"),
            {"badge": payload["badge_number"]},
        ).fetchone()
        if existing_badge:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Badge number '{payload['badge_number']}' is already registered.",
            )

    investigator_id = str(uuid.uuid4())
    password_hash = hash_password(payload["temporary_password"])

    db.execute(
        text("""
            INSERT INTO investigators (
                id, full_name, email, badge_number,
                organization, department, role,
                password_hash, is_badge_verified, first_login,
                is_active
            ) VALUES (
                :id, :full_name, :email, :badge_number,
                :organization, :department, :role,
                :password_hash, :is_badge_verified, False,
                TRUE
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
            "password_hash": password_hash,
            "is_badge_verified": payload.get("is_badge_verified", False),
        },
    )
    db.commit()

    return {
        "message": "Investigator registered successfully.",
        "investigator_id": investigator_id,
        "full_name": payload["full_name"],
        "email": payload["email"],
        "badge_number": payload.get("badge_number"),
        "role": payload["role"],
        "is_badge_verified": payload.get("is_badge_verified", False),
        "first_login": True,
        "credentials_note": (
            "Communicate the temporary password to the investigator "
            "through a secure official channel. They must change it on first login."
        ),
    }


@router.patch("/investigators/{investigator_id}/verify-badge")
def verify_badge(investigator_id: str, db: Session = Depends(get_db)):
    """
    Mark an investigator's badge as verified by the Republic of Kenya.
    Required before the investigator can log in.
    """
    result = db.execute(
        text("SELECT id, full_name, badge_number FROM investigators WHERE id = :id"),
        {"id": investigator_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {investigator_id} not found.",
        )

    db.execute(
        text("""
            UPDATE investigators
            SET is_badge_verified = TRUE
            WHERE id = :id
        """),
        {"id": investigator_id},
    )
    db.commit()

    return {
        "message": "Badge verified successfully. Investigator can now log in.",
        "investigator_id": investigator_id,
        "full_name": result["full_name"],
        "badge_number": result["badge_number"],
        "is_badge_verified": False,
    }


@router.patch("/investigators/{investigator_id}/reset-password")
def reset_password(
    investigator_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    """
    Admin resets an investigator's password.
    Sets first_login = TRUE so they must change it on next login.
    Also unlocks the account if it was locked.
    """
    new_password = payload.get("new_password", "")
    if not new_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="new_password is required.",
        )

    valid, msg = validate_password_strength(new_password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password too weak: {msg}",
        )

    result = db.execute(
        text("SELECT id, full_name FROM investigators WHERE id = :id"),
        {"id": investigator_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {investigator_id} not found.",
        )

    password_hash = hash_password(new_password)
    db.execute(
        text("""
            UPDATE investigators
            SET
                password_hash = :password_hash,
                first_login = TRUE,
                failed_login_count = 0,
                locked_until = NULL
            WHERE id = :id
        """),
        {"password_hash": password_hash, "id": investigator_id},
    )
    db.commit()

    return {
        "message": "Password reset successfully. Investigator must change it on next login.",
        "investigator_id": investigator_id,
        "full_name": result["full_name"],
        "first_login": True,
    }


@router.patch("/investigators/{investigator_id}/unlock")
def unlock_account(investigator_id: str, db: Session = Depends(get_db)):
    """
    Unlock an investigator account that was locked due to failed login attempts.
    """
    result = db.execute(
        text("SELECT id, full_name FROM investigators WHERE id = :id"),
        {"id": investigator_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {investigator_id} not found.",
        )

    db.execute(
        text("""
            UPDATE investigators
            SET
                failed_login_count = 0,
                locked_until = NULL
            WHERE id = :id
        """),
        {"id": investigator_id},
    )
    db.commit()

    return {
        "message": "Account unlocked successfully.",
        "investigator_id": investigator_id,
        "full_name": result["full_name"],
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


@router.get("/activity-logs")
def get_activity_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """
    Retrieve system activity logs for admin monitoring.
    Shows all login attempts, file submissions, analysis runs and more.
    """
    result = db.execute(
        text("""
            SELECT
                s.id,
                s.event_category,
                s.event_action,
                s.event_description,
                s.ip_address,
                s.success,
                s.error_message,
                s.occurred_at,
                s.http_method,
                s.endpoint_path,
                s.response_status_code,
                i.full_name AS investigator_name,
                i.badge_number,
                i.role
            FROM system_audit_log s
            LEFT JOIN investigators i ON s.investigator_id = i.id
            ORDER BY s.occurred_at DESC
            LIMIT :limit
        """),
        {"limit": limit},
    )
    rows = result.mappings().all()
    return {
        "total": len(rows),
        "logs": [dict(row) for row in rows],
    }