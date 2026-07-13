# =============================================================================
# HexShield AI — Authentication Router
# Handles login, logout, token refresh, and password management.
# =============================================================================

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.services.auth import (
    authenticate_investigator,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_investigator,
    hash_password,
    validate_password_strength,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Cookie names
ACCESS_TOKEN_COOKIE = "hexshield_access_token"
REFRESH_TOKEN_COOKIE = "hexshield_refresh_token"

# Cookie settings
COOKIE_SECURE = False      # Set True in production with HTTPS
COOKIE_HTTPONLY = True     # Cannot be accessed by JavaScript
COOKIE_SAMESITE = "lax"


# =============================================================================
# DEPENDENCY — Get current authenticated investigator
# =============================================================================

def get_auth_investigator(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """
    FastAPI dependency that validates the access token from cookie.
    Use with Depends() on any protected endpoint.
    """
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
        )

    investigator = get_current_investigator(db, token)
    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please log in again.",
        )

    return investigator


def require_role(*allowed_roles: str):
    """
    Role-based access control decorator factory.
    Usage: Depends(require_role("SYSTEM_ADMIN", "LEAD_INVESTIGATOR"))
    """
    def role_checker(
        investigator: dict = Depends(get_auth_investigator),
    ) -> dict:
        if investigator["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied. Required roles: {list(allowed_roles)}. "
                    f"Your role: {investigator['role']}."
                ),
            )
        return investigator
    return role_checker


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/auth/login")
def login(
    payload: dict,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticate an investigator and set httpOnly cookies.

    Accepts badge_number or email + password.
    Returns investigator info and sets:
      - hexshield_access_token (30 min)
      - hexshield_refresh_token (8 hours)
    """
    login_identifier = payload.get("login_identifier", "").strip()
    password = payload.get("password", "")

    if not login_identifier or not password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Badge number/email and password are required.",
        )

    # Capture request metadata for explicit account access audit logging
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    # Authenticate
    investigator, error = authenticate_investigator(
        db=db,
        login_identifier=login_identifier,
        password=password,
        ip_address=client_ip,
    )

    if error:
        logger.warning(
            "Failed login audit: targeted_email=%s client_ip=%s user_agent=%s",
            login_identifier,
            client_ip,
            user_agent,
        )

        # Log failed attempt with the targeted account identifier and client metadata
        db.execute(
            text("""
                INSERT INTO system_audit_log (
                    event_category, event_action, event_description,
                    ip_address, user_agent, success, error_message
                ) VALUES (
                    'AUTH', 'LOGIN_FAILED', :description,
                    :ip, :user_agent, FALSE, :error
                )
            """),
            {
                "description": (
                    f"Failed login attempt for targeted email/account: "
                    f"{login_identifier} client_ip={client_ip} user_agent={user_agent}"
                ),
                "ip": client_ip,
                "user_agent": user_agent,
                "error": error,
            },
        )
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error,
        )

    # Create tokens
    token_data = {
        "sub": str(investigator["id"]),
        "role": investigator["role"],
        "badge": investigator.get("badge_number"),
        "name": investigator["full_name"],
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Set httpOnly cookies
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        httponly=COOKIE_HTTPONLY,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=30 * 60,  # 30 minutes
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        httponly=COOKIE_HTTPONLY,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=8 * 60 * 60,  # 8 hours
    )

    logger.info(
        "Successful login audit: investigator_id=%s full_name=%s role=%s client_ip=%s user_agent=%s",
        investigator["id"],
        investigator["full_name"],
        investigator["role"],
        client_ip,
        user_agent,
    )

    # Log successful login with explicit account access metadata
    db.execute(
        text("""
            INSERT INTO system_audit_log (
                event_category, event_action, event_description,
                investigator_id, ip_address, user_agent, success
            ) VALUES (
                'AUTH', 'LOGIN_SUCCESS', :description,
                :investigator_id, :ip, :user_agent, TRUE
            )
        """),
        {
            "description": (
                f"Successful login: investigator_id={investigator['id']} "
                f"full_name={investigator['full_name']} role={investigator['role']} "
                f"client_ip={client_ip} user_agent={user_agent}"
            ),
            "investigator_id": str(investigator["id"]),
            "ip": client_ip,
            "user_agent": user_agent,
        },
    )
    db.commit()

    return {
        "message": "Login successful.",
        "investigator": {
            "id": str(investigator["id"]),
            "full_name": investigator["full_name"],
            "email": investigator["email"],
            "badge_number": investigator.get("badge_number"),
            "role": investigator["role"],
            "organization": investigator["organization"],
            "first_login": investigator.get("first_login", False),
        },
    }


@router.post("/auth/logout")
def logout(response: Response, db: Session = Depends(get_db)):
    """
    Log out by clearing authentication cookies.
    """
    response.delete_cookie(ACCESS_TOKEN_COOKIE)
    response.delete_cookie(REFRESH_TOKEN_COOKIE)
    return {"message": "Logged out successfully."}


@router.post("/auth/refresh")
def refresh_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Issue a new access token using the refresh token.
    Called automatically by the frontend when access token expires.
    """
    refresh = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token found. Please log in again.",
        )

    payload = decode_token(refresh)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token. Please log in again.",
        )

    # Verify investigator still exists and is active
    investigator = get_current_investigator(db, refresh)

    # Issue new access token
    token_data = {
        "sub": payload["sub"],
        "role": payload["role"],
        "badge": payload.get("badge"),
        "name": payload.get("name"),
    }
    new_access_token = create_access_token(token_data)

    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=new_access_token,
        httponly=COOKIE_HTTPONLY,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=30 * 60,
    )

    return {"message": "Token refreshed successfully."}


@router.get("/auth/me")
def get_me(
    investigator: dict = Depends(get_auth_investigator),
):
    """
    Return the currently authenticated investigator's profile.
    Used by the frontend to verify session on page load.
    """
    return {
        "id": str(investigator["id"]),
        "full_name": investigator["full_name"],
        "email": investigator["email"],
        "badge_number": investigator.get("badge_number"),
        "role": investigator["role"],
        "organization": investigator["organization"],
        "first_login": investigator.get("first_login", False),
    }


@router.post("/auth/change-password")
def change_password(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    investigator: dict = Depends(get_auth_investigator),
):
    """
    Change password for the currently authenticated investigator.
    Required on first login.
    """
    current_password = payload.get("current_password", "")
    new_password = payload.get("new_password", "")
    confirm_password = payload.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Current password, new password, and confirmation are required.",
        )

    if new_password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="New password and confirmation do not match.",
        )

    # Validate new password strength
    valid, msg = validate_password_strength(new_password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=msg,
        )

    # Verify current password
    result = db.execute(
        text("SELECT password_hash FROM investigators WHERE id = :id"),
        {"id": investigator["id"]},
    ).fetchone()

    from app.services.auth import verify_password
    if not result or not verify_password(current_password, result[0]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    # Update password and clear first_login flag
    new_hash = hash_password(new_password)
    db.execute(
        text("""
            UPDATE investigators
            SET
                password_hash = :password_hash,
                first_login = FALSE
            WHERE id = :id
        """),
        {"password_hash": new_hash, "id": investigator["id"]},
    )

    # Log password change
    client_ip = request.client.host if request.client else "unknown"
    db.execute(
        text("""
            INSERT INTO system_audit_log (
                event_category, event_action, event_description,
                investigator_id, ip_address, success
            ) VALUES (
                'AUTH', 'PASSWORD_CHANGED',
                :description, :id, :ip, TRUE
            )
        """),
        {
            "description": f"Password changed for {investigator['full_name']}",
            "id": investigator["id"],
            "ip": client_ip,
        },
    )
    db.commit()

    return {"message": "Password changed successfully."}