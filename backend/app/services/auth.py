# =============================================================================
# HexShield AI — Authentication Service
# Handles password hashing, JWT token generation, and session management.
# Security standard: CJIS AAL2 compliant
# =============================================================================

import hashlib
import secrets
import logging
import string
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.config import settings

logger = logging.getLogger(__name__)

# =============================================================================
# PASSWORD HASHING
# bcrypt with 12 rounds — CJIS compliant
# =============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_HOURS = 8


def hash_password(password: str) -> str:
    """Hash a plain text password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforce CJIS-compliant password requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."


def generate_temporary_password(length: int = 16) -> str:
    """
    Generate a CJIS-friendly temporary password for new investigator setup.
    """
    alphabet = (
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
        + "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    )

    for _ in range(20):
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        valid, _ = validate_password_strength(password)
        if valid:
            return password

    return "TempPass!2026Secure"


# =============================================================================
# JWT TOKEN MANAGEMENT
# =============================================================================

def create_access_token(data: dict) -> str:
    """
    Create a short-lived JWT access token (30 minutes).
    Contains investigator ID, role, and badge number.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({
        "exp": expire,
        "type": "access",
        "iat": datetime.now(timezone.utc),
    })
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def create_refresh_token(data: dict) -> str:
    """
    Create a longer-lived JWT refresh token (8 hours — one work shift).
    Used to obtain new access tokens without re-logging in.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        hours=REFRESH_TOKEN_EXPIRE_HOURS
    )
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
    })
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT token.
    Returns the payload dict or None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        return None


# =============================================================================
# ACCOUNT LOCKOUT
# =============================================================================

def is_account_locked(investigator: dict) -> bool:
    """Check if an investigator account is currently locked."""
    if investigator.get("locked_until") is None:
        return False
    locked_until = investigator["locked_until"]
    if isinstance(locked_until, str):
        locked_until = datetime.fromisoformat(locked_until)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < locked_until


def increment_failed_login(db: Session, investigator_id: str) -> int:
    """
    Increment failed login counter.
    Lock account for 15 minutes after 5 failures.
    Returns the new failed attempt count.
    """
    result = db.execute(
        text("""
            UPDATE investigators
            SET failed_login_count = failed_login_count + 1
            WHERE id = :id
            RETURNING failed_login_count
        """),
        {"id": investigator_id},
    ).fetchone()
    db.commit()

    count = result[0] if result else 1

    if count >= MAX_FAILED_ATTEMPTS:
        locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=LOCKOUT_MINUTES
        )
        db.execute(
            text("""
                UPDATE investigators
                SET locked_until = :locked_until
                WHERE id = :id
            """),
            {"locked_until": locked_until, "id": investigator_id},
        )
        db.commit()
        logger.warning(
            f"Account {investigator_id} locked until {locked_until} "
            f"after {count} failed attempts."
        )

    return count


def reset_failed_login(db: Session, investigator_id: str) -> None:
    """Reset failed login counter and lockout on successful login."""
    db.execute(
        text("""
            UPDATE investigators
            SET
                failed_login_count = 0,
                locked_until = NULL,
                last_login_at = NOW()
            WHERE id = :id
        """),
        {"id": investigator_id},
    )
    db.commit()


# =============================================================================
# LOGIN LOGIC
# =============================================================================

def authenticate_investigator(
    db: Session,
    login_identifier: str,
    password: str,
    ip_address: Optional[str] = None,
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Authenticate an investigator by badge number or email + password.

    Returns:
        Tuple of (investigator_dict, error_message)
        If successful: (investigator, None)
        If failed: (None, error_message)
    """
    # Find investigator by badge number or email
    result = db.execute(
        text("""
            SELECT
                id, full_name, email, badge_number,
                organization, role, is_active,
                is_badge_verified, first_login,
                password_hash, failed_login_count,
                locked_until
            FROM investigators
            WHERE
                (badge_number = :identifier OR email = :identifier)
                AND is_active = TRUE
        """),
        {"identifier": login_identifier},
    ).mappings().first()

    if not result:
        logger.warning(
            f"Login attempt with unknown identifier: {login_identifier} "
            f"from IP: {ip_address}"
        )
        return None, "Invalid credentials."

    investigator = dict(result)

    # Check account lockout
    if is_account_locked(investigator):
        logger.warning(
            f"Login attempt on locked account: {investigator['id']} "
            f"from IP: {ip_address}"
        )
        return None, (
            "Account is temporarily locked due to multiple failed login attempts. "
            "Please try again in 15 minutes or contact your system administrator."
        )

    # Check password is set
    if not investigator.get("password_hash"):
        return None, (
            "Account password has not been set. "
            "Please contact your system administrator."
        )

    # Verify password
    if not verify_password(password, investigator["password_hash"]):
        count = increment_failed_login(db, investigator["id"])
        remaining = MAX_FAILED_ATTEMPTS - count
        logger.warning(
            f"Failed login for {investigator['id']} from IP: {ip_address}. "
            f"Attempts: {count}/{MAX_FAILED_ATTEMPTS}"
        )
        if remaining > 0:
            return None, (
                f"Invalid credentials. "
                f"{remaining} attempt(s) remaining before account lockout."
            )
        else:
            return None, (
                "Account locked for 15 minutes due to multiple failed attempts."
            )

    # Check badge verification for non-admin roles
    if investigator["role"] != "SYSTEM_ADMIN":
        if not investigator.get("is_badge_verified"):
            logger.warning(
                f"Login attempt with unverified badge: {investigator['id']}"
            )
            return None, (
                "Your badge number has not been verified by the system administrator. "
                "Please contact the ICT Department."
            )

    # Successful login — reset failed counter and update IP
    reset_failed_login(db, investigator["id"])

    if ip_address:
        db.execute(
            text("""
                UPDATE investigators
                SET last_login_ip = :ip
                WHERE id = :id
            """),
            {"ip": ip_address, "id": investigator["id"]},
        )
        db.commit()

    logger.info(
        f"Successful login: {investigator['full_name']} "
        f"({investigator['role']}) from IP: {ip_address}"
    )

    return investigator, None


# =============================================================================
# CURRENT USER FROM TOKEN
# =============================================================================

def get_current_investigator(
    db: Session,
    token: str,
) -> Optional[dict]:
    """
    Validate JWT token and return the current investigator.
    Returns None if token is invalid or investigator is inactive.
    """
    payload = decode_token(token)
    if not payload:
        return None

    if payload.get("type") != "access":
        return None

    investigator_id = payload.get("sub")
    if not investigator_id:
        return None

    result = db.execute(
        text("""
            SELECT
                id, full_name, email, badge_number,
                organization, role, is_active,
                is_badge_verified, first_login
            FROM investigators
            WHERE id = :id AND is_active = TRUE
        """),
        {"id": investigator_id},
    ).mappings().first()

    if not result:
        return None

    return dict(result)