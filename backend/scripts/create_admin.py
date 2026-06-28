# =============================================================================
# HexShield AI — System Admin Bootstrap Script
# =============================================================================
# PURPOSE:
#   Creates the initial SYSTEM_ADMIN account directly in the database.
#   This script is run ONCE by the ICT Department on first deployment.
#   It requires direct database access — it cannot be run from the UI.
#
# USAGE:
#   python scripts/create_admin.py
#
# SECURITY:
#   - Run this script only on the server, never on a client machine.
#   - Delete or restrict access to this script after first use.
#   - The admin credentials must be communicated securely to the ICT team.
# =============================================================================

import sys
import uuid
import getpass
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import engine, verify_database_connection
from app.services.auth import hash_password, validate_password_strength

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def create_system_admin() -> None:
    logger.info("=" * 60)
    logger.info("HexShield AI — System Admin Bootstrap")
    logger.info("=" * 60)
    logger.info("This script creates the initial SYSTEM_ADMIN account.")
    logger.info("Run this only once on first deployment.")
    logger.info("=" * 60)

    # Verify database connection
    if not verify_database_connection():
        logger.critical("Cannot connect to database. Check DATABASE_URL in .env")
        sys.exit(1)

    # Check if admin already exists
    with engine.connect() as conn:
        existing = conn.execute(
            text("""
                SELECT id, full_name, email
                FROM investigators
                WHERE role = 'SYSTEM_ADMIN'
                LIMIT 1
            """)
        ).fetchone()

        if existing:
            logger.warning("A SYSTEM_ADMIN account already exists:")
            logger.warning(f"  Name  : {existing[1]}")
            logger.warning(f"  Email : {existing[2]}")
            logger.warning("To create another admin, use the application UI.")
            confirm = input("\nDo you want to create an additional admin? (yes/no): ")
            if confirm.lower() != "yes":
                logger.info("Aborted.")
                sys.exit(0)

    print("\nEnter details for the System Admin account:")
    print("-" * 40)

    # Collect admin details
    full_name = input("Full Name: ").strip()
    if not full_name:
        logger.error("Full name is required.")
        sys.exit(1)

    email = input("Email Address: ").strip()
    if not email or "@" not in email:
        logger.error("Valid email address is required.")
        sys.exit(1)

    organization = input("Organization (e.g. DCI Kenya ICT Department): ").strip()
    if not organization:
        organization = "HexShield AI Administration"

    print("\nPassword Requirements:")
    print("  - Minimum 12 characters")
    print("  - At least one uppercase letter")
    print("  - At least one lowercase letter")
    print("  - At least one digit")
    print("  - At least one special character (!@#$%^&*...)")
    print()

    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password: ")

        if password != confirm:
            print("Passwords do not match. Try again.\n")
            continue

        valid, msg = validate_password_strength(password)
        if not valid:
            print(f"Password too weak: {msg}\n")
            continue

        break

    # Create the admin account
    admin_id = str(uuid.uuid4())
    password_hash = hash_password(password)

    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO investigators (
                    id,
                    full_name,
                    email,
                    organization,
                    role,
                    is_active,
                    is_badge_verified,
                    password_hash,
                    first_login
                ) VALUES (
                    :id,
                    :full_name,
                    :email,
                    :organization,
                    'SYSTEM_ADMIN',
                    TRUE,
                    TRUE,
                    :password_hash,
                    FALSE
                )
            """),
            {
                "id": admin_id,
                "full_name": full_name,
                "email": email,
                "organization": organization,
                "password_hash": password_hash,
            },
        )
        conn.commit()

    logger.info("=" * 60)
    logger.info("SYSTEM_ADMIN account created successfully.")
    logger.info(f"  ID       : {admin_id}")
    logger.info(f"  Name     : {full_name}")
    logger.info(f"  Email    : {email}")
    logger.info(f"  Role     : SYSTEM_ADMIN")
    logger.info("=" * 60)
    logger.info("The admin can now log in at the HexShield AI login page.")
    logger.info("Use email address and password to log in as admin.")
    logger.info("=" * 60)


if __name__ == "__main__":
    create_system_admin()