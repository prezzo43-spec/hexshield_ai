# =============================================================================
# HexShield AI — Database Migration Runner
# Executes SQL migration files against the Neon PostgreSQL database.
# Run this script once to build the schema.
# Usage: python scripts/run_migration.py
# =============================================================================

import sys
import os
import hashlib
import logging
from pathlib import Path

# Add the backend root to the Python path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import engine, verify_database_connection
from app.config import settings

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Migration file path
# -----------------------------------------------------------------------------
MIGRATION_FILE = Path(__file__).parent.parent / "database" / "migrations" / "001_initial_schema.sql"


def compute_checksum(sql: str) -> str:
    """Compute SHA-256 checksum of the SQL content."""
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def migration_already_applied(version: str) -> bool:
    """
    Check if this migration version has already been applied.
    Prevents running the same migration twice.
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT id FROM schema_migrations WHERE version = :version"),
                {"version": version},
            )
            return result.fetchone() is not None
    except Exception:
        # schema_migrations table does not exist yet — migration has not run
        return False


def run_migration() -> None:
    """
    Read and execute the SQL migration file against the Neon database.
    """
    logger.info("=" * 60)
    logger.info("HexShield AI — Database Migration Runner")
    logger.info("=" * 60)
    logger.info(f"Environment : {settings.APP_ENV}")
    logger.info(f"Database    : {settings.DATABASE_URL[:40]}...")
    logger.info(f"Migration   : {MIGRATION_FILE.name}")
    logger.info("=" * 60)

    # Step 1 — Verify database connection
    logger.info("Step 1: Verifying database connection...")
    if not verify_database_connection():
        logger.critical("Cannot connect to database. Aborting migration.")
        sys.exit(1)
    logger.info("Database connection OK.")

    # Step 2 — Read migration file
    logger.info("Step 2: Reading migration file...")
    if not MIGRATION_FILE.exists():
        logger.critical(f"Migration file not found: {MIGRATION_FILE}")
        sys.exit(1)

    sql_content = MIGRATION_FILE.read_text(encoding="utf-8")
    checksum = compute_checksum(sql_content)
    logger.info(f"Migration file loaded. Checksum: {checksum[:16]}...")

    # Step 3 — Check if already applied
    logger.info("Step 3: Checking migration history...")
    if migration_already_applied("1.0.0"):
        logger.warning("Migration 1.0.0 has already been applied. Skipping.")
        logger.info("Schema is up to date. Nothing to do.")
        sys.exit(0)
    logger.info("Migration 1.0.0 not yet applied. Proceeding.")

    # Step 4 — Execute migration
    logger.info("Step 4: Executing migration SQL...")
    try:
        with engine.connect() as conn:
            # Execute the entire SQL file as a single transaction
            conn.execute(text(sql_content))
            conn.commit()
        logger.info("Migration SQL executed successfully.")
    except Exception as e:
        logger.critical(f"Migration failed during SQL execution: {e}")
        logger.critical("The database may be in a partial state. Review manually.")
        sys.exit(1)

    # Step 5 — Verify tables were created
    logger.info("Step 5: Verifying tables were created...")
    expected_tables = [
        "investigators",
        "cases",
        "file_submissions",
        "magic_byte_signatures",
        "hex_analysis_results",
        "ai_media_analysis_results",
        "ai_analysis_frame_details",
        "chain_of_custody_events",
        "forensic_reports",
        "system_audit_log",
        "schema_migrations",
    ]

    with engine.connect() as conn:
        for table in expected_tables:
            result = conn.execute(
                text(
                    "SELECT EXISTS ("
                    "SELECT FROM information_schema.tables "
                    "WHERE table_schema = 'public' "
                    "AND table_name = :table"
                    ")"
                ),
                {"table": table},
            )
            exists = result.scalar()
            if exists:
                logger.info(f"  [OK] {table}")
            else:
                logger.error(f"  [MISSING] {table}")

    logger.info("=" * 60)
    logger.info("Migration completed successfully.")
    logger.info("HexShield AI database schema is ready.")
    logger.info("=" * 60)


if __name__ == "__main__":
    run_migration()