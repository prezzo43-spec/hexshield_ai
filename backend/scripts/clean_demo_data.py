# =============================================================================
# HexShield AI — Demo Data Cleanup Script
# =============================================================================

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from app.database import engine, verify_database_connection


def clean_demo_data():
    print("=" * 60)
    print("HexShield AI — Demo Data Cleanup")
    print("=" * 60)

    if not verify_database_connection():
        print("Cannot connect to database.")
        sys.exit(1)

    confirm = input(
        "\nThis will DELETE all cases, submissions, analysis results,\n"
        "reports, custody events, and non-admin investigators.\n"
        "The admin account will be preserved.\n\n"
        "Type 'DELETE' to confirm: "
    )

    if confirm != "DELETE":
        print("Aborted. No data was deleted.")
        sys.exit(0)

    with engine.connect() as conn:
        print("\nDeleting demo data...")

        # Temporarily disable immutability rules
        conn.execute(text("DROP RULE IF EXISTS no_delete_custody ON chain_of_custody_events"))
        conn.execute(text("DROP RULE IF EXISTS no_update_custody ON chain_of_custody_events"))
        conn.execute(text("DROP RULE IF EXISTS no_delete_audit ON system_audit_log"))
        conn.execute(text("DROP RULE IF EXISTS no_update_audit ON system_audit_log"))

        conn.execute(text("DELETE FROM forensic_reports"))
        print("  [OK] forensic_reports cleared")

        conn.execute(text("DELETE FROM ai_analysis_frame_details"))
        print("  [OK] ai_analysis_frame_details cleared")

        conn.execute(text("DELETE FROM ai_media_analysis_results"))
        print("  [OK] ai_media_analysis_results cleared")

        conn.execute(text("DELETE FROM hex_analysis_results"))
        print("  [OK] hex_analysis_results cleared")

        conn.execute(text("DELETE FROM chain_of_custody_events"))
        print("  [OK] chain_of_custody_events cleared")

        conn.execute(text("DELETE FROM file_submissions"))
        print("  [OK] file_submissions cleared")

        conn.execute(text("DELETE FROM cases"))
        print("  [OK] cases cleared")

        conn.execute(text(
            "DELETE FROM investigators WHERE role != 'SYSTEM_ADMIN'"
        ))
        print("  [OK] non-admin investigators cleared")

        conn.execute(text("DELETE FROM system_audit_log"))
        print("  [OK] system_audit_log cleared")

        # Re-apply immutability rules
        conn.execute(text("""
            CREATE RULE no_update_custody AS
                ON UPDATE TO chain_of_custody_events
                DO INSTEAD NOTHING
        """))
        conn.execute(text("""
            CREATE RULE no_delete_custody AS
                ON DELETE TO chain_of_custody_events
                DO INSTEAD NOTHING
        """))
        conn.execute(text("""
            CREATE RULE no_update_audit AS
                ON UPDATE TO system_audit_log
                DO INSTEAD NOTHING
        """))
        conn.execute(text("""
            CREATE RULE no_delete_audit AS
                ON DELETE TO system_audit_log
                DO INSTEAD NOTHING
        """))
        print("  [OK] immutability rules restored")

        conn.commit()

    print("\n" + "=" * 60)
    print("Demo data cleanup complete.")
    print("Admin account preserved.")
    print("Database is ready for production use.")
    print("=" * 60)


if __name__ == "__main__":
    clean_demo_data()