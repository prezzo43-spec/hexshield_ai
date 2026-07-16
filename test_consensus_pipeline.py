# =============================================================================
# HexShield AI — Forensic Consensus Pipeline Test
# =============================================================================

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables first to avoid initialization crashes
from dotenv import load_dotenv

# Explicitly target the backend/.env path
backend_env = Path(__file__).resolve().parent / "backend" / ".env"
load_dotenv(dotenv_path=backend_env)

# Add backend directory to path if needed
backend_path = Path(__file__).resolve().parent / "backend"
if backend_path.exists() and str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))
else:
    # If already running inside the backend folder, make sure parent is included
    sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from app.services.ai_engine.consensus_engine import ForensicConsensusEngine
    from app.services.forensic_reporting.report_generator import (
        ForensicReportData,
        CaseInfo,
        InvestigatorInfo,
        SubmissionInfo,
        CustodyEvent,
    )
    print("✓ Successfully imported modules and schemas!")
except ImportError as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)


def run_pipeline_test():
    print("\n--- Initializing Forensic Consensus Engine ---")
    
    # 1. Initialize the engine
    try:
        engine = ForensicConsensusEngine()
        print("✓ Forensic Consensus Engine initialized successfully.")
    except Exception as e:
        print(f"✗ Failed to initialize Consensus Engine: {e}")
        return

    # --- DYNAMIC DEBUG: PRINT AVAILABLE METHODS ---
    print("\n=== [DEBUG] ForensicConsensusEngine Methods ===")
    methods = [method for method in dir(engine) if not method.startswith('_')]
    for m in methods:
        print(f" - {m}")
    print("============================================\n")

    # 2. Build Mock Objects using correct Report Generator Data Classes
    print("\n--- Preparing Mock Forensic Data Objects ---")
    
    mock_lead_investigator = InvestigatorInfo(
        id="inv_99812",
        full_name="Dr. Sarah Koech",
        email="s.koech@hexshield.ai",
        organization="Directorate of Criminal Investigations (DCI)",
        badge_number="DCI-99812",
        role="Senior Forensic Analyst",
    )

    mock_submitter = InvestigatorInfo(
        id="inv_99813",
        full_name="Sgt. James Kiprop",
        email="j.kiprop@hexshield.ai",
        organization="Directorate of Criminal Investigations (DCI)",
        badge_number="DCI-99813",
        role="Evidence Custodian",
    )

    mock_case = CaseInfo(
        id="case_2026_098A",
        case_reference="HEX-2026-098A",
        case_title="State vs. Unauthorized Firmware Modification",
        jurisdiction="Nairobi, Kenya",
        applicable_law="Computer Misuse and Cybercrimes Act, 2018",
        classification="RESTRICTED",
        lead_investigator=mock_lead_investigator,
    )

    mock_submission = SubmissionInfo(
        id="sub_88319",
        original_filename="suspicious_firmware.bin",
        file_size_bytes=1048576,  # 1 MB
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        sha512_hash="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        mime_type_declared="application/octet-stream",
        mime_type_detected="application/x-executable",
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        submitted_by=mock_submitter,
    )

    mock_custody_chain = [
        CustodyEvent(
            event_sequence=1,
            event_type="INGESTION",
            event_description="Evidence payload ingested via secure portal.",
            actor_name="Sgt. James Kiprop",
            actor_badge="DCI-99813",
            actor_role="Evidence Custodian",
            hash_at_event="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            hash_verified=True,
            event_timestamp=datetime.now(timezone.utc).isoformat(),
            notes="Secure upload verified.",
        )
    ]

    # Combine everything into the top-level report payload
    forensic_payload = ForensicReportData(
        report_id="rpt_001928",
        report_type="CONSTRUCT_REPORT",
        generated_at=datetime.now(timezone.utc).isoformat(),
        issuing_authority="HexShield AI Forensic Services",
        jurisdiction="Kenya",
        case=mock_case,
        submission=mock_submission,
        hex_analysis=None,  # Populated during evaluation if needed
        ai_analysis=None,   # Populated during evaluation if needed
        custody_chain=mock_custody_chain,
        examiner_notes="Primary triage pipeline assessment.",
    )

    # 3. Execute the Consensus Pipeline Analysis
    print("\n--- Executing Forensic Consensus Engine Pipeline ---")
    try:
        # Directly call the verified consensus evaluation method
        result = engine.evaluate_consensus(forensic_payload)
            
        print("\n=== PIPELINE RESULT ===")
        print(result)
        print("=======================")
        print("\n✓ Pipeline Test executed completely without errors.")
        
    except Exception as e:
        print(f"✗ Failed to execute Consensus Engine: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_pipeline_test()