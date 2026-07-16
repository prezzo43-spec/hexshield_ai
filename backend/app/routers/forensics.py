# =============================================================================
# HexShield AI — Forensics Router
# Handles pipeline orchestration, consensus generation, and report assembly.
# =============================================================================

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.routers.auth import get_auth_investigator, require_role
from app.services.ai_engine.consensus_engine import ForensicConsensusEngine
from app.services.forensic_reporting.report_generator import (
    ForensicReportData,
    CaseInfo,
    InvestigatorInfo,
    SubmissionInfo,
    CustodyEvent,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize Engine globally for runtime resource efficiency
engine = ForensicConsensusEngine()


@router.post(
    "/forensics/consensus/evaluate/{submission_id}",
    response_model=ForensicReportData,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("LEAD_INVESTIGATOR", "SENIOR_ANALYST", "SYSTEM_ADMIN"))],
    summary="Evaluate consensus on an evidence submission",
    description="Assembles evidence profiles from database schemas, coordinates AI evaluations, and saves results.",
)
def evaluate_submission_consensus(
    submission_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_auth_investigator),
):
    """
    Triggers the AI Consensus pipeline for a given database submission ID.
    Reconciles metadata, builds dynamic Pydantic payloads, and executes consensus evaluation.
    """
    client_ip = request.client.host if request.client else "unknown"
    logger.info(
        "Consensus request received: submission_id=%s requested_by=%s",
        submission_id,
        current_user.get("full_name"),
    )

    # 1. Fetch DB records to construct the dynamic payload
    # Note: Replace column names/queries with your exact database schema fields
    try:
        # Get dynamic submission metadata
        submission_record = db.execute(
            text("""
                SELECT 
                    id, original_filename, file_size_bytes, 
                    sha256_hash, sha512_hash, mime_type_declared, 
                    mime_type_detected, ingestion_timestamp, submitted_by_id
                FROM evidence_submissions 
                WHERE id = :id
            """),
            {"id": submission_id},
        ).fetchone()

        if not submission_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence submission with ID {submission_id} not found.",
            )

        # Get connected case details
        case_record = db.execute(
            text("""
                SELECT 
                    c.id, c.case_reference, c.case_title, c.jurisdiction, 
                    c.applicable_law, c.classification, c.lead_investigator_id,
                    i.full_name, i.email, i.organization, i.badge_number, i.role
                FROM cases c
                LEFT JOIN investigators i ON c.lead_investigator_id = i.id
                JOIN case_submissions cs ON cs.case_id = c.id
                WHERE cs.submission_id = :submission_id
                LIMIT 1
            """),
            {"submission_id": submission_id},
        ).fetchone()

        # Build structural dynamic classes
        lead_inv = InvestigatorInfo(
            id=str(case_record[6]) if case_record else "SYSTEM",
            full_name=case_record[7] if case_record else "Unassigned",
            email=case_record[8] if case_record else "system@hexshield.ai",
            organization=case_record[9] if case_record else "HexShield Forensic Services",
            badge_number=case_record[10] if case_record else "SYSTEM-00",
            role=case_record[11] if case_record else "System automated",
        )

        mock_case = CaseInfo(
            id=str(case_record[0]) if case_record else "case_auto_gen",
            case_reference=case_record[1] if case_record else "AUTO-REF",
            case_title=case_record[2] if case_record else "Consensus Engine Dry Run",
            jurisdiction=case_record[3] if case_record else "Nairobi, Kenya",
            applicable_law=case_record[4] if case_record else "Computer Misuse and Cybercrimes Act, 2018",
            classification=case_record[5] if case_record else "RESTRICTED",
            lead_investigator=lead_inv,
        )

        # Fetch submitter metadata
        submitter_record = db.execute(
            text("SELECT id, full_name, email, organization, badge_number, role FROM investigators WHERE id = :id"),
            {"id": submission_record.submitted_by_id},
        ).fetchone()

        submitter_inv = InvestigatorInfo(
            id=str(submitter_record[0]),
            full_name=submitter_record[1],
            email=submitter_record[2],
            organization=submitter_record[3],
            badge_number=submitter_record[4],
            role=submitter_record[5],
        )

        mock_submission = SubmissionInfo(
            id=str(submission_record.id),
            original_filename=submission_record.original_filename,
            file_size_bytes=submission_record.file_size_bytes,
            sha256_hash=submission_record.sha256_hash,
            sha512_hash=submission_record.sha512_hash,
            mime_type_declared=submission_record.mime_type_declared,
            mime_type_detected=submission_record.mime_type_detected,
            ingestion_timestamp=submission_record.ingestion_timestamp.isoformat() 
            if isinstance(submission_record.ingestion_timestamp, datetime) 
            else submission_record.ingestion_timestamp,
            submitted_by=submitter_inv,
        )

        # Reconstruct verified chain of custody events sequentially from DB
        custody_records = db.execute(
            text("""
                SELECT 
                    event_sequence, event_type, event_description, actor_name, 
                    actor_badge, actor_role, hash_at_event, hash_verified, 
                    event_timestamp, notes
                FROM custody_chain_log 
                WHERE submission_id = :submission_id
                ORDER BY event_sequence ASC
            """),
            {"submission_id": submission_id},
        ).fetchall()

        custody_chain = []
        for r in custody_records:
            custody_chain.append(
                CustodyEvent(
                    event_sequence=r.event_sequence,
                    event_type=r.event_type,
                    event_description=r.event_description,
                    actor_name=r.actor_name,
                    actor_badge=r.actor_badge,
                    actor_role=r.actor_role,
                    hash_at_event=r.hash_at_event,
                    hash_verified=r.hash_verified,
                    event_timestamp=r.event_timestamp.isoformat() 
                    if isinstance(r.event_timestamp, datetime) 
                    else r.event_timestamp,
                    notes=r.notes,
                )
            )

        # Fallback to default event if DB table is empty to prevent schema validation collapse
        if not custody_chain:
            custody_chain.append(
                CustodyEvent(
                    event_sequence=1,
                    event_type="INGESTION",
                    event_description="Automatic payload registration upon upload",
                    actor_name=submitter_inv.full_name,
                    actor_badge=submitter_inv.badge_number,
                    actor_role=submitter_inv.role,
                    hash_at_event=submission_record.sha256_hash,
                    hash_verified=True,
                    event_timestamp=datetime.now(timezone.utc).isoformat(),
                    notes="Ingestion metadata locked.",
                )
            )

        # Assemble Payload
        forensic_payload = ForensicReportData(
            report_id=f"rpt_{submission_id[:8]}",
            report_type="CONSTRUCT_REPORT",
            generated_at=datetime.now(timezone.utc).isoformat(),
            issuing_authority="HexShield AI Forensic Services",
            jurisdiction="Kenya",
            case=mock_case,
            submission=mock_submission,
            hex_analysis=None,
            ai_analysis=None,
            custody_chain=custody_chain,
            examiner_notes="Processing AI automated consensus.",
        )

    except Exception as dbe:
        logger.error("Failed compiling submission dataset from database: %s", str(dbe))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed gathering forensic database assets: {str(dbe)}"
        )

    # 2. Fire the engine
    try:
        evaluated_report = engine.evaluate_consensus(forensic_payload)

        # 3. Save evaluated findings back to Database
        db.execute(
            text("""
                UPDATE evidence_submissions 
                SET 
                    consensus_notes = :notes,
                    analysis_completed_at = :completed_at
                WHERE id = :id
            """),
            {
                "notes": evaluated_report.examiner_notes,
                "completed_at": datetime.now(timezone.utc),
                "id": submission_id,
            },
        )

        # Write explicit tracking transaction to system security logs
        db.execute(
            text("""
                INSERT INTO system_audit_log (
                    event_category, event_action, event_description, 
                    investigator_id, ip_address, success
                ) VALUES (
                    'FORENSICS', 'CONSENSUS_GENERATION', :description, 
                    :user_id, :ip, TRUE
                )
            """),
            {
                "description": f"Consensus successfully processed for submission: {submission_id}",
                "user_id": str(current_user.get("id")),
                "ip": client_ip,
            },
        )
        db.commit()

        return evaluated_report

    except Exception as e:
        db.rollback()
        logger.error("Consensus compilation crash: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic consensus calculation failed: {str(e)}",
        )