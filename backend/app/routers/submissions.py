# =============================================================================
# HexShield AI — File Submissions & Consolidated Analysis Router
# Handles secure file ingestion, evidence endpoints, and forensic AI consensus.
# =============================================================================

import uuid
import hashlib
import logging
import mimetypes
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone

try:
    import magic
except ImportError:
    magic = None

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Request,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.config import settings
from app.routers.auth import get_auth_investigator, require_role

# Import the corrected Pydantic-compatible Dataclasses
from app.services.forensic_reporting.report_generator import (
    ForensicReportData,
    CaseInfo,
    InvestigatorInfo,
    SubmissionInfo,
    CustodyEvent,
)

# Import Consensus Engine directly
from app.services.ai_engine.consensus_engine import ForensicConsensusEngine

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize Consensus Engine globally
engine = ForensicConsensusEngine()

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sanitize_filename(original: str) -> str:
    ext = Path(original).suffix.lower()
    if not ext.isalnum() and ext not in {".jpg", ".jpeg", ".png", ".bmp", ".pdf", ".mp4", ".wav", ".txt"}:
        ext = ""
    return f"{uuid.uuid4()}{ext}"


def save_file_to_storage(data: bytes, stored_filename: str) -> str:
    upload_dir = Path(settings.UPLOAD_DIR).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    storage_path = (upload_dir / stored_filename).resolve()
    if upload_dir not in storage_path.parents and storage_path != upload_dir:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid storage path detected.",
        )
    storage_path.write_bytes(data)
    return str(storage_path)


def validate_file_size(file_size: int) -> None:
    max_bytes = settings.max_upload_size_bytes
    if file_size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"File size {file_size} bytes exceeds maximum allowed "
                f"size of {settings.MAX_UPLOAD_SIZE_MB} MB."
            ),
        )


def validate_upload_type(
    original_filename: str,
    declared_mime: Optional[str],
    detected_mime: Optional[str],
) -> None:
    ext = Path(original_filename).suffix.lower()
    if ext and ext not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported file extension: '{ext}'. "
                f"Allowed extensions: {settings.allowed_upload_extensions}."
            ),
        )

    if detected_mime:
        mime = detected_mime.lower()
        if not any(mime.startswith(prefix) for prefix in settings.allowed_upload_mime_prefixes):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Unsupported uploaded file type: '{detected_mime}'. "
                    f"Allowed MIME prefixes: {settings.allowed_upload_mime_prefixes}."
                ),
            )


def validate_content_length(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if content_length is None:
        return

    try:
        length_value = int(content_length)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Content-Length header.",
        )

    if length_value < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Content-Length header. Value must be non-negative.",
        )

    if length_value > settings.max_request_body_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Declared upload size {length_value} bytes exceeds maximum "
                f"allowed size of {settings.MAX_REQUEST_BODY_SIZE_MB} MB."
            ),
        )


# =============================================================================
# FILE SUBMISSIONS ENDPOINTS
# =============================================================================

@router.post("/cases/{case_id}/submissions", status_code=status.HTTP_201_CREATED)
async def submit_file(
    request: Request,
    case_id: str,
    file: UploadFile = File(...),
    submitted_by: str = Form(...),
    source_description: Optional[str] = Form(None),
    submission_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    case = db.execute(
        text("SELECT id, case_reference, status FROM cases WHERE id = :id"),
        {"id": case_id},
    ).mappings().first()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found.",
        )

    if case["status"] in ("CLOSED", "ARCHIVED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot submit evidence to a {case['status']} case.",
        )

    investigator = db.execute(
        text("SELECT id, full_name, badge_number, role FROM investigators WHERE id = :id AND is_active = TRUE"),
        {"id": submitted_by},
    ).mappings().first()

    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {submitted_by} not found or inactive.",
        )

    validate_content_length(request)
    file_bytes = await file.read()
    validate_file_size(len(file_bytes))

    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Submitted file is empty.",
        )

    original_filename = file.filename or "unknown_file"
    declared_mime = file.content_type or None
    detected_mime = None
    if magic is not None:
        try:
            detected_mime = magic.from_buffer(file_bytes, mime=True)
        except Exception as exc:
            logger.warning("Unable to detect MIME type for %s: %s", original_filename, exc)
    else:
        detected_mime = mimetypes.guess_type(original_filename)[0]

    validate_upload_type(original_filename, declared_mime, detected_mime)

    sha256_hash = compute_sha256(file_bytes)
    sha512_hash = compute_sha512(file_bytes)

    duplicate = db.execute(
        text("SELECT id, original_filename FROM file_submissions WHERE sha256_hash = :hash AND case_id = :case_id"),
        {"hash": sha256_hash, "case_id": case_id},
    ).mappings().first()

    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A file with identical content has already been submitted to this case.",
        )

    stored_filename = sanitize_filename(original_filename)
    storage_path = save_file_to_storage(file_bytes, stored_filename)
    file_extension = Path(original_filename).suffix.lower() or None

    submission_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO file_submissions (
                id, case_id, submitted_by, original_filename, stored_filename,
                file_extension, file_size_bytes, mime_type_declared, mime_type_detected,
                sha256_hash, sha512_hash, storage_path, source_description, submission_notes
            ) VALUES (
                :id, :case_id, :submitted_by, :original_filename, :stored_filename,
                :file_extension, :file_size_bytes, :mime_type_declared, :mime_type_detected,
                :sha256_hash, :sha512_hash, :storage_path, :source_description, :submission_notes
            )
        """),
        {
            "id": submission_id,
            "case_id": case_id,
            "submitted_by": submitted_by,
            "original_filename": original_filename,
            "stored_filename": stored_filename,
            "file_extension": file_extension,
            "file_size_bytes": len(file_bytes),
            "mime_type_declared": declared_mime,
            "mime_type_detected": detected_mime,
            "sha256_hash": sha256_hash,
            "sha512_hash": sha512_hash,
            "storage_path": storage_path,
            "source_description": source_description,
            "submission_notes": submission_notes,
        },
    )

    db.execute(
        text("""
            INSERT INTO chain_of_custody_events (
                id, case_id, submission_id, event_type, event_sequence,
                actor_id, actor_role, actor_badge_number, event_description,
                hash_at_event, hash_verified, notes
            ) VALUES (
                :id, :case_id, :submission_id, 'ACQUISITION', 1,
                :actor_id, :actor_role, :actor_badge_number, :event_description,
                :hash_at_event, TRUE, :notes
            )
        """),
        {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "submission_id": submission_id,
            "actor_id": investigator["id"],
            "actor_role": investigator["role"],
            "actor_badge_number": investigator["badge_number"],
            "event_description": f"Evidence acquired. Filename: '{original_filename}'. Hash verified.",
            "hash_at_event": sha256_hash,
            "notes": source_description,
        },
    )
    db.commit()

    return {
        "message": "File submitted successfully.",
        "submission_id": submission_id,
        "case_id": case_id,
        "original_filename": original_filename,
        "sha256_hash": sha256_hash,
    }


@router.get("/cases/{case_id}/submissions")
def list_case_submissions(case_id: str, db: Session = Depends(get_db)):
    case = db.execute(text("SELECT id FROM cases WHERE id = :id"), {"id": case_id}).fetchone()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")

    result = db.execute(
        text("""
            SELECT fs.id, fs.original_filename, fs.file_extension, fs.file_size_bytes,
                   fs.mime_type_declared, fs.mime_type_detected, fs.sha256_hash,
                   fs.hex_analysis_complete, fs.ai_analysis_complete, fs.report_generated,
                   fs.ingestion_timestamp, i.full_name AS submitted_by_name
            FROM file_submissions fs
            JOIN investigators i ON fs.submitted_by = i.id
            WHERE fs.case_id = :case_id
            ORDER BY fs.ingestion_timestamp DESC
        """),
        {"case_id": case_id},
    )
    rows = result.mappings().all()
    return {"case_id": case_id, "total": len(rows), "submissions": [dict(row) for row in rows]}


@router.get("/submissions/{submission_id}")
def get_submission(submission_id: str, db: Session = Depends(get_db)):
    result = db.execute(
        text("""
            SELECT fs.id, fs.case_id, fs.original_filename, fs.stored_filename,
                   fs.file_extension, fs.file_size_bytes, fs.mime_type_declared,
                   fs.mime_type_detected, fs.sha256_hash, fs.sha512_hash,
                   fs.source_description, fs.submission_notes, fs.hex_analysis_complete,
                   fs.ai_analysis_complete, fs.report_generated, fs.ingestion_timestamp,
                   i.full_name AS submitted_by_name, i.email AS submitted_by_email,
                   c.case_reference
            FROM file_submissions fs
            JOIN investigators i ON fs.submitted_by = i.id
            JOIN cases c ON fs.case_id = c.id
            WHERE fs.id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found.")
    return dict(result)


# =============================================================================
# COHESIVE AI CONSENSUS ANALYSIS PIPELINE
# =============================================================================

@router.post(
    "/submissions/{submission_id}/analyze/ai",
    response_model=ForensicReportData,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_role("LEAD_INVESTIGATOR", "SENIOR_ANALYST", "SYSTEM_ADMIN"))],
    summary="Evaluate consensus on an evidence submission",
)
def evaluate_submission_consensus(
    submission_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_auth_investigator),
):
    """
    Unified entry point for AI Forensic Analysis. Evaluates AI consensus and returns
    a serialized response.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    logger.info("Evaluating AI consensus directly in submissions for: %s", submission_id)

    try:
        # 1. Fetch File Submission Metadata
        submission_record = db.execute(
            text("""
                SELECT id, case_id, original_filename, file_size_bytes, 
                       sha256_hash, sha512_hash, mime_type_declared, 
                       mime_type_detected, ingestion_timestamp, submitted_by
                FROM file_submissions 
                WHERE id = :id
            """),
            {"id": submission_id},
        ).fetchone()

        if not submission_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence submission with ID {submission_id} not found.",
            )

        # 2. Fetch Case Information
        case_record = db.execute(
            text("""
                SELECT c.id, c.case_reference, c.case_title, c.jurisdiction, 
                       c.applicable_law, c.classification, c.lead_investigator_id,
                       i.full_name, i.email, i.organization, i.badge_number, i.role
                FROM cases c
                LEFT JOIN investigators i ON c.lead_investigator_id = i.id
                WHERE c.id = :case_id
                LIMIT 1
            """),
            {"case_id": submission_record.case_id},
        ).fetchone()

        # 3. Fetch Submitter Profile
        submitter_record = db.execute(
            text("SELECT id, full_name, email, organization, badge_number, role FROM investigators WHERE id = :id"),
            {"id": submission_record.submitted_by},
        ).fetchone()

        # Dynamic mapping to forensic dataclasses
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
            applicable_law=case_record[4] if case_record else "Computer Misuse and Cybercrimes Act, Kenya",
            classification=case_record[5] if case_record else "RESTRICTED",
            lead_investigator=lead_inv,
        )

        submitter_inv = InvestigatorInfo(
            id=str(submitter_record[0]) if submitter_record else "SYSTEM",
            full_name=submitter_record[1] if submitter_record else "System",
            email=submitter_record[2] if submitter_record else "system@hexshield.ai",
            organization=submitter_record[3] if submitter_record else "HexShield AI",
            badge_number=submitter_record[4] if submitter_record else "SYS-00",
            role=submitter_record[5] if submitter_record else "automated",
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
            else str(submission_record.ingestion_timestamp),
            submitted_by=submitter_inv,
        )

        # 4. Sequential Chain of Custody Query
        custody_records = db.execute(
            text("""
                SELECT c.event_sequence, c.event_type, c.event_description, i.full_name AS actor_name, 
                       i.badge_number AS actor_badge, c.actor_role, c.hash_at_event, c.hash_verified, 
                       c.event_timestamp, c.notes
                FROM chain_of_custody_events c
                JOIN investigators i ON c.actor_id = i.id
                WHERE c.submission_id = :submission_id
                ORDER BY c.event_sequence ASC
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
                    else str(r.event_timestamp),
                    notes=r.notes,
                )
            )

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

        # Build complete payload structure
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
        logger.error("Failed assembling forensic databases resources: %s", str(dbe))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Database payload assembly failed: {str(dbe)}"
        )

    # 5. Run the Consensus Evaluation Engine
    try:
        evaluated_report = engine.evaluate_consensus(forensic_payload)

        # 6. Save update results back to submission
        db.execute(
            text("""
                UPDATE file_submissions 
                SET consensus_notes = :notes,
                    ai_analysis_complete = TRUE,
                    analysis_completed_at = :completed_at
                WHERE id = :id
            """),
            {
                "notes": evaluated_report.examiner_notes,
                "completed_at": datetime.now(timezone.utc),
                "id": submission_id,
            },
        )

        # 7. Write immutable audit event
        db.execute(
            text("""
                INSERT INTO audit_ledger (
                    evidence_id, action_description, actor_id, ip_address, timestamp, notes
                ) VALUES (
                    :evidence_id, :description, :actor_id, :ip, :timestamp, :notes
                )
            """),
            {
                "evidence_id": submission_id,
                "description": "CONSENSUS_GENERATION_SUCCESSFUL",
                "actor_id": str(current_user.get("id")),
                "ip": client_ip,
                "timestamp": datetime.now(timezone.utc),
                "notes": f"AI Consensus evaluated successfully by {current_user.get('full_name')}."
            },
        )
        db.commit()

        return evaluated_report

    except Exception as e:
        db.rollback()
        logger.error("Consensus pipeline evaluation failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic consensus calculation failed: {str(e)}",
        )