# =============================================================================
# HexShield AI — File Submissions Router
# Handles secure file ingestion and evidence submission endpoints.
# This is the primary evidence intake point for the system.
# =============================================================================

import uuid
import hashlib
import os
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.config import settings

router = APIRouter()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sanitize_filename(original: str) -> str:
    """
    Generate a safe internal storage filename using UUID.
    Preserves the original file extension.
    """
    ext = Path(original).suffix.lower()
    return f"{uuid.uuid4()}{ext}"


def save_file_to_storage(data: bytes, stored_filename: str) -> str:
    """
    Save file bytes to the configured upload directory.
    Returns the full storage path.
    """
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    storage_path = upload_dir / stored_filename
    storage_path.write_bytes(data)
    return str(storage_path)


def validate_file_size(file_size: int) -> None:
    """
    Enforce the maximum upload size configured in settings.
    Raises HTTPException if exceeded.
    """
    max_bytes = settings.max_upload_size_bytes
    if file_size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"File size {file_size} bytes exceeds maximum allowed "
                f"size of {settings.MAX_UPLOAD_SIZE_MB} MB."
            ),
        )


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/cases/{case_id}/submissions", status_code=status.HTTP_201_CREATED)
async def submit_file(
    case_id: str,
    file: UploadFile = File(...),
    submitted_by: str = Form(...),
    source_description: Optional[str] = Form(None),
    submission_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """
    Submit a file as digital evidence for a forensic case.

    This endpoint:
    1. Validates the case and submitting investigator exist
    2. Reads and validates file size
    3. Computes SHA-256 and SHA-512 hashes immediately at ingestion
    4. Saves the file to secure storage with a UUID-based filename
    5. Creates an immutable file_submissions record
    6. Records the initial chain-of-custody ACQUISITION event

    The file is never renamed or modified after ingestion.
    The hash computed here is the forensic baseline.
    """

    # Step 1 — Verify case exists and is active
    case = db.execute(
        text("""
            SELECT id, case_reference, status
            FROM cases
            WHERE id = :id
        """),
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
            detail=(
                f"Cannot submit evidence to a {case['status']} case. "
                f"Case must be OPEN or UNDER_ANALYSIS."
            ),
        )

    # Step 2 — Verify submitting investigator exists and is active
    investigator = db.execute(
        text("""
            SELECT id, full_name, badge_number, role
            FROM investigators
            WHERE id = :id AND is_active = TRUE
        """),
        {"id": submitted_by},
    ).mappings().first()

    if not investigator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigator {submitted_by} not found or inactive.",
        )

    # Step 3 — Read file bytes and validate size
    file_bytes = await file.read()
    validate_file_size(len(file_bytes))

    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Submitted file is empty. Zero-byte files cannot be ingested.",
        )

    # Step 4 — Compute cryptographic hashes at ingestion
    sha256_hash = compute_sha256(file_bytes)
    sha512_hash = compute_sha512(file_bytes)

    # Step 5 — Check for duplicate submission (same hash in same case)
    duplicate = db.execute(
        text("""
            SELECT id, original_filename
            FROM file_submissions
            WHERE sha256_hash = :hash AND case_id = :case_id
        """),
        {"hash": sha256_hash, "case_id": case_id},
    ).mappings().first()

    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A file with identical content (SHA-256: {sha256_hash[:16]}...) "
                f"has already been submitted to this case as "
                f"'{duplicate['original_filename']}'."
            ),
        )

    # Step 6 — Generate safe internal filename and save to storage
    original_filename = file.filename or "unknown_file"
    stored_filename = sanitize_filename(original_filename)
    storage_path = save_file_to_storage(file_bytes, stored_filename)

    # Step 7 — Extract file extension and declared MIME type
    file_extension = Path(original_filename).suffix.lower() or None
    declared_mime = file.content_type or None

    # Step 8 — Create the immutable file_submissions record
    submission_id = str(uuid.uuid4())

    db.execute(
        text("""
            INSERT INTO file_submissions (
                id,
                case_id,
                submitted_by,
                original_filename,
                stored_filename,
                file_extension,
                file_size_bytes,
                mime_type_declared,
                sha256_hash,
                sha512_hash,
                storage_path,
                source_description,
                submission_notes
            ) VALUES (
                :id,
                :case_id,
                :submitted_by,
                :original_filename,
                :stored_filename,
                :file_extension,
                :file_size_bytes,
                :mime_type_declared,
                :sha256_hash,
                :sha512_hash,
                :storage_path,
                :source_description,
                :submission_notes
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
            "sha256_hash": sha256_hash,
            "sha512_hash": sha512_hash,
            "storage_path": storage_path,
            "source_description": source_description,
            "submission_notes": submission_notes,
        },
    )

    # Step 9 — Record initial ACQUISITION custody event
    custody_id = str(uuid.uuid4())
    db.execute(
        text("""
            INSERT INTO chain_of_custody_events (
                id,
                case_id,
                submission_id,
                event_type,
                event_sequence,
                actor_id,
                actor_role,
                actor_badge_number,
                event_description,
                hash_at_event,
                hash_verified,
                notes
            ) VALUES (
                :id,
                :case_id,
                :submission_id,
                'ACQUISITION',
                1,
                :actor_id,
                :actor_role,
                :actor_badge_number,
                :event_description,
                :hash_at_event,
                TRUE,
                :notes
            )
        """),
        {
            "id": custody_id,
            "case_id": case_id,
            "submission_id": submission_id,
            "actor_id": investigator["id"],
            "actor_role": investigator["role"],
            "actor_badge_number": investigator["badge_number"],
            "event_description": (
                f"Digital evidence acquired and ingested into HexShield AI. "
                f"Original filename: '{original_filename}'. "
                f"File size: {len(file_bytes)} bytes. "
                f"Submitted by: {investigator['full_name']}."
            ),
            "hash_at_event": sha256_hash,
            "notes": source_description,
        },
    )

    db.commit()

    return {
        "message": "File submitted successfully. Evidence record created.",
        "submission_id": submission_id,
        "case_id": case_id,
        "case_reference": case["case_reference"],
        "original_filename": original_filename,
        "file_size_bytes": len(file_bytes),
        "sha256_hash": sha256_hash,
        "sha512_hash": sha512_hash,
        "custody_event": "ACQUISITION recorded.",
        "next_step": f"Trigger analysis at POST /api/v1/submissions/{submission_id}/analyze",
    }


@router.get("/cases/{case_id}/submissions")
def list_case_submissions(case_id: str, db: Session = Depends(get_db)):
    """
    List all file submissions for a specific case.
    """
    case = db.execute(
        text("SELECT id FROM cases WHERE id = :id"),
        {"id": case_id},
    ).fetchone()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found.",
        )

    result = db.execute(
        text("""
            SELECT
                fs.id,
                fs.original_filename,
                fs.file_extension,
                fs.file_size_bytes,
                fs.mime_type_declared,
                fs.mime_type_detected,
                fs.sha256_hash,
                fs.hex_analysis_complete,
                fs.ai_analysis_complete,
                fs.report_generated,
                fs.ingestion_timestamp,
                i.full_name AS submitted_by_name
            FROM file_submissions fs
            JOIN investigators i ON fs.submitted_by = i.id
            WHERE fs.case_id = :case_id
            ORDER BY fs.ingestion_timestamp DESC
        """),
        {"case_id": case_id},
    )
    rows = result.mappings().all()

    return {
        "case_id": case_id,
        "total": len(rows),
        "submissions": [dict(row) for row in rows],
    }


@router.get("/submissions/{submission_id}")
def get_submission(submission_id: str, db: Session = Depends(get_db)):
    """
    Retrieve full details of a single file submission.
    """
    result = db.execute(
        text("""
            SELECT
                fs.id,
                fs.case_id,
                fs.original_filename,
                fs.stored_filename,
                fs.file_extension,
                fs.file_size_bytes,
                fs.mime_type_declared,
                fs.mime_type_detected,
                fs.sha256_hash,
                fs.sha512_hash,
                fs.source_description,
                fs.submission_notes,
                fs.hex_analysis_complete,
                fs.ai_analysis_complete,
                fs.report_generated,
                fs.ingestion_timestamp,
                i.full_name AS submitted_by_name,
                i.email AS submitted_by_email,
                c.case_reference
            FROM file_submissions fs
            JOIN investigators i ON fs.submitted_by = i.id
            JOIN cases c ON fs.case_id = c.id
            WHERE fs.id = :id
        """),
        {"id": submission_id},
    ).mappings().first()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Submission {submission_id} not found.",
        )

    return dict(result)