# app/routers/submissions.py
import uuid
import os
import hashlib
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from sqlalchemy.orm import Session
from sqlalchemy import text

try:
    import magic  # python-magic for structural file signature validation
except Exception:  # pragma: no cover - fallback for environments without libmagic
    magic = None

from app.database import get_db
from app.routers.auth import require_role
from app.config import settings

router = APIRouter(prefix="", tags=["Evidence Ingestion & Submissions"])

# Establish upload directory footprint
UPLOAD_DIR = settings.UPLOAD_DIR
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/cases/{case_id}/submissions", status_code=status.HTTP_201_CREATED)
async def submit_evidence(
    case_id: uuid.UUID,
    source_description: str = Form(default="", min_length=0),
    submission_notes: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_investigator: dict = Depends(require_role("SYSTEM_ADMIN", "LEAD_INVESTIGATOR", "INVESTIGATOR"))
):
    """
    Ingest structural digital evidence into an active case environment.
    Calculates cryptographic hashes, enforces deduplication, and commits 
    Sequence 1 (ACQUISITION) to the chain of custody.
    """
    # 1. Validate Target Case Context
    case = db.execute(
        text("SELECT id, status FROM cases WHERE id = :id"),
        {"id": str(case_id)}
    ).fetchone()
    
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target case framework '{case_id}' does not exist."
        )
        
    if case.status == "CLOSED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot ingest evidence into a closed case file."
        )

    # 2. Normalize submission metadata so empty descriptions still ingest cleanly
    normalized_source_description = (source_description or "").strip()
    if not normalized_source_description:
        normalized_source_description = file.filename or "Unnamed evidence submission"

    # 3. Stream File Content to Memory & Compute Cryptographic Signatures
    file_bytes = await file.read()
    file_size = len(file_bytes)
    
    if file_size == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot upload empty zero-byte files.")

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    sha512_hash = hashlib.sha512(file_bytes).hexdigest()

    # 3. Deduplication Inspection Check
    duplicate = db.execute(
        text("SELECT id FROM file_submissions WHERE case_id = :case_id AND sha256_hash = :hash"),
        {"case_id": str(case_id), "hash": sha256_hash}
    ).fetchone()
    
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate evidence mismatch. This exact file payload already exists inside this case context."
        )

    # 4. Extract Structural File Signatures (Magic Verification)
    declared_mime = file.content_type
    detected_mime = declared_mime or "application/octet-stream"

    if magic is not None:
        try:
            mime_detector = magic.Magic(mime=True)
            detected_mime = mime_detector.from_buffer(file_bytes)
        except Exception:
            detected_mime = declared_mime or "application/octet-stream"
    else:
        extension = (file.filename or "").lower()
        if extension.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            detected_mime = "image/" + ("jpeg" if extension.endswith((".jpg", ".jpeg")) else "png" if extension.endswith(".png") else "gif" if extension.endswith(".gif") else "webp")
        elif extension.endswith((".mp4", ".mov", ".avi", ".mkv")):
            detected_mime = "video/mp4" if extension.endswith(".mp4") else "video/quicktime" if extension.endswith(".mov") else "video/x-msvideo" if extension.endswith(".avi") else "video/x-matroska"
        elif extension.endswith((".mp3", ".wav", ".flac")):
            detected_mime = "audio/mpeg" if extension.endswith(".mp3") else "audio/x-wav" if extension.endswith(".wav") else "audio/flac"
        elif extension.endswith(".txt"):
            detected_mime = "text/plain"
        elif extension.endswith(".pdf"):
            detected_mime = "application/pdf"
        elif extension.endswith(".zip"):
            detected_mime = "application/zip"

    # 5. Write Buffered Asset Securely to Storage Footprint
    submission_id = str(uuid.uuid4())
    file_extension = os.path.splitext(file.filename)[1].lower() or ".bin"
    stored_filename = f"{submission_id}{file_extension}"
    target_storage_path = os.path.join(UPLOAD_DIR, stored_filename)
    
    try:
        with open(target_storage_path, "wb") as buffer:
            buffer.write(file_bytes)
    except IOError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage filesystem write exception encountered: {str(e)}"
        )

    # 6. Commit Submission Metadata Entry to Database
    try:
        db.execute(
            text("""
                INSERT INTO file_submissions (
                    id, case_id, submitted_by, original_filename, stored_filename,
                    file_extension, file_size_bytes, mime_type_declared, mime_type_detected,
                    sha256_hash, sha512_hash, storage_path, source_description, submission_notes
                ) VALUES (
                    :id, :case_id, :submitted_by, :orig_name, :store_name,
                    :ext, :size, :declared, :detected, :sha256, :sha512, :path, :src, :notes
                )
            """),
            {
                "id": submission_id, "case_id": str(case_id), "submitted_by": current_investigator.get("id"),
                "orig_name": file.filename, "store_name": stored_filename, "ext": file_extension,
                "size": file_size, "declared": declared_mime, "detected": detected_mime,
                "sha256": sha256_hash, "sha512": sha512_hash, "path": target_storage_path,
                "src": normalized_source_description, "notes": submission_notes
            }
        )

        # 7. Commit Sequence 1 (ACQUISITION) Event to Chain of Custody Table
        db.execute(
            text("""
                INSERT INTO chain_of_custody_events (
                    id, case_id, submission_id, event_type, event_sequence,
                    actor_id, actor_role, actor_badge_number, event_description,
                    location_description, hash_at_event
                ) VALUES (
                    :event_id, :case_id, :sub_id, 'ACQUISITION', 1,
                    :actor_id, :role, :badge, :desc, :loc, :hash
                )
            """),
            {
                "event_id": str(uuid.uuid4()), "case_id": str(case_id), "sub_id": submission_id,
                "actor_id": current_investigator.get("id"), "role": current_investigator.get("role"),
                "badge": current_investigator.get("badge_number"),
                "desc": f"Evidence media file '{file.filename}' ingested and signed securely.",
                "loc": "HexShield Central Core Digital Intake Engine", "hash": sha256_hash
            }
        )
        db.commit()

        return {
            "status": "success",
            "message": "Evidence ingested and cataloged inside chain of custody record base.",
            "submission_id": submission_id,
            "sha256_hash": sha256_hash,
            "detected_mime_type": detected_mime
        }
    except Exception as e:
        db.rollback()
        if os.path.exists(target_storage_path):
            os.remove(target_storage_path)  # Cleanup residual disk state
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database synchronization error encountered: {str(e)}"
        )

