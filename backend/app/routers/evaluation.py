"""Administrator evaluation summary for the forensic benchmark."""

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status

from app.routers.auth import require_role

router = APIRouter()


@router.get("/evaluation/summary")
def evaluation_summary(
    admin: dict = Depends(require_role("SYSTEM_ADMIN")),
):
    report_path = Path(__file__).resolve().parents[2] / "docs" / "evaluation_report.json"
    if not report_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation report is not available.",
        )

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Evaluation report could not be read.",
        ) from exc

    return {
        "title": report.get("evaluation_title"),
        "framework": report.get("framework"),
        "dataset_size": report.get("test_dataset_size", 0),
        "metrics": report.get("metrics", {}),
        "confusion_matrix": report.get("confusion_matrix", {}),
        "caveat": "Preliminary prototype benchmark; not a universal deepfake accuracy claim.",
    }
