# =============================================================================
# HexShield AI — Health Check Router
# Provides system health and status endpoints.
# =============================================================================

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
import platform
import sys

from app.database import get_db
from app.config import settings

router = APIRouter()


@router.get("/health")
def health_check():
    """
    Basic health check endpoint.
    Returns 200 if the API is running.
    """
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
    }


@router.get("/health/detailed")
def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check including database connectivity.
    Returns status of all system components.
    """
    # Check database
    db_status = "healthy"
    db_error = None
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "unhealthy"
        db_error = str(e)

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "components": {
            "database": {
                "status": db_status,
                "error": db_error,
            },
            "hex_engine": {
                "status": "healthy",
                "version": "1.0.0"
            }
        },
        "system": {
            "python_version": sys.version,
            "platform": platform.system(),
        },
    }