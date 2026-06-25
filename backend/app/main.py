# =============================================================================
# HexShield AI — FastAPI Application Entry Point
# API Framework
#
# This is the root of the backend application. It:
#   - Creates and configures the FastAPI app instance
#   - Registers all API routers
#   - Configures CORS for frontend communication
#   - Runs startup and shutdown lifecycle events
#   - Provides the health check endpoint
# =============================================================================

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings, ensure_storage_dirs
from app.database import verify_database_connection

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s  %(levelname)s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Application Lifespan
# Handles startup and shutdown events cleanly.
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Code before 'yield' runs at startup.
    Code after 'yield' runs at shutdown.
    """
    # Startup
    logger.info("=" * 60)
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment : {settings.APP_ENV}")
    logger.info(f"Debug mode  : {settings.DEBUG}")
    logger.info("=" * 60)

    # Ensure storage directories exist
    ensure_storage_dirs()
    logger.info("Storage directories verified.")

    # Verify database connection
    db_ok = verify_database_connection()
    if not db_ok:
        logger.critical(
            "Database connection failed at startup. "
            "Check DATABASE_URL in .env"
        )
    else:
        logger.info("Database connection established.")

    logger.info(f"{settings.APP_NAME} is ready to accept requests.")

    yield

    # Shutdown
    logger.info(f"{settings.APP_NAME} shutting down.")


# -----------------------------------------------------------------------------
# FastAPI Application Instance
# -----------------------------------------------------------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "HexShield AI: A Multi-Layered Forensic Engine for Malicious Streams "
        "and Manipulated Media. Provides hex-level binary triage, AI-driven "
        "deepfake detection, and ISO/IEC 27037 compliant chain-of-custody "
        "forensic reporting."
    ),
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# CORS Middleware
# Allows the Next.js frontend to communicate with this API.
# -----------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Request Timing Middleware
# Adds X-Process-Time header to every response for performance monitoring.
# -----------------------------------------------------------------------------
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.monotonic()
    response = await call_next(request)
    process_time = (time.monotonic() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response


# -----------------------------------------------------------------------------
# Global Exception Handler
# Returns structured JSON errors instead of raw stack traces.
# -----------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please contact the system administrator.",
            "path": str(request.url),
        },
    )


# -----------------------------------------------------------------------------
# API Routers
# Each router handles one domain of the API.
# Imported here and registered with a prefix and tags.
# -----------------------------------------------------------------------------
from app.routers import health, investigators, cases, submissions, analysis, reports

app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(investigators.router, prefix="/api/v1", tags=["Investigators"])
app.include_router(cases.router, prefix="/api/v1", tags=["Cases"])
app.include_router(submissions.router, prefix="/api/v1", tags=["File Submissions"])
app.include_router(analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])