# =============================================================================
# HexShield AI — Forensic Reporting Package
# Exposes the public API for Layer 3: Forensic Preservation and Reporting
# =============================================================================

from app.services.forensic_reporting.report_generator import (
    ForensicReportData,
    ForensicReportAssembler,
    compute_report_hash,
    ensure_reports_dir,
    determine_overall_verdict,
)
from app.services.forensic_reporting.json_report import JSONReportGenerator
from app.services.forensic_reporting.pdf_report import PDFReportGenerator

__all__ = [
    "ForensicReportData",
    "ForensicReportAssembler",
    "compute_report_hash",
    "ensure_reports_dir",
    "determine_overall_verdict",
    "JSONReportGenerator",
    "PDFReportGenerator",
]