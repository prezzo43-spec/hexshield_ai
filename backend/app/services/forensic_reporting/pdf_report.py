# =============================================================================
# HexShield AI — PDF Forensic Report Generator
# Layer 3: Forensic Preservation and Reporting Module
#
# Generates court-ready PDF forensic reports using ReportLab.
# PDF reports are designed for:
#   - Court submission
#   - Inter-agency sharing
#   - Official forensic record keeping
# =============================================================================

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from app.services.forensic_reporting.report_generator import (
    ForensicReportData,
    compute_report_hash,
    ensure_reports_dir,
    determine_overall_verdict,
)

logger = logging.getLogger(__name__)

# Verdict colors for PDF rendering
VERDICT_COLORS = {
    "MALICIOUS":    (0.8, 0.1, 0.1),   # Red
    "SUSPICIOUS":   (0.9, 0.5, 0.0),   # Orange
    "CLEAN":        (0.1, 0.6, 0.1),   # Green
    "AUTHENTIC":    (0.1, 0.6, 0.1),   # Green
    "INCONCLUSIVE": (0.4, 0.4, 0.4),   # Gray
}


class PDFReportGenerator:
    """
    Generates court-ready PDF forensic reports.
    """

    REPORT_VERSION = "1.0.0"

    def generate(
        self, report_data: ForensicReportData
    ) -> Tuple[bytes, str, str]:
        """
        Generate a PDF forensic report.

        Args:
            report_data: Assembled ForensicReportData object

        Returns:
            Tuple of (report_bytes, report_filename, report_hash)
        """
        logger.info(
            f"Generating PDF report for submission "
            f"{report_data.submission.id}"
        )

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                HRFlowable,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            import io

            buffer = io.BytesIO()

            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
            )

            styles = getSampleStyleSheet()
            story = []

            # Custom styles
            title_style = ParagraphStyle(
                "ForensicTitle",
                parent=styles["Title"],
                fontSize=18,
                spaceAfter=6,
                textColor=colors.HexColor("#1a1a2e"),
            )
            heading_style = ParagraphStyle(
                "ForensicHeading",
                parent=styles["Heading1"],
                fontSize=13,
                spaceBefore=14,
                spaceAfter=6,
                textColor=colors.HexColor("#16213e"),
            )
            subheading_style = ParagraphStyle(
                "ForensicSubHeading",
                parent=styles["Heading2"],
                fontSize=11,
                spaceBefore=10,
                spaceAfter=4,
                textColor=colors.HexColor("#0f3460"),
            )
            normal_style = ParagraphStyle(
                "ForensicNormal",
                parent=styles["Normal"],
                fontSize=9,
                spaceAfter=4,
                leading=14,
            )
            small_style = ParagraphStyle(
                "ForensicSmall",
                parent=styles["Normal"],
                fontSize=8,
                textColor=colors.HexColor("#555555"),
            )
            mono_style = ParagraphStyle(
                "ForensicMono",
                parent=styles["Code"],
                fontSize=7,
                leading=10,
                textColor=colors.HexColor("#333333"),
            )

            overall_verdict = determine_overall_verdict(
                hex_risk=report_data.hex_analysis.overall_risk_level
                if report_data.hex_analysis else None,
                ai_verdict=report_data.ai_analysis.verdict
                if report_data.ai_analysis else None,
            )

            verdict_rgb = VERDICT_COLORS.get(
                overall_verdict, (0.4, 0.4, 0.4)
            )
            verdict_color = colors.Color(*verdict_rgb)

            # =================================================================
            # HEADER
            # =================================================================
            story.append(
                Paragraph("HEXSHIELD AI", title_style)
            )
            story.append(
                Paragraph(
                    "Digital Forensic Analysis Report",
                    ParagraphStyle(
                        "Subtitle",
                        parent=styles["Normal"],
                        fontSize=12,
                        textColor=colors.HexColor("#444444"),
                        spaceAfter=4,
                    ),
                )
            )
            story.append(
                Paragraph(
                    f"Classification: "
                    f"<b>{report_data.case.classification}</b>",
                    small_style,
                )
            )
            story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
            story.append(Spacer(1, 0.3 * cm))

            # =================================================================
            # REPORT METADATA TABLE
            # =================================================================
            story.append(Paragraph("Report Information", heading_style))

            meta_data = [
                ["Report ID", report_data.report_id],
                ["Report Type", report_data.report_type],
                ["Generated At", report_data.generated_at],
                ["Issuing Authority", report_data.issuing_authority],
                ["Jurisdiction", report_data.jurisdiction],
                ["Overall Verdict", overall_verdict],
            ]

            meta_table = Table(
                meta_data,
                colWidths=[4 * cm, 13 * cm],
            )
            meta_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("TEXTCOLOR", (1, 5), (1, 5), verdict_color),
                    ("FONTNAME", (1, 5), (1, 5), "Helvetica-Bold"),
                ])
            )
            story.append(meta_table)

            # =================================================================
            # CASE INFORMATION
            # =================================================================
            story.append(Paragraph("Case Information", heading_style))

            case_data = [
                ["Case Reference", report_data.case.case_reference],
                ["Case Title", report_data.case.case_title],
                ["Classification", report_data.case.classification],
                ["Jurisdiction", report_data.case.jurisdiction],
                ["Applicable Law", report_data.case.applicable_law or "N/A"],
                ["Lead Investigator", report_data.case.lead_investigator.full_name],
                ["Badge Number", report_data.case.lead_investigator.badge_number or "N/A"],
                ["Organization", report_data.case.lead_investigator.organization],
            ]

            case_table = Table(case_data, colWidths=[4 * cm, 13 * cm])
            case_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ])
            )
            story.append(case_table)

            # =================================================================
            # EVIDENCE RECORD
            # =================================================================
            story.append(Paragraph("Evidence Record", heading_style))

            evidence_data = [
                ["Submission ID", report_data.submission.id],
                ["Original Filename", report_data.submission.original_filename],
                ["File Size", f"{report_data.submission.file_size_bytes:,} bytes"],
                ["Ingestion Timestamp", report_data.submission.ingestion_timestamp],
                ["Submitted By", report_data.submission.submitted_by.full_name],
                ["MIME Type (Declared)", report_data.submission.mime_type_declared or "N/A"],
                ["MIME Type (Detected)", report_data.submission.mime_type_detected or "N/A"],
            ]

            evidence_table = Table(evidence_data, colWidths=[4 * cm, 13 * cm])
            evidence_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ])
            )
            story.append(evidence_table)

            # Cryptographic hashes
            story.append(Paragraph("Cryptographic Integrity", subheading_style))
            story.append(
                Paragraph(
                    f"<b>SHA-256:</b> {report_data.submission.sha256_hash}",
                    mono_style,
                )
            )
            story.append(
                Paragraph(
                    f"<b>SHA-512:</b> {report_data.submission.sha512_hash}",
                    mono_style,
                )
            )

            # =================================================================
            # LAYER 1 — HEX TRIAGE
            # =================================================================
            story.append(
                Paragraph("Layer 1: Hex-Level Binary Triage", heading_style)
            )

            if report_data.hex_analysis:
                hex_data = report_data.hex_analysis
                risk_color = VERDICT_COLORS.get(
                    hex_data.overall_risk_level, (0.4, 0.4, 0.4)
                )

                hex_table_data = [
                    ["Risk Level", hex_data.overall_risk_level],
                    ["Shannon Entropy", f"{hex_data.shannon_entropy:.6f} bits/byte"],
                    ["Entropy Verdict", hex_data.entropy_verdict],
                    ["MIME Spoof Detected", "YES" if hex_data.mime_spoof_detected else "NO"],
                    ["File Format Identified", hex_data.file_format_identified],
                    ["Threat Relevance", hex_data.threat_relevance],
                    ["Suspicious Sections", str(hex_data.suspicious_sections_count)],
                    ["Engine Version", hex_data.engine_version],
                    ["Analyzed At", hex_data.analyzed_at],
                ]

                hex_table = Table(
                    hex_table_data, colWidths=[5 * cm, 12 * cm]
                )
                hex_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                        (
                            "TEXTCOLOR",
                            (1, 0),
                            (1, 0),
                            colors.Color(*risk_color),
                        ),
                        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    ])
                )
                story.append(hex_table)

                story.append(Paragraph("Risk Summary", subheading_style))
                story.append(Paragraph(hex_data.risk_summary, normal_style))

                if hex_data.mime_spoof_details:
                    story.append(
                        Paragraph("MIME Spoofing Details", subheading_style)
                    )
                    story.append(
                        Paragraph(hex_data.mime_spoof_details, normal_style)
                    )

                story.append(Paragraph("Magic Bytes Extracted", subheading_style))
                story.append(
                    Paragraph(
                        hex_data.magic_bytes_extracted[:64] + "...",
                        mono_style,
                    )
                )
            else:
                story.append(
                    Paragraph(
                        "Hex triage analysis was not performed on this submission.",
                        normal_style,
                    )
                )

            # =================================================================
            # LAYER 2 — AI ANALYSIS
            # =================================================================
            story.append(
                Paragraph(
                    "Layer 2: AI Deepfake Detection Analysis", heading_style
                )
            )

            if report_data.ai_analysis:
                ai_data = report_data.ai_analysis
                ai_verdict_color = VERDICT_COLORS.get(
                    ai_data.verdict, (0.4, 0.4, 0.4)
                )

                ai_table_data = [
                    ["Verdict", ai_data.verdict],
                    ["Media Type", ai_data.media_type],
                    ["Authenticity Score", f"{ai_data.authenticity_score:.4f}"],
                    ["Manipulation Confidence", f"{ai_data.manipulation_confidence:.4f}"],
                    ["Model Name", ai_data.model_name],
                    ["Model Version", ai_data.model_version],
                    ["Processing Duration", f"{ai_data.processing_duration_ms} ms"],
                    ["Analyzed At", ai_data.analyzed_at],
                ]

                ai_table = Table(
                    ai_table_data, colWidths=[5 * cm, 12 * cm]
                )
                ai_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                        (
                            "TEXTCOLOR",
                            (1, 0),
                            (1, 0),
                            colors.Color(*ai_verdict_color),
                        ),
                        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                    ])
                )
                story.append(ai_table)
            else:
                story.append(
                    Paragraph(
                        "AI deepfake analysis was not performed on this submission.",
                        normal_style,
                    )
                )

            # =================================================================
            # CHAIN OF CUSTODY
            # =================================================================
            story.append(
                Paragraph("Chain of Custody", heading_style)
            )
            story.append(
                Paragraph(
                    "The following events constitute the complete chain of custody "
                    "for this evidence item, recorded in compliance with "
                    "ISO/IEC 27037 digital evidence standards.",
                    normal_style,
                )
            )

            for event in report_data.custody_chain:
                story.append(
                    Paragraph(
                        f"<b>Event {event.event_sequence}: "
                        f"{event.event_type}</b>",
                        subheading_style,
                    )
                )
                custody_data = [
                    ["Timestamp", event.event_timestamp],
                    ["Actor", f"{event.actor_name} ({event.actor_badge or 'N/A'})"],
                    ["Role", event.actor_role],
                    ["Hash at Event", event.hash_at_event or "N/A"],
                    ["Hash Verified", "YES" if event.hash_verified else "NO"],
                    ["Description", event.event_description],
                ]
                if event.notes:
                    custody_data.append(["Notes", event.notes])

                custody_table = Table(
                    custody_data, colWidths=[4 * cm, 13 * cm]
                )
                custody_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ])
                )
                story.append(custody_table)
                story.append(Spacer(1, 0.2 * cm))

            # =================================================================
            # EXAMINER NOTES
            # =================================================================
            if report_data.examiner_notes:
                story.append(Paragraph("Examiner Notes", heading_style))
                story.append(
                    Paragraph(report_data.examiner_notes, normal_style)
                )

            # =================================================================
            # LEGAL DISCLAIMER
            # =================================================================
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph("Legal Disclaimer", subheading_style))
            story.append(
                Paragraph(
                    "This report was generated by HexShield AI, a digital forensic "
                    "analysis platform. The findings contained herein are based on "
                    "automated analysis and should be reviewed by a qualified forensic "
                    "examiner before presentation in legal proceedings. Hash values "
                    "provided constitute the cryptographic integrity baseline for the "
                    "analyzed evidence under ISO/IEC 27037 standards.",
                    small_style,
                )
            )

            # Build PDF
            doc.build(story)
            report_bytes = buffer.getvalue()

            # Generate filename
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            case_ref = report_data.case.case_reference.replace("-", "_")
            report_filename = (
                f"HEXSHIELD_{case_ref}_{report_data.submission.id[:8]}"
                f"_{timestamp}_FORENSIC_REPORT.pdf"
            )

            # Compute report hash
            report_hash = compute_report_hash(report_bytes)

            # Save to disk
            reports_dir = ensure_reports_dir()
            report_path = reports_dir / report_filename
            report_path.write_bytes(report_bytes)

            logger.info(
                f"PDF report generated: {report_filename} "
                f"({len(report_bytes)} bytes), hash={report_hash[:16]}..."
            )

            return report_bytes, report_filename, report_hash

        except ImportError:
            logger.error(
                "ReportLab is not installed. "
                "Install reportlab to generate PDF reports."
            )
            raise RuntimeError(
                "ReportLab is required for PDF report generation. "
                "Run: pip install reportlab"
            )
        except Exception as e:
            logger.error(f"PDF report generation failed: {e}", exc_info=True)
            raise