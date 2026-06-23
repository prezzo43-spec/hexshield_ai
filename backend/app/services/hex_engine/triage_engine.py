# =============================================================================
# HexShield AI — Hex-Level Binary Triage Engine
# Layer 1: Core Orchestration Module
#
# This module is the main entry point for Layer 1 analysis.
# It coordinates:
#   1. File ingestion and cryptographic hashing
#   2. Magic byte extraction and signature matching
#   3. MIME type spoofing detection
#   4. Shannon Entropy calculation (full file and per-section)
#   5. Risk verdict determination
#   6. Structured result packaging for database persistence
# =============================================================================

import hashlib
import logging
import time
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from pathlib import Path

from app.services.hex_engine.magic_bytes_db import (
    MagicSignature,
    get_signature_by_hex,
    get_signatures_by_extension,
    get_signatures_by_mime,
)
from app.services.hex_engine.entropy import (
    analyze_entropy,
    analyze_file_sections,
    EntropyResult,
    SectionEntropyResult,
)
from app.config import settings

logger = logging.getLogger(__name__)

# Engine version — increment when logic changes to preserve analysis lineage
ENGINE_VERSION = "1.0.0"

# Number of bytes read for magic byte identification
MAGIC_BYTES_READ_LENGTH = settings.MAGIC_BYTES_READ_LENGTH


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TriageResult:
    """
    Complete result of a Layer 1 hex triage analysis.
    This object is serialized and persisted to the hex_analysis_results table.
    """

    # File identity
    original_filename:      str
    file_size_bytes:        int
    sha256_hash:            str
    sha512_hash:            str

    # Magic byte findings
    magic_bytes_hex:        str
    matched_signature:      Optional[MagicSignature]
    mime_type_declared:     Optional[str]
    mime_type_detected:     Optional[str]
    mime_spoof_detected:    bool
    mime_spoof_details:     Optional[str]

    # Header analysis
    file_header_valid:          bool
    header_anomalies_detected:  bool
    header_anomaly_details:     Optional[str]

    # Entropy analysis
    entropy_result:             EntropyResult
    section_entropy_results:    List[SectionEntropyResult]
    suspicious_sections:        List[Dict]

    # Overall verdict
    overall_risk_level:     str   # CLEAN | SUSPICIOUS | MALICIOUS | UNKNOWN
    risk_summary:           str

    # Operational metadata
    engine_version:         str
    analysis_duration_ms:   int
    errors:                 List[str] = field(default_factory=list)


# =============================================================================
# CORE TRIAGE ENGINE
# =============================================================================

class HexTriageEngine:
    """
    Layer 1: Hex-Level Binary Triage Engine.

    Analyzes raw file byte streams to detect:
    - MIME type spoofing (declared type vs magic byte detected type)
    - High entropy indicating encryption, packing, or obfuscation
    - Suspicious byte patterns and structural anomalies

    Usage:
        engine = HexTriageEngine()
        result = engine.analyze_file(file_path, declared_mime_type)
    """

    def __init__(
        self,
        elevated_threshold: float = None,
        critical_threshold: float = None,
    ):
        self.elevated_threshold = (
            elevated_threshold or settings.ENTROPY_ELEVATED_THRESHOLD
        )
        self.critical_threshold = (
            critical_threshold or settings.ENTROPY_CRITICAL_THRESHOLD
        )
        logger.info(
            f"HexTriageEngine initialized — "
            f"elevated_threshold={self.elevated_threshold}, "
            f"critical_threshold={self.critical_threshold}, "
            f"engine_version={ENGINE_VERSION}"
        )

    # -------------------------------------------------------------------------
    # PUBLIC — Main Analysis Entry Point
    # -------------------------------------------------------------------------

    def analyze_file(
        self,
        file_path: str,
        declared_mime_type: Optional[str] = None,
    ) -> TriageResult:
        """
        Perform complete Layer 1 hex triage on a file.

        Args:
            file_path          : Absolute or relative path to the file
            declared_mime_type : MIME type as declared by submitter or OS

        Returns:
            TriageResult containing all analysis findings
        """
        start_time = time.monotonic()
        errors = []
        path = Path(file_path)

        logger.info(f"Starting hex triage: {path.name} ({path.stat().st_size} bytes)")

        # Step 1 — Read file bytes
        try:
            file_bytes = self._read_file(file_path)
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            return self._error_result(str(path.name), str(e), start_time)

        file_size = len(file_bytes)

        # Step 2 — Compute cryptographic hashes
        sha256, sha512 = self._compute_hashes(file_bytes)

        # Step 3 — Extract magic bytes
        magic_hex = self._extract_magic_bytes(file_bytes)

        # Step 4 — Match magic bytes against signatures database
        matched_sig = get_signature_by_hex(magic_hex)

        # Step 5 — Determine detected MIME type
        mime_detected = matched_sig.mime_type if matched_sig else None

        # Step 6 — MIME spoofing detection
        spoof_detected, spoof_details = self._detect_mime_spoof(
            original_filename=path.name,
            declared_mime=declared_mime_type,
            detected_mime=mime_detected,
            matched_sig=matched_sig,
            magic_hex=magic_hex,
        )

        # Step 7 — Header validation
        header_valid, header_anomalies, header_details = self._validate_header(
            file_bytes=file_bytes,
            matched_sig=matched_sig,
            magic_hex=magic_hex,
        )

        # Step 8 — Shannon Entropy analysis (full file)
        entropy_result = analyze_entropy(
            data=file_bytes,
            elevated_threshold=self.elevated_threshold,
            critical_threshold=self.critical_threshold,
        )

        # Step 9 — Per-section entropy analysis
        section_results = analyze_file_sections(
            data=file_bytes,
            section_size=256,
            critical_threshold=self.critical_threshold,
        )

        # Step 10 — Build suspicious sections list
        suspicious_sections = self._build_suspicious_sections(section_results)

        # Step 11 — Determine overall risk verdict
        risk_level, risk_summary = self._determine_risk_verdict(
            spoof_detected=spoof_detected,
            entropy_verdict=entropy_result.verdict,
            header_anomalies=header_anomalies,
            matched_sig=matched_sig,
            suspicious_sections=suspicious_sections,
        )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        logger.info(
            f"Hex triage complete: {path.name} — "
            f"risk={risk_level}, entropy={entropy_result.entropy_value:.4f}, "
            f"spoof={spoof_detected}, duration={duration_ms}ms"
        )

        return TriageResult(
            original_filename=path.name,
            file_size_bytes=file_size,
            sha256_hash=sha256,
            sha512_hash=sha512,
            magic_bytes_hex=magic_hex,
            matched_signature=matched_sig,
            mime_type_declared=declared_mime_type,
            mime_type_detected=mime_detected,
            mime_spoof_detected=spoof_detected,
            mime_spoof_details=spoof_details,
            file_header_valid=header_valid,
            header_anomalies_detected=header_anomalies,
            header_anomaly_details=header_details,
            entropy_result=entropy_result,
            section_entropy_results=section_results,
            suspicious_sections=suspicious_sections,
            overall_risk_level=risk_level,
            risk_summary=risk_summary,
            engine_version=ENGINE_VERSION,
            analysis_duration_ms=duration_ms,
            errors=errors,
        )

    def analyze_bytes(
        self,
        data: bytes,
        filename: str = "unknown",
        declared_mime_type: Optional[str] = None,
    ) -> TriageResult:
        """
        Perform triage on raw bytes directly (without a file path).
        Used for in-memory analysis and unit testing.

        Args:
            data               : Raw bytes to analyze
            filename           : Virtual filename for reporting
            declared_mime_type : MIME type as declared by submitter
        """
        start_time = time.monotonic()

        file_size = len(data)
        sha256, sha512 = self._compute_hashes(data)
        magic_hex = self._extract_magic_bytes(data)
        matched_sig = get_signature_by_hex(magic_hex)
        mime_detected = matched_sig.mime_type if matched_sig else None

        spoof_detected, spoof_details = self._detect_mime_spoof(
            original_filename=filename,
            declared_mime=declared_mime_type,
            detected_mime=mime_detected,
            matched_sig=matched_sig,
            magic_hex=magic_hex,
        )

        header_valid, header_anomalies, header_details = self._validate_header(
            file_bytes=data,
            matched_sig=matched_sig,
            magic_hex=magic_hex,
        )

        entropy_result = analyze_entropy(
            data=data,
            elevated_threshold=self.elevated_threshold,
            critical_threshold=self.critical_threshold,
        )

        section_results = analyze_file_sections(
            data=data,
            section_size=256,
            critical_threshold=self.critical_threshold,
        )

        suspicious_sections = self._build_suspicious_sections(section_results)

        risk_level, risk_summary = self._determine_risk_verdict(
            spoof_detected=spoof_detected,
            entropy_verdict=entropy_result.verdict,
            header_anomalies=header_anomalies,
            matched_sig=matched_sig,
            suspicious_sections=suspicious_sections,
        )

        duration_ms = int((time.monotonic() - start_time) * 1000)

        return TriageResult(
            original_filename=filename,
            file_size_bytes=file_size,
            sha256_hash=sha256,
            sha512_hash=sha512,
            magic_bytes_hex=magic_hex,
            matched_signature=matched_sig,
            mime_type_declared=declared_mime_type,
            mime_type_detected=mime_detected,
            mime_spoof_detected=spoof_detected,
            mime_spoof_details=spoof_details,
            file_header_valid=header_valid,
            header_anomalies_detected=header_anomalies,
            header_anomaly_details=header_details,
            entropy_result=entropy_result,
            section_entropy_results=section_results,
            suspicious_sections=suspicious_sections,
            overall_risk_level=risk_level,
            risk_summary=risk_summary,
            engine_version=ENGINE_VERSION,
            analysis_duration_ms=duration_ms,
            errors=[],
        )

    # -------------------------------------------------------------------------
    # PRIVATE — Analysis Sub-Methods
    # -------------------------------------------------------------------------

    def _read_file(self, file_path: str) -> bytes:
        """Read file bytes from disk."""
        with open(file_path, "rb") as f:
            return f.read()

    def _compute_hashes(self, data: bytes):
        """
        Compute SHA-256 and SHA-512 hashes of the file bytes.
        These are the primary cryptographic integrity fingerprints.
        """
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
        return sha256, sha512

    def _extract_magic_bytes(self, data: bytes) -> str:
        """
        Extract the leading bytes of a file and return as uppercase hex string.
        The number of bytes read is controlled by MAGIC_BYTES_READ_LENGTH.
        """
        magic_bytes = data[:MAGIC_BYTES_READ_LENGTH]
        return magic_bytes.hex().upper()

    def _detect_mime_spoof(
        self,
        original_filename: str,
        declared_mime: Optional[str],
        detected_mime: Optional[str],
        matched_sig: Optional[MagicSignature],
        magic_hex: str,
    ):
        """
        Detect MIME type spoofing by comparing:
        1. The declared MIME type vs the magic-byte-detected MIME type
        2. The file extension vs the magic-byte-detected format
        3. The file extension vs the declared MIME type

        Returns:
            Tuple of (spoof_detected: bool, spoof_details: Optional[str])
        """
        spoof_detected = False
        details = []

        file_ext = Path(original_filename).suffix.lower()

        # Check 1 — Declared MIME vs detected MIME
        if declared_mime and detected_mime:
            # Normalize for comparison
            declared_base = declared_mime.split(";")[0].strip().lower()
            detected_base = detected_mime.lower()

            if declared_base != detected_base:
                # Allow known safe aliases
                safe_aliases = {
                    ("application/zip", "application/vnd.openxmlformats-officedocument"),
                    ("application/octet-stream", "application/x-dosexec"),
                }
                pair = (declared_base, detected_base)
                reverse_pair = (detected_base, declared_base)

                if pair not in safe_aliases and reverse_pair not in safe_aliases:
                    spoof_detected = True
                    details.append(
                        f"MIME mismatch: declared='{declared_mime}' "
                        f"but magic bytes indicate '{detected_mime}'."
                    )

        # Check 2 — File extension vs detected magic signature
        if matched_sig and file_ext:
            expected_extensions = [e.lower() for e in matched_sig.common_extensions]
            if file_ext not in expected_extensions and expected_extensions != [""]:
                spoof_detected = True
                details.append(
                    f"Extension mismatch: file extension '{file_ext}' does not match "
                    f"magic-byte-identified format '{matched_sig.format_name}' "
                    f"(expected extensions: {matched_sig.common_extensions})."
                )

        # Check 3 — No signature matched but file has a known extension
        if not matched_sig and file_ext in [
            ".exe", ".dll", ".pdf", ".jpg", ".png", ".zip", ".docx"
        ]:
            details.append(
                f"WARNING: No known magic signature matched for "
                f"file with extension '{file_ext}'. "
                f"Leading bytes: {magic_hex[:16]}..."
            )

        spoof_details = " | ".join(details) if details else None
        return spoof_detected, spoof_details

    def _validate_header(
        self,
        file_bytes: bytes,
        matched_sig: Optional[MagicSignature],
        magic_hex: str,
    ):
        """
        Perform basic file header structural validation.
        Checks for truncation, null-byte headers, and format-specific
        structural requirements.

        Returns:
            Tuple of (header_valid: bool, anomalies_detected: bool,
                      anomaly_details: Optional[str])
        """
        anomalies = []

        # Check 1 — File is not empty
        if len(file_bytes) == 0:
            return False, True, "File is empty — zero bytes."

        # Check 2 — File is not suspiciously small
        if len(file_bytes) < 4:
            anomalies.append(
                f"File is extremely small ({len(file_bytes)} bytes). "
                f"May be truncated or a stub."
            )

        # Check 3 — Null-byte header (common in memory dump artifacts)
        if file_bytes[:4] == b"\x00\x00\x00\x00":
            anomalies.append(
                "File begins with four null bytes. "
                "Possible memory dump artifact or deliberate header erasure."
            )

        # Check 4 — PE-specific validation
        if matched_sig and "PE" in matched_sig.format_name:
            if len(file_bytes) > 60:
                # PE header contains pointer to PE signature at offset 0x3C
                pe_offset = int.from_bytes(file_bytes[60:64], byteorder="little")
                if pe_offset + 4 <= len(file_bytes):
                    pe_sig = file_bytes[pe_offset: pe_offset + 4]
                    if pe_sig != b"PE\x00\x00":
                        anomalies.append(
                            f"PE signature missing at expected offset {pe_offset}. "
                            f"Found: {pe_sig.hex().upper()}. "
                            f"File may be corrupted or partially overwritten."
                        )

        header_valid = len(anomalies) == 0
        anomalies_detected = len(anomalies) > 0
        anomaly_details = " | ".join(anomalies) if anomalies else None

        return header_valid, anomalies_detected, anomaly_details

    def _build_suspicious_sections(
        self, section_results: List[SectionEntropyResult]
    ) -> List[Dict]:
        """
        Convert flagged SectionEntropyResult objects into
        serializable dicts for JSON storage in the database.
        """
        return [
            {
                "offset": r.offset,
                "length": r.length,
                "entropy": r.entropy_value,
                "flag": "HIGH_ENTROPY_SECTION",
            }
            for r in section_results
            if r.is_suspicious
        ]

    def _determine_risk_verdict(
        self,
        spoof_detected: bool,
        entropy_verdict: str,
        header_anomalies: bool,
        matched_sig: Optional[MagicSignature],
        suspicious_sections: List[Dict],
    ):
        """
        Determine the overall risk level based on all Layer 1 findings.

        Risk matrix:
          MALICIOUS  — MIME spoof + CRITICAL entropy, OR
                       CRITICAL threat signature + CRITICAL entropy
          SUSPICIOUS — Any single high-risk indicator
          CLEAN      — No indicators detected
          UNKNOWN    — No signature match, inconclusive

        Returns:
            Tuple of (risk_level: str, risk_summary: str)
        """
        risk_factors = []

        if spoof_detected:
            risk_factors.append("MIME_SPOOF")
        if entropy_verdict == "CRITICAL":
            risk_factors.append("CRITICAL_ENTROPY")
        if entropy_verdict == "ELEVATED":
            risk_factors.append("ELEVATED_ENTROPY")
        if header_anomalies:
            risk_factors.append("HEADER_ANOMALY")
        if matched_sig and matched_sig.threat_relevance == "CRITICAL":
            risk_factors.append("CRITICAL_FORMAT")
        if matched_sig and matched_sig.threat_relevance == "HIGH":
            risk_factors.append("HIGH_THREAT_FORMAT")
        if len(suspicious_sections) > 3:
            risk_factors.append("MULTIPLE_HIGH_ENTROPY_SECTIONS")

        # Risk determination logic
        if "MIME_SPOOF" in risk_factors and "CRITICAL_ENTROPY" in risk_factors:
            risk_level = "MALICIOUS"
            risk_summary = (
                "MALICIOUS: File exhibits MIME spoofing combined with critical "
                "entropy — strong indicators of an obfuscated malicious payload "
                "disguised as a benign file type."
            )
        elif "CRITICAL_FORMAT" in risk_factors and "CRITICAL_ENTROPY" in risk_factors:
            risk_level = "MALICIOUS"
            risk_summary = (
                "MALICIOUS: Executable format with critical entropy detected. "
                "Consistent with a packed or encrypted malware binary."
            )
        elif len(risk_factors) >= 2:
            risk_level = "SUSPICIOUS"
            risk_summary = (
                f"SUSPICIOUS: Multiple risk indicators detected — "
                f"{', '.join(risk_factors)}. Manual forensic review required."
            )
        elif len(risk_factors) == 1:
            risk_level = "SUSPICIOUS"
            risk_summary = (
                f"SUSPICIOUS: Single risk indicator detected — "
                f"{risk_factors[0]}. Further analysis recommended."
            )
        elif not matched_sig:
            risk_level = "UNKNOWN"
            risk_summary = (
                "UNKNOWN: No magic byte signature matched. "
                "File format could not be identified. Manual review required."
            )
        else:
            risk_level = "CLEAN"
            risk_summary = (
                f"CLEAN: No risk indicators detected. "
                f"File identified as '{matched_sig.format_name}' with "
                f"normal entropy characteristics."
            )

        return risk_level, risk_summary

    # -------------------------------------------------------------------------
    # PRIVATE — Error Handling
    # -------------------------------------------------------------------------

    def _error_result(
        self, filename: str, error_message: str, start_time: float
    ) -> TriageResult:
        """Return a safe error TriageResult when analysis cannot proceed."""
        from app.services.hex_engine.entropy import EntropyResult
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return TriageResult(
            original_filename=filename,
            file_size_bytes=0,
            sha256_hash="",
            sha512_hash="",
            magic_bytes_hex="",
            matched_signature=None,
            mime_type_declared=None,
            mime_type_detected=None,
            mime_spoof_detected=False,
            mime_spoof_details=None,
            file_header_valid=False,
            header_anomalies_detected=True,
            header_anomaly_details=f"Analysis failed: {error_message}",
            entropy_result=EntropyResult(
                entropy_value=0.0,
                verdict="NORMAL",
                elevated_threshold=self.elevated_threshold,
                critical_threshold=self.critical_threshold,
                byte_distribution={i: 0 for i in range(256)},
                total_bytes_analyzed=0,
                unique_byte_count=0,
                most_frequent_bytes=[],
                least_frequent_bytes=[],
                analysis_notes=[f"Analysis failed: {error_message}"],
            ),
            section_entropy_results=[],
            suspicious_sections=[],
            overall_risk_level="UNKNOWN",
            risk_summary=f"Analysis could not be completed: {error_message}",
            engine_version=ENGINE_VERSION,
            analysis_duration_ms=duration_ms,
            errors=[error_message],
        )