# =============================================================================
# HexShield AI — Layer 1 Unit Tests
# Step 4: Comprehensive tests for the Hex-Level Binary Triage Engine
#
# Test coverage:
#   - Shannon Entropy calculations
#   - Magic byte signature matching
#   - MIME spoofing detection
#   - Header anomaly detection
#   - Overall risk verdict logic
#   - Analysis of all 10 simulated test files
# =============================================================================

import sys
import pytest
from pathlib import Path

# Add backend root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.hex_engine import (
    HexTriageEngine,
    calculate_shannon_entropy,
    analyze_entropy,
    analyze_file_sections,
    get_signature_by_hex,
    get_signatures_by_extension,
    get_all_critical_signatures,
)

# Path to generated test files
TEST_FILES_DIR = Path(__file__).parent / "test_files"


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def engine():
    """Shared HexTriageEngine instance for all tests."""
    return HexTriageEngine(
        elevated_threshold=6.5,
        critical_threshold=7.2,
    )


@pytest.fixture(scope="module")
def test_files():
    """Load all generated test files into memory once."""
    files = {}
    for path in TEST_FILES_DIR.iterdir():
        if path.is_file():
            files[path.name] = path.read_bytes()
    return files


# =============================================================================
# SECTION 1: Shannon Entropy Unit Tests
# =============================================================================

class TestShannonEntropy:

    def test_empty_bytes_returns_zero(self):
        """Empty input must return 0.0 entropy."""
        result = calculate_shannon_entropy(b"")
        assert result == 0.0

    def test_single_byte_repeated_returns_zero(self):
        """
        A stream of identical bytes has no randomness.
        Entropy must be 0.0.
        """
        data = b"\x00" * 1024
        result = calculate_shannon_entropy(data)
        assert result == 0.0

    def test_two_values_equal_distribution(self):
        """
        Two alternating byte values with equal distribution
        should produce entropy of exactly 1.0.
        """
        data = b"\x00\xFF" * 512
        result = calculate_shannon_entropy(data)
        assert abs(result - 1.0) < 0.001

    def test_random_bytes_near_maximum_entropy(self):
        """
        Cryptographically random bytes should produce
        entropy close to the theoretical maximum of 8.0.
        """
        import os
        data = os.urandom(8192)
        result = calculate_shannon_entropy(data)
        assert result >= 7.5, (
            f"Random bytes should have entropy >= 7.5, got {result}"
        )

    def test_plain_text_low_entropy(self):
        """
        Plain English text has low byte diversity.
        Entropy should be below 6.0.
        """
        data = b"The quick brown fox jumps over the lazy dog. " * 100
        result = calculate_shannon_entropy(data)
        assert result < 6.0, (
            f"Plain text should have entropy < 6.0, got {result}"
        )

    def test_entropy_within_valid_range(self):
        """Entropy must always be between 0.0 and 8.0."""
        import os
        for _ in range(10):
            data = os.urandom(1024)
            result = calculate_shannon_entropy(data)
            assert 0.0 <= result <= 8.0

    def test_entropy_result_verdict_normal(self):
        """Low entropy data must produce NORMAL verdict."""
        data = b"AAAAAAAAAAAAAAAA" * 256
        result = analyze_entropy(data, elevated_threshold=6.5, critical_threshold=7.2)
        assert result.verdict == "NORMAL"
        assert result.entropy_value < 6.5

    def test_entropy_result_verdict_critical(self):
        """High entropy random data must produce CRITICAL verdict."""
        import os
        data = os.urandom(4096)
        result = analyze_entropy(data, elevated_threshold=6.5, critical_threshold=7.2)
        assert result.verdict == "CRITICAL"
        assert result.entropy_value >= 7.2

    def test_entropy_result_contains_byte_distribution(self):
        """EntropyResult must contain full 256-bucket byte distribution."""
        data = b"\x00\x01\x02\x03" * 256
        result = analyze_entropy(data)
        assert len(result.byte_distribution) == 256
        assert result.byte_distribution[0] == 256
        assert result.byte_distribution[1] == 256

    def test_entropy_result_unique_byte_count(self):
        """Unique byte count must match actual distinct values in data."""
        data = b"\xAA\xBB\xCC" * 100
        result = analyze_entropy(data)
        assert result.unique_byte_count == 3

    def test_section_entropy_analysis(self):
        """
        Section analysis must identify high-entropy sections
        within a file that has mixed entropy content.
        """
        import os
        low_part = b"A" * 1024
        high_part = os.urandom(1024)
        mixed = low_part + high_part

        sections = analyze_file_sections(
            mixed, section_size=256, critical_threshold=7.2
        )
        flagged = [s for s in sections if s.is_suspicious]

        assert len(flagged) > 0, (
            "Section analysis must flag high-entropy sections in mixed data"
        )


# =============================================================================
# SECTION 2: Magic Byte Signature Tests
# =============================================================================

class TestMagicByteSignatures:

    def test_jpeg_signature_detected(self):
        """FFD8FF must match JPEG signature."""
        sig = get_signature_by_hex("FFD8FFE000104A464946")
        assert sig is not None
        assert sig.format_name == "JPEG Image"
        assert sig.mime_type == "image/jpeg"

    def test_pe_executable_signature_detected(self):
        """4D5A must match Windows PE Executable."""
        sig = get_signature_by_hex("4D5A90000300000004000000FFFF")
        assert sig is not None
        assert sig.format_name == "Windows PE Executable"
        assert sig.threat_relevance == "CRITICAL"

    def test_pdf_signature_detected(self):
        """255044462D must match PDF."""
        sig = get_signature_by_hex("255044462D312E37")
        assert sig is not None
        assert sig.format_name == "PDF Document"
        assert sig.mime_type == "application/pdf"

    def test_elf_signature_detected(self):
        """7F454C46 must match ELF executable."""
        sig = get_signature_by_hex("7F454C4602010100")
        assert sig is not None
        assert sig.format_name == "ELF Executable (Linux/Unix)"
        assert sig.threat_relevance == "CRITICAL"

    def test_ole2_signature_detected(self):
        """D0CF11E0A1B11AE1 must match OLE2 document."""
        sig = get_signature_by_hex("D0CF11E0A1B11AE1")
        assert sig is not None
        assert sig.format_name == "Microsoft Office OLE2 (Legacy)"
        assert sig.threat_relevance == "HIGH"

    def test_png_signature_detected(self):
        """89504E470D0A1A0A must match PNG."""
        sig = get_signature_by_hex("89504E470D0A1A0A")
        assert sig is not None
        assert sig.format_name == "PNG Image"

    def test_unknown_signature_returns_none(self):
        """Unknown hex pattern must return None."""
        sig = get_signature_by_hex("DEADBEEFCAFEBABE")
        assert sig is None

    def test_extension_lookup_exe(self):
        """Extension .exe must return PE executable signatures."""
        sigs = get_signatures_by_extension(".exe")
        assert len(sigs) > 0
        assert any(s.threat_relevance == "CRITICAL" for s in sigs)

    def test_all_critical_signatures_are_critical(self):
        """All signatures returned by get_all_critical_signatures must be CRITICAL."""
        critical = get_all_critical_signatures()
        assert len(critical) > 0
        assert all(s.threat_relevance == "CRITICAL" for s in critical)


# =============================================================================
# SECTION 3: MIME Spoofing Detection Tests
# =============================================================================

class TestMimeSpoofDetection:

    def test_exe_disguised_as_jpg_detected(self, engine, test_files):
        """
        mime_spoof_exe.jpg contains PE magic bytes.
        Declared as image/jpeg — must detect spoof.
        """
        data = test_files.get("mime_spoof_exe.jpg")
        assert data is not None, "Test file mime_spoof_exe.jpg not found"

        result = engine.analyze_bytes(
            data=data,
            filename="mime_spoof_exe.jpg",
            declared_mime_type="image/jpeg",
        )

        assert result.mime_spoof_detected is True, (
            "EXE disguised as JPG must be detected as MIME spoof"
        )
        assert result.mime_type_detected == "application/x-dosexec"
        assert result.overall_risk_level in ("SUSPICIOUS", "MALICIOUS")

    def test_pdf_disguised_as_png_detected(self, engine, test_files):
        """
        mime_spoof_pdf.png contains PDF magic bytes.
        Declared as image/png — must detect spoof.
        """
        data = test_files.get("mime_spoof_pdf.png")
        assert data is not None, "Test file mime_spoof_pdf.png not found"

        result = engine.analyze_bytes(
            data=data,
            filename="mime_spoof_pdf.png",
            declared_mime_type="image/png",
        )

        assert result.mime_spoof_detected is True, (
            "PDF disguised as PNG must be detected as MIME spoof"
        )
        assert result.overall_risk_level in ("SUSPICIOUS", "MALICIOUS")

    def test_clean_jpeg_no_spoof(self, engine, test_files):
        """
        clean_image.jpg is a legitimate JPEG.
        Must NOT be flagged as MIME spoof.
        """
        data = test_files.get("clean_image.jpg")
        assert data is not None

        result = engine.analyze_bytes(
            data=data,
            filename="clean_image.jpg",
            declared_mime_type="image/jpeg",
        )

        assert result.mime_spoof_detected is False, (
            "Legitimate JPEG must not be flagged as MIME spoof"
        )

    def test_clean_pdf_no_spoof(self, engine, test_files):
        """
        clean_pdf.pdf is a legitimate PDF.
        Must NOT be flagged as MIME spoof.
        """
        data = test_files.get("clean_pdf.pdf")
        assert data is not None

        result = engine.analyze_bytes(
            data=data,
            filename="clean_pdf.pdf",
            declared_mime_type="application/pdf",
        )

        assert result.mime_spoof_detected is False, (
            "Legitimate PDF must not be flagged as MIME spoof"
        )


# =============================================================================
# SECTION 4: Entropy-Based Detection Tests
# =============================================================================

class TestEntropyDetection:

    def test_high_entropy_block_critical_verdict(self, engine, test_files):
        """
        high_entropy_block.bin contains random bytes.
        Must produce CRITICAL entropy verdict.
        """
        data = test_files.get("high_entropy_block.bin")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="high_entropy_block.bin")

        assert result.entropy_result.verdict == "CRITICAL", (
            f"High entropy block must produce CRITICAL verdict, "
            f"got {result.entropy_result.verdict} "
            f"(entropy={result.entropy_result.entropy_value})"
        )
        assert result.entropy_result.entropy_value >= 7.2

    def test_low_entropy_text_normal_verdict(self, engine, test_files):
        """
        low_entropy_text.txt contains repetitive plain text.
        Must produce NORMAL entropy verdict.
        """
        data = test_files.get("low_entropy_text.txt")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="low_entropy_text.txt")

        assert result.entropy_result.verdict == "NORMAL", (
            f"Low entropy text must produce NORMAL verdict, "
            f"got {result.entropy_result.verdict} "
            f"(entropy={result.entropy_result.entropy_value})"
        )

    def test_mixed_entropy_suspicious_sections(self, engine, test_files):
        """
        mixed_entropy.bin has normal header + high entropy payload.
        Section analysis must flag the high entropy regions.
        """
        data = test_files.get("mixed_entropy.bin")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="mixed_entropy.bin")

        assert len(result.suspicious_sections) > 0, (
            "Mixed entropy file must have suspicious sections flagged"
        )


# =============================================================================
# SECTION 5: Header Anomaly Detection Tests
# =============================================================================

class TestHeaderAnomalyDetection:

    def test_null_header_anomaly_detected(self, engine, test_files):
        """
        null_header.bin begins with null bytes.
        Must detect header anomaly.
        """
        data = test_files.get("null_header.bin")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="null_header.bin")

        assert result.header_anomalies_detected is True, (
            "Null byte header must be flagged as anomaly"
        )

    def test_clean_jpeg_valid_header(self, engine, test_files):
        """clean_image.jpg must have a valid header."""
        data = test_files.get("clean_image.jpg")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="clean_image.jpg")

        assert result.file_header_valid is True


# =============================================================================
# SECTION 6: Cryptographic Hash Tests
# =============================================================================

class TestCryptographicHashing:

    def test_sha256_hash_length(self, engine):
        """SHA-256 hash must be exactly 64 hex characters."""
        data = b"HexShield AI forensic test data"
        result = engine.analyze_bytes(data=data, filename="test.bin")
        assert len(result.sha256_hash) == 64

    def test_sha512_hash_length(self, engine):
        """SHA-512 hash must be exactly 128 hex characters."""
        data = b"HexShield AI forensic test data"
        result = engine.analyze_bytes(data=data, filename="test.bin")
        assert len(result.sha512_hash) == 128

    def test_hash_deterministic(self, engine):
        """Same input must always produce same hash."""
        data = b"deterministic hash test"
        result1 = engine.analyze_bytes(data=data, filename="test.bin")
        result2 = engine.analyze_bytes(data=data, filename="test.bin")
        assert result1.sha256_hash == result2.sha256_hash
        assert result1.sha512_hash == result2.sha512_hash

    def test_different_inputs_different_hashes(self, engine):
        """Different inputs must produce different hashes."""
        result1 = engine.analyze_bytes(data=b"file one", filename="a.bin")
        result2 = engine.analyze_bytes(data=b"file two", filename="b.bin")
        assert result1.sha256_hash != result2.sha256_hash


# =============================================================================
# SECTION 7: Full File Analysis Tests
# =============================================================================

class TestFullFileAnalysis:

    def test_elf_binary_critical_format(self, engine, test_files):
        """ELF binary must be identified as CRITICAL threat format."""
        data = test_files.get("elf_binary.bin")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="elf_binary.bin")

        assert result.matched_signature is not None
        assert result.matched_signature.threat_relevance == "CRITICAL"
        assert result.overall_risk_level in ("SUSPICIOUS", "MALICIOUS")

    def test_ole2_document_high_format(self, engine, test_files):
        """OLE2 document must be identified as HIGH threat format."""
        data = test_files.get("ole2_document.doc")
        assert data is not None

        result = engine.analyze_bytes(data=data, filename="ole2_document.doc")

        assert result.matched_signature is not None
        assert result.matched_signature.threat_relevance == "HIGH"

    def test_engine_version_recorded(self, engine, test_files):
        """Engine version must be recorded in every result."""
        data = test_files.get("clean_image.jpg")
        result = engine.analyze_bytes(data=data, filename="clean_image.jpg")
        assert result.engine_version == "1.0.0"

    def test_analysis_duration_recorded(self, engine, test_files):
        """Analysis duration must be a non-negative integer."""
        data = test_files.get("clean_image.jpg")
        result = engine.analyze_bytes(data=data, filename="clean_image.jpg")
        assert isinstance(result.analysis_duration_ms, int)
        assert result.analysis_duration_ms >= 0

    def test_all_test_files_analyzed_without_error(self, engine, test_files):
        """
        Every generated test file must be analyzed without
        raising an exception or returning empty hashes.
        """
        assert len(test_files) == 10, (
            f"Expected 10 test files, found {len(test_files)}"
        )
        for filename, data in test_files.items():
            result = engine.analyze_bytes(data=data, filename=filename)
            assert result.sha256_hash != "", (
                f"SHA-256 hash must not be empty for {filename}"
            )
            assert result.overall_risk_level in (
                "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"
            ), f"Invalid risk level for {filename}: {result.overall_risk_level}"