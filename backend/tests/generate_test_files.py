# =============================================================================
# HexShield AI — Test File Generator
# Step 4: Simulated malicious and benign files for Layer 1 unit testing
#
# This script generates synthetic test files that simulate real-world
# attack scenarios without using actual malware samples.
#
# Generated files:
#   1. clean_image.jpg          — Legitimate JPEG image
#   2. clean_pdf.pdf            — Legitimate PDF document
#   3. mime_spoof_exe.jpg       — EXE disguised as JPEG (MIME spoof)
#   4. mime_spoof_pdf.png       — PDF disguised as PNG (MIME spoof)
#   5. high_entropy_block.bin   — Simulated encrypted/packed payload
#   6. low_entropy_text.txt     — Plain text, low entropy
#   7. mixed_entropy.bin        — Normal header + high entropy payload
#   8. null_header.bin          — File beginning with null bytes
#   9. elf_binary.bin           — ELF executable header simulation
#  10. ole2_document.doc        — OLE2 macro-capable document simulation
# =============================================================================

import os
import sys
import random
import struct
import hashlib
import logging
from pathlib import Path

# Add backend root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent / "test_files"


def write_file(filename: str, data: bytes) -> Path:
    """Write bytes to a test file and log its SHA-256."""
    output_path = OUTPUT_DIR / filename
    output_path.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    logger.info(f"  Created: {filename} ({len(data)} bytes) SHA-256: {sha256[:16]}...")
    return output_path


def generate_high_entropy_bytes(size: int) -> bytes:
    """
    Generate bytes with near-maximum Shannon Entropy.
    Simulates encrypted or compressed payload data.
    Uses os.urandom which produces cryptographically random bytes.
    """
    return os.urandom(size)


def generate_low_entropy_bytes(size: int) -> bytes:
    """
    Generate bytes with low Shannon Entropy.
    Simulates plain text or highly structured data.
    """
    # Repeat a small set of ASCII characters
    chars = b"The quick brown fox jumps over the lazy dog. "
    result = (chars * (size // len(chars) + 1))[:size]
    return result


def generate_test_files() -> None:
    """Generate all simulated test files."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("=" * 60)
    logger.info("HexShield AI — Test File Generator")
    logger.info(f"Output directory: {OUTPUT_DIR}")
    logger.info("=" * 60)

    # ------------------------------------------------------------------
    # 1. Clean JPEG image
    # Minimal valid JPEG: SOI marker + APP0 JFIF header + EOI marker
    # ------------------------------------------------------------------
    logger.info("Generating: clean_image.jpg")
    jpeg_data = (
        b"\xFF\xD8\xFF\xE0"          # SOI + APP0 marker
        b"\x00\x10"                   # APP0 length
        b"JFIF\x00"                   # JFIF identifier
        b"\x01\x01"                   # Version 1.1
        b"\x00"                       # Aspect ratio units
        b"\x00\x01\x00\x01"          # X/Y density
        b"\x00\x00"                   # Thumbnail size
        + generate_low_entropy_bytes(512)  # Simulated image data
        + b"\xFF\xD9"                 # EOI marker
    )
    write_file("clean_image.jpg", jpeg_data)

    # ------------------------------------------------------------------
    # 2. Clean PDF document
    # Minimal valid PDF header
    # ------------------------------------------------------------------
    logger.info("Generating: clean_pdf.pdf")
    pdf_data = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"%%EOF\n"
        + generate_low_entropy_bytes(256)
    )
    write_file("clean_pdf.pdf", pdf_data)

    # ------------------------------------------------------------------
    # 3. MIME Spoof — EXE disguised as JPEG
    # File has .jpg extension and declares image/jpeg MIME type
    # but begins with Windows PE (MZ) magic bytes
    # ------------------------------------------------------------------
    logger.info("Generating: mime_spoof_exe.jpg  [MIME SPOOF: EXE as JPG]")
    pe_header = (
        b"MZ"                          # MZ magic bytes — Windows PE signature
        b"\x90\x00"                    # Bytes on last page
        b"\x03\x00"                    # Pages in file
        b"\x00\x00"                    # Relocations
        b"\x04\x00"                    # Size of header in paragraphs
        b"\x00\x00"                    # Minimum extra paragraphs
        b"\xFF\xFF"                    # Maximum extra paragraphs
        b"\x00\x00"                    # Initial SS value
        b"\xB8\x00"                    # Initial SP value
        b"\x00\x00"                    # Checksum
        b"\x00\x00"                    # Initial IP value
        b"\x00\x00"                    # Initial CS value
        b"\x40\x00"                    # File address of relocation table
        b"\x00\x00"                    # Overlay number
        + b"\x00" * 32                 # Reserved
        + b"\x80\x00\x00\x00"         # PE header offset at 0x3C = 0x80
        + b"\x00" * 64                 # DOS stub (simplified)
        + b"PE\x00\x00"               # PE signature
        + generate_low_entropy_bytes(256)
    )
    write_file("mime_spoof_exe.jpg", pe_header)

    # ------------------------------------------------------------------
    # 4. MIME Spoof — PDF disguised as PNG
    # File has .png extension but begins with PDF magic bytes
    # ------------------------------------------------------------------
    logger.info("Generating: mime_spoof_pdf.png  [MIME SPOOF: PDF as PNG]")
    pdf_as_png = (
        b"%PDF-1.4\n"                  # PDF magic bytes
        b"% Spoofed as PNG\n"
        + generate_low_entropy_bytes(512)
    )
    write_file("mime_spoof_pdf.png", pdf_as_png)

    # ------------------------------------------------------------------
    # 5. High Entropy Binary Block
    # Simulates an encrypted or packed payload
    # Expected entropy: ~7.9-8.0 (near maximum)
    # ------------------------------------------------------------------
    logger.info("Generating: high_entropy_block.bin  [CRITICAL ENTROPY]")
    high_entropy_data = generate_high_entropy_bytes(4096)
    write_file("high_entropy_block.bin", high_entropy_data)

    # ------------------------------------------------------------------
    # 6. Low Entropy Text File
    # Simulates plain text — expected entropy: ~3.5-4.5
    # ------------------------------------------------------------------
    logger.info("Generating: low_entropy_text.txt  [NORMAL ENTROPY]")
    low_entropy_data = generate_low_entropy_bytes(4096)
    write_file("low_entropy_text.txt", low_entropy_data)

    # ------------------------------------------------------------------
    # 7. Mixed Entropy Binary
    # Legitimate-looking JPEG header followed by high-entropy payload
    # Simulates a steganographic carrier or polyglot file
    # ------------------------------------------------------------------
    logger.info("Generating: mixed_entropy.bin  [MIXED: normal header + encrypted payload]")
    mixed_data = (
        b"\xFF\xD8\xFF\xE0"            # JPEG SOI + APP0 — looks legitimate
        b"\x00\x10JFIF\x00\x01\x01"
        b"\x00\x00\x01\x00\x01\x00\x00"
        + generate_low_entropy_bytes(512)   # Normal image-like data
        + generate_high_entropy_bytes(2048) # Encrypted payload appended
    )
    write_file("mixed_entropy.bin", mixed_data)

    # ------------------------------------------------------------------
    # 8. Null Header File
    # File beginning with null bytes — header erasure indicator
    # ------------------------------------------------------------------
    logger.info("Generating: null_header.bin  [HEADER ANOMALY: null bytes]")
    null_header_data = (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Null byte header
        + generate_low_entropy_bytes(512)
    )
    write_file("null_header.bin", null_header_data)

    # ------------------------------------------------------------------
    # 9. ELF Binary Simulation
    # Linux/Unix executable magic bytes
    # ------------------------------------------------------------------
    logger.info("Generating: elf_binary.bin  [CRITICAL: ELF executable]")
    elf_header = (
        b"\x7FELF"                     # ELF magic bytes
        + b"\x02"                      # 64-bit
        + b"\x01"                      # Little endian
        + b"\x01"                      # ELF version 1
        + b"\x00"                      # OS/ABI: System V
        + b"\x00" * 8                  # Padding
        + b"\x02\x00"                  # Type: ET_EXEC (executable)
        + b"\x3E\x00"                  # Machine: x86-64
        + b"\x01\x00\x00\x00"         # ELF version
        + generate_low_entropy_bytes(256)
    )
    write_file("elf_binary.bin", elf_header)

    # ------------------------------------------------------------------
    # 10. OLE2 Document Simulation
    # Microsoft Office legacy format with macro capability
    # ------------------------------------------------------------------
    logger.info("Generating: ole2_document.doc  [HIGH: OLE2 macro-capable]")
    ole2_header = (
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"  # OLE2 magic bytes
        + b"\x00" * 8                           # Class ID (empty)
        + b"\x3E\x00"                           # Minor version
        + b"\x03\x00"                           # Major version
        + b"\xFE\xFF"                           # Byte order (little endian)
        + b"\x09\x00"                           # Sector size (512 bytes)
        + b"\x06\x00"                           # Mini sector size
        + b"\x00" * 6                           # Reserved
        + generate_low_entropy_bytes(480)
    )
    write_file("ole2_document.doc", ole2_header)

    logger.info("=" * 60)
    logger.info(f"Test file generation complete. 10 files created in:")
    logger.info(f"  {OUTPUT_DIR}")
    logger.info("=" * 60)


if __name__ == "__main__":
    generate_test_files()