# =============================================================================
# HexShield AI — Magic Byte Signatures Database
# Layer 1: Hex-Level Binary Triage Engine
#
# This module defines the in-memory magic byte knowledge base used by the
# hex triage engine to identify file formats from raw binary signatures.
#
# Sources:
#   - Gary Kessler's File Signatures Table (https://www.garykessler.net/library/file_sigs.html)
#   - IANA Media Types Registry
#   - National Institute of Standards and Technology (NIST)
# =============================================================================

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MagicSignature:
    """
    Represents a single file format magic byte signature.

    Attributes:
        format_name       : Human-readable format name
        hex_signature     : Magic bytes as uppercase hex string (no spaces)
        byte_offset       : Position in file where signature appears
        mime_type         : Expected MIME type for this signature
        common_extensions : File extensions associated with this format
        threat_relevance  : Forensic threat level
        description       : Brief format description
    """
    format_name:        str
    hex_signature:      str
    byte_offset:        int
    mime_type:          str
    common_extensions:  List[str]
    threat_relevance:   str  # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    description:        str


# =============================================================================
# MAGIC BYTE SIGNATURES REGISTRY
# Organized by threat relevance — highest threat formats listed first.
# =============================================================================

MAGIC_SIGNATURES: List[MagicSignature] = [

    # -------------------------------------------------------------------------
    # CRITICAL — Executable and Script Formats
    # Direct code execution vectors. Highest forensic priority.
    # -------------------------------------------------------------------------

    MagicSignature(
        format_name="Windows PE Executable",
        hex_signature="4D5A",
        byte_offset=0,
        mime_type="application/x-dosexec",
        common_extensions=[".exe", ".dll", ".sys", ".scr", ".drv", ".ocx"],
        threat_relevance="CRITICAL",
        description="Windows Portable Executable. MZ header indicates executable code.",
    ),
    MagicSignature(
        format_name="ELF Executable (Linux/Unix)",
        hex_signature="7F454C46",
        byte_offset=0,
        mime_type="application/x-elf",
        common_extensions=[".elf", ".bin", ".so", ""],
        threat_relevance="CRITICAL",
        description="Executable and Linkable Format. Linux/Unix native executable.",
    ),
    MagicSignature(
        format_name="Mach-O Executable (macOS 32-bit)",
        hex_signature="FEEDFACE",
        byte_offset=0,
        mime_type="application/x-mach-binary",
        common_extensions=[".macho", ".dylib", ""],
        threat_relevance="CRITICAL",
        description="macOS Mach-O 32-bit executable binary.",
    ),
    MagicSignature(
        format_name="Mach-O Executable (macOS 64-bit)",
        hex_signature="FEEDFACF",
        byte_offset=0,
        mime_type="application/x-mach-binary",
        common_extensions=[".macho", ".dylib", ""],
        threat_relevance="CRITICAL",
        description="macOS Mach-O 64-bit executable binary.",
    ),
    MagicSignature(
        format_name="Python Bytecode",
        hex_signature="6F0D0D0A",
        byte_offset=0,
        mime_type="application/x-python-code",
        common_extensions=[".pyc"],
        threat_relevance="CRITICAL",
        description="Compiled Python bytecode. Can execute arbitrary code.",
    ),
    MagicSignature(
        format_name="Java Class File",
        hex_signature="CAFEBABE",
        byte_offset=0,
        mime_type="application/java-vm",
        common_extensions=[".class", ".jar"],
        threat_relevance="CRITICAL",
        description="Java compiled class file. Executable on any JVM.",
    ),
    MagicSignature(
        format_name="Windows Batch Script",
        hex_signature="406563686F",
        byte_offset=0,
        mime_type="application/x-msdos-program",
        common_extensions=[".bat", ".cmd"],
        threat_relevance="CRITICAL",
        description="Windows batch script. @echo signature indicates script execution.",
    ),
    MagicSignature(
        format_name="Unix Shell Script",
        hex_signature="2321",
        byte_offset=0,
        mime_type="text/x-shellscript",
        common_extensions=[".sh", ".bash", ".zsh"],
        threat_relevance="CRITICAL",
        description="Unix shell script shebang (#!). Indicates executable script.",
    ),
    MagicSignature(
        format_name="PowerShell Script",
        hex_signature="FFFE",
        byte_offset=0,
        mime_type="text/x-powershell",
        common_extensions=[".ps1", ".psm1"],
        threat_relevance="CRITICAL",
        description="PowerShell script with UTF-16 BOM. Common malware delivery vector.",
    ),

    # -------------------------------------------------------------------------
    # HIGH — Document Formats with Macro/Script Capability
    # -------------------------------------------------------------------------

    MagicSignature(
        format_name="Microsoft Office OLE2 (Legacy)",
        hex_signature="D0CF11E0A1B11AE1",
        byte_offset=0,
        mime_type="application/vnd.ms-office",
        common_extensions=[".doc", ".xls", ".ppt", ".msg", ".vsd"],
        threat_relevance="HIGH",
        description="OLE2 Compound Document. Legacy Office format supporting VBA macros.",
    ),
    MagicSignature(
        format_name="Microsoft Office Open XML",
        hex_signature="504B0304",
        byte_offset=0,
        mime_type="application/vnd.openxmlformats-officedocument",
        common_extensions=[".docx", ".xlsx", ".pptx", ".odt", ".jar", ".apk", ".zip"],
        threat_relevance="HIGH",
        description="ZIP-based format. Used by modern Office files and Android APKs.",
    ),
    MagicSignature(
        format_name="PDF Document",
        hex_signature="255044462D",
        byte_offset=0,
        mime_type="application/pdf",
        common_extensions=[".pdf"],
        threat_relevance="HIGH",
        description="PDF document. Can contain embedded JavaScript and executable actions.",
    ),
    MagicSignature(
        format_name="HTML Document",
        hex_signature="3C68746D6C",
        byte_offset=0,
        mime_type="text/html",
        common_extensions=[".html", ".htm"],
        threat_relevance="HIGH",
        description="HTML file. Can contain embedded scripts and phishing content.",
    ),
    MagicSignature(
        format_name="XML Document",
        hex_signature="3C3F786D6C",
        byte_offset=0,
        mime_type="application/xml",
        common_extensions=[".xml", ".svg", ".xsl"],
        threat_relevance="HIGH",
        description="XML document. May contain XXE attack vectors or embedded scripts.",
    ),

    # -------------------------------------------------------------------------
    # MEDIUM — Archive and Container Formats
    # May contain nested malicious files.
    # -------------------------------------------------------------------------

    MagicSignature(
        format_name="RAR Archive",
        hex_signature="526172211A0700",
        byte_offset=0,
        mime_type="application/x-rar-compressed",
        common_extensions=[".rar"],
        threat_relevance="MEDIUM",
        description="RAR compressed archive. Common malware delivery container.",
    ),
    MagicSignature(
        format_name="7-Zip Archive",
        hex_signature="377ABCAF271C",
        byte_offset=0,
        mime_type="application/x-7z-compressed",
        common_extensions=[".7z"],
        threat_relevance="MEDIUM",
        description="7-Zip archive. Strong encryption can conceal malicious payloads.",
    ),
    MagicSignature(
        format_name="GZIP Archive",
        hex_signature="1F8B",
        byte_offset=0,
        mime_type="application/gzip",
        common_extensions=[".gz", ".tgz"],
        threat_relevance="MEDIUM",
        description="GZIP compressed data. Common on Linux systems.",
    ),
    MagicSignature(
        format_name="TAR Archive",
        hex_signature="7573746172",
        byte_offset=257,
        mime_type="application/x-tar",
        common_extensions=[".tar"],
        threat_relevance="MEDIUM",
        description="POSIX TAR archive. Signature at offset 257.",
    ),
    MagicSignature(
        format_name="ISO Disk Image",
        hex_signature="4344303031",
        byte_offset=32769,
        mime_type="application/x-iso9660-image",
        common_extensions=[".iso"],
        threat_relevance="MEDIUM",
        description="ISO 9660 CD/DVD image. Can contain bootable malware.",
    ),

    # -------------------------------------------------------------------------
    # LOW — Media Formats
    # Benign in isolation but relevant for deepfake detection context.
    # -------------------------------------------------------------------------

    MagicSignature(
        format_name="JPEG Image",
        hex_signature="FFD8FF",
        byte_offset=0,
        mime_type="image/jpeg",
        common_extensions=[".jpg", ".jpeg"],
        threat_relevance="LOW",
        description="JPEG image. Primary target format for deepfake face manipulation.",
    ),
    MagicSignature(
        format_name="PNG Image",
        hex_signature="89504E470D0A1A0A",
        byte_offset=0,
        mime_type="image/png",
        common_extensions=[".png"],
        threat_relevance="LOW",
        description="PNG image. Lossless format used in synthetic media generation.",
    ),
    MagicSignature(
        format_name="GIF Image",
        hex_signature="474946383761",
        byte_offset=0,
        mime_type="image/gif",
        common_extensions=[".gif"],
        threat_relevance="LOW",
        description="GIF87a image format.",
    ),
    MagicSignature(
        format_name="GIF89a Image",
        hex_signature="474946383961",
        byte_offset=0,
        mime_type="image/gif",
        common_extensions=[".gif"],
        threat_relevance="LOW",
        description="GIF89a image format with animation support.",
    ),
    MagicSignature(
        format_name="BMP Image",
        hex_signature="424D",
        byte_offset=0,
        mime_type="image/bmp",
        common_extensions=[".bmp"],
        threat_relevance="LOW",
        description="Windows Bitmap image format.",
    ),
    MagicSignature(
        format_name="WebP Image",
        hex_signature="52494646",
        byte_offset=0,
        mime_type="image/webp",
        common_extensions=[".webp"],
        threat_relevance="LOW",
        description="WebP image. RIFF container — verify WEBP marker at offset 8.",
    ),
    MagicSignature(
        format_name="MP4 Video",
        hex_signature="66747970",
        byte_offset=4,
        mime_type="video/mp4",
        common_extensions=[".mp4", ".m4v", ".m4a"],
        threat_relevance="LOW",
        description="MPEG-4 video container. Primary format for deepfake video evidence.",
    ),
    MagicSignature(
        format_name="AVI Video",
        hex_signature="41564920",
        byte_offset=8,
        mime_type="video/x-msvideo",
        common_extensions=[".avi"],
        threat_relevance="LOW",
        description="Audio Video Interleave format. Signature at offset 8.",
    ),
    MagicSignature(
        format_name="MKV Video",
        hex_signature="1A45DFA3",
        byte_offset=0,
        mime_type="video/x-matroska",
        common_extensions=[".mkv", ".webm"],
        threat_relevance="LOW",
        description="Matroska/WebM video container.",
    ),
    MagicSignature(
        format_name="MP3 Audio",
        hex_signature="494433",
        byte_offset=0,
        mime_type="audio/mpeg",
        common_extensions=[".mp3"],
        threat_relevance="LOW",
        description="MP3 audio with ID3 tag header.",
    ),
    MagicSignature(
        format_name="WAV Audio",
        hex_signature="52494646",
        byte_offset=0,
        mime_type="audio/wav",
        common_extensions=[".wav"],
        threat_relevance="LOW",
        description="WAV audio. RIFF container — verify WAVE marker at offset 8.",
    ),
    MagicSignature(
        format_name="FLAC Audio",
        hex_signature="664C6143",
        byte_offset=0,
        mime_type="audio/flac",
        common_extensions=[".flac"],
        threat_relevance="LOW",
        description="Free Lossless Audio Codec.",
    ),

    # -------------------------------------------------------------------------
    # INFORMATIONAL — Data and Document Formats
    # -------------------------------------------------------------------------

    MagicSignature(
        format_name="SQLite Database",
        hex_signature="53514C69746520666F726D617420330",
        byte_offset=0,
        mime_type="application/x-sqlite3",
        common_extensions=[".sqlite", ".db", ".sqlite3"],
        threat_relevance="INFORMATIONAL",
        description="SQLite database file. May contain forensic artifacts.",
    ),
    MagicSignature(
        format_name="UTF-8 Text with BOM",
        hex_signature="EFBBBF",
        byte_offset=0,
        mime_type="text/plain",
        common_extensions=[".txt", ".csv", ".log"],
        threat_relevance="INFORMATIONAL",
        description="UTF-8 encoded text file with Byte Order Mark.",
    ),
    MagicSignature(
        format_name="UTF-16 LE Text",
        hex_signature="FFFE",
        byte_offset=0,
        mime_type="text/plain",
        common_extensions=[".txt"],
        threat_relevance="INFORMATIONAL",
        description="UTF-16 Little Endian encoded text.",
    ),
]


# =============================================================================
# LOOKUP FUNCTIONS
# =============================================================================

def get_signature_by_hex(hex_string: str) -> Optional[MagicSignature]:
    """
    Find a signature by matching the beginning of a hex string.
    Returns the first matching signature or None.

    Args:
        hex_string: Hex string of file bytes (uppercase, no spaces)
    """
    hex_upper = hex_string.upper()
    for sig in MAGIC_SIGNATURES:
        if hex_upper.startswith(sig.hex_signature.upper()):
            return sig
    return None


def get_signatures_by_mime(mime_type: str) -> List[MagicSignature]:
    """
    Return all signatures matching a given MIME type.

    Args:
        mime_type: MIME type string to search for
    """
    return [
        sig for sig in MAGIC_SIGNATURES
        if sig.mime_type.lower() == mime_type.lower()
    ]


def get_signatures_by_extension(extension: str) -> List[MagicSignature]:
    """
    Return all signatures associated with a given file extension.

    Args:
        extension: File extension including dot (e.g., '.exe', '.pdf')
    """
    ext_lower = extension.lower()
    return [
        sig for sig in MAGIC_SIGNATURES
        if ext_lower in [e.lower() for e in sig.common_extensions]
    ]


def get_all_critical_signatures() -> List[MagicSignature]:
    """Return all signatures with CRITICAL threat relevance."""
    return [
        sig for sig in MAGIC_SIGNATURES
        if sig.threat_relevance == "CRITICAL"
    ]