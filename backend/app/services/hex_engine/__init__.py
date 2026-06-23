# =============================================================================
# HexShield AI — Hex Engine Package
# Exposes the public API for Layer 1: Hex-Level Binary Triage Engine
# =============================================================================

from app.services.hex_engine.triage_engine import HexTriageEngine, TriageResult
from app.services.hex_engine.entropy import (
    analyze_entropy,
    analyze_file_sections,
    calculate_shannon_entropy,
    EntropyResult,
    SectionEntropyResult,
)
from app.services.hex_engine.magic_bytes_db import (
    MagicSignature,
    get_signature_by_hex,
    get_signatures_by_mime,
    get_signatures_by_extension,
    get_all_critical_signatures,
    MAGIC_SIGNATURES,
)

__all__ = [
    # Engine
    "HexTriageEngine",
    "TriageResult",
    # Entropy
    "analyze_entropy",
    "analyze_file_sections",
    "calculate_shannon_entropy",
    "EntropyResult",
    "SectionEntropyResult",
    # Magic Bytes
    "MagicSignature",
    "get_signature_by_hex",
    "get_signatures_by_mime",
    "get_signatures_by_extension",
    "get_all_critical_signatures",
    "MAGIC_SIGNATURES",
]