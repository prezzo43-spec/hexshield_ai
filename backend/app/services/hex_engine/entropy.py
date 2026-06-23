# =============================================================================
# HexShield AI — Shannon Entropy Calculator
# Layer 1: Hex-Level Binary Triage Engine
#
# Shannon Entropy measures the randomness of a byte stream.
# Formula: H = -sum(p(x) * log2(p(x))) for all byte values x
#
# Interpretation:
#   0.0 - 4.0  : Low entropy  — structured data, plain text
#   4.0 - 6.5  : Normal       — typical compressed or binary files
#   6.5 - 7.2  : Elevated     — possible encryption or packing
#   7.2 - 8.0  : Critical     — high probability of encrypted/packed payload
#
# Theoretical maximum: 8.0 bits (perfectly random byte distribution)
# =============================================================================

import math
import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class EntropyResult:
    """
    Complete result of a Shannon Entropy analysis on a byte stream.

    Attributes:
        entropy_value        : Calculated Shannon Entropy (0.0 to 8.0)
        verdict              : NORMAL | ELEVATED | CRITICAL
        elevated_threshold   : The elevated threshold used in this analysis
        critical_threshold   : The critical threshold used in this analysis
        byte_distribution    : Full 256-bucket byte frequency counts
        total_bytes_analyzed : Number of bytes analyzed
        unique_byte_count    : Number of distinct byte values present
        most_frequent_bytes  : Top 5 most frequent bytes (value, count, percentage)
        least_frequent_bytes : Top 5 least frequent bytes (value, count, percentage)
        analysis_notes       : Human-readable interpretation notes
    """
    entropy_value:          float
    verdict:                str
    elevated_threshold:     float
    critical_threshold:     float
    byte_distribution:      Dict[int, int]
    total_bytes_analyzed:   int
    unique_byte_count:      int
    most_frequent_bytes:    List[Tuple[int, int, float]]
    least_frequent_bytes:   List[Tuple[int, int, float]]
    analysis_notes:         List[str]


@dataclass
class SectionEntropyResult:
    """
    Entropy result for a specific section or chunk of a file.

    Attributes:
        offset        : Byte offset where this section starts
        length        : Number of bytes in this section
        entropy_value : Shannon Entropy of this section
        is_suspicious : True if entropy exceeds the critical threshold
    """
    offset:         int
    length:         int
    entropy_value:  float
    is_suspicious:  bool


# =============================================================================
# CORE ENTROPY FUNCTIONS
# =============================================================================

def calculate_byte_distribution(data: bytes) -> Dict[int, int]:
    """
    Build a frequency table of all 256 possible byte values.
    Bytes not present in the data have a count of 0.

    Args:
        data: Raw bytes to analyze

    Returns:
        Dictionary mapping byte value (0-255) to occurrence count
    """
    distribution = {i: 0 for i in range(256)}
    for byte in data:
        distribution[byte] += 1
    return distribution


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy of a byte sequence.

    H = -sum(p(x) * log2(p(x))) for all byte values x where p(x) > 0

    Args:
        data: Raw bytes to analyze

    Returns:
        Entropy value between 0.0 and 8.0
        Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    total_bytes = len(data)
    distribution = calculate_byte_distribution(data)

    entropy = 0.0
    for count in distribution.values():
        if count == 0:
            continue
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    # Clamp to valid range due to floating point precision
    return round(min(max(entropy, 0.0), 8.0), 6)


def determine_entropy_verdict(
    entropy_value: float,
    elevated_threshold: float = 6.5,
    critical_threshold: float = 7.2,
) -> str:
    """
    Determine the entropy verdict based on configured thresholds.

    Args:
        entropy_value       : Calculated Shannon Entropy
        elevated_threshold  : Threshold above which verdict is ELEVATED
        critical_threshold  : Threshold above which verdict is CRITICAL

    Returns:
        'NORMAL' | 'ELEVATED' | 'CRITICAL'
    """
    if entropy_value >= critical_threshold:
        return "CRITICAL"
    elif entropy_value >= elevated_threshold:
        return "ELEVATED"
    else:
        return "NORMAL"


def analyze_entropy(
    data: bytes,
    elevated_threshold: float = 6.5,
    critical_threshold: float = 7.2,
) -> EntropyResult:
    """
    Perform a complete entropy analysis on a byte stream.
    Returns a full EntropyResult with distribution, verdict, and notes.

    Args:
        data                : Raw bytes to analyze
        elevated_threshold  : Threshold for ELEVATED verdict
        critical_threshold  : Threshold for CRITICAL verdict

    Returns:
        EntropyResult dataclass with complete analysis
    """
    if not data:
        return EntropyResult(
            entropy_value=0.0,
            verdict="NORMAL",
            elevated_threshold=elevated_threshold,
            critical_threshold=critical_threshold,
            byte_distribution={i: 0 for i in range(256)},
            total_bytes_analyzed=0,
            unique_byte_count=0,
            most_frequent_bytes=[],
            least_frequent_bytes=[],
            analysis_notes=["Empty input — no entropy analysis performed."],
        )

    total_bytes = len(data)
    distribution = calculate_byte_distribution(data)
    entropy_value = calculate_shannon_entropy(data)
    verdict = determine_entropy_verdict(
        entropy_value, elevated_threshold, critical_threshold
    )

    # Count unique bytes
    unique_byte_count = sum(1 for count in distribution.values() if count > 0)

    # Compute frequency statistics
    sorted_by_freq = sorted(
        [(byte_val, count) for byte_val, count in distribution.items() if count > 0],
        key=lambda x: x[1],
        reverse=True,
    )

    most_frequent = [
        (byte_val, count, round(count / total_bytes * 100, 2))
        for byte_val, count in sorted_by_freq[:5]
    ]

    least_frequent = [
        (byte_val, count, round(count / total_bytes * 100, 2))
        for byte_val, count in sorted_by_freq[-5:]
        if count > 0
    ]

    # Generate human-readable analysis notes
    notes = _generate_entropy_notes(
        entropy_value=entropy_value,
        verdict=verdict,
        unique_byte_count=unique_byte_count,
        total_bytes=total_bytes,
        distribution=distribution,
        elevated_threshold=elevated_threshold,
        critical_threshold=critical_threshold,
    )

    logger.debug(
        f"Entropy analysis complete: value={entropy_value:.6f}, "
        f"verdict={verdict}, bytes={total_bytes}, unique={unique_byte_count}"
    )

    return EntropyResult(
        entropy_value=entropy_value,
        verdict=verdict,
        elevated_threshold=elevated_threshold,
        critical_threshold=critical_threshold,
        byte_distribution=distribution,
        total_bytes_analyzed=total_bytes,
        unique_byte_count=unique_byte_count,
        most_frequent_bytes=most_frequent,
        least_frequent_bytes=least_frequent,
        analysis_notes=notes,
    )


def analyze_file_sections(
    data: bytes,
    section_size: int = 256,
    critical_threshold: float = 7.2,
) -> List[SectionEntropyResult]:
    """
    Analyze entropy across fixed-size sections of a file.
    Identifies specific byte ranges with anomalously high entropy —
    a strong indicator of encrypted, packed, or obfuscated payloads
    embedded within an otherwise normal file.

    Args:
        data               : Complete file bytes
        section_size       : Size of each analysis chunk in bytes
        critical_threshold : Entropy threshold for flagging a section

    Returns:
        List of SectionEntropyResult for each chunk
    """
    if not data:
        return []

    results = []
    total_bytes = len(data)

    for offset in range(0, total_bytes, section_size):
        chunk = data[offset: offset + section_size]
        if len(chunk) < 16:
            # Skip chunks too small for meaningful entropy measurement
            continue

        chunk_entropy = calculate_shannon_entropy(chunk)
        is_suspicious = chunk_entropy >= critical_threshold

        results.append(
            SectionEntropyResult(
                offset=offset,
                length=len(chunk),
                entropy_value=round(chunk_entropy, 6),
                is_suspicious=is_suspicious,
            )
        )

    suspicious_count = sum(1 for r in results if r.is_suspicious)
    if suspicious_count > 0:
        logger.warning(
            f"Section entropy analysis: {suspicious_count}/{len(results)} "
            f"sections exceed critical threshold ({critical_threshold})"
        )

    return results


# =============================================================================
# INTERNAL HELPER
# =============================================================================

def _generate_entropy_notes(
    entropy_value: float,
    verdict: str,
    unique_byte_count: int,
    total_bytes: int,
    distribution: Dict[int, int],
    elevated_threshold: float,
    critical_threshold: float,
) -> List[str]:
    """
    Generate human-readable forensic interpretation notes
    based on entropy analysis results.
    """
    notes = []

    notes.append(
        f"Shannon Entropy: {entropy_value:.6f} bits per byte "
        f"(theoretical maximum: 8.0)."
    )

    if verdict == "CRITICAL":
        notes.append(
            f"CRITICAL: Entropy {entropy_value:.4f} exceeds critical threshold "
            f"({critical_threshold}). This is highly consistent with encrypted, "
            f"packed, or obfuscated data. Manual inspection is mandatory."
        )
    elif verdict == "ELEVATED":
        notes.append(
            f"ELEVATED: Entropy {entropy_value:.4f} exceeds elevated threshold "
            f"({elevated_threshold}). The file may contain compressed sections "
            f"or lightly obfuscated content. Further analysis recommended."
        )
    else:
        notes.append(
            f"NORMAL: Entropy {entropy_value:.4f} is within expected range for "
            f"structured or plain-text data."
        )

    notes.append(
        f"Byte diversity: {unique_byte_count}/256 distinct byte values "
        f"observed across {total_bytes} bytes analyzed."
    )

    # Detect null-byte padding (common in memory dumps and some exploits)
    null_count = distribution.get(0, 0)
    null_percentage = (null_count / total_bytes * 100) if total_bytes > 0 else 0
    if null_percentage > 30:
        notes.append(
            f"WARNING: {null_percentage:.1f}% null bytes detected. "
            f"This may indicate memory dump artifacts or padding used "
            f"to evade entropy-based detection."
        )

    # Detect very low byte diversity (possible single-byte XOR obfuscation)
    if unique_byte_count < 16 and total_bytes > 64:
        notes.append(
            f"WARNING: Very low byte diversity ({unique_byte_count} unique values). "
            f"Possible single-byte XOR encoding or highly repetitive data."
        )

    return notes