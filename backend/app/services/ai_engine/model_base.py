# =============================================================================
# HexShield AI — AI Engine Base Model
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Defines the abstract base class that all AI analysis models inherit from.
# Enforces a consistent interface across image, video, and audio analyzers.
# =============================================================================

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# SHARED DATA CLASSES
# =============================================================================

@dataclass
class AIAnalysisResult:
    """
    Standardized result returned by every AI analysis model.
    This structure maps directly to the ai_media_analysis_results table.
    """

    # Media classification
    media_type:                 str     # IMAGE | VIDEO | AUDIO

    # Primary scores
    authenticity_score:         float   # 0.0 (synthetic) to 1.0 (authentic)
    manipulation_confidence:    float   # 0.0 to 1.0

    # Final verdict
    verdict:                    str     # AUTHENTIC | SUSPICIOUS | MANIPULATED | INCONCLUSIVE

    # Model attribution — mandatory for court admissibility
    model_name:                 str
    model_version:              str
    model_weights_hash:         Optional[str] = None

    # Image-specific
    face_regions_detected:      Optional[List[Dict]] = None
    compression_artifact_score: Optional[float] = None
    noise_pattern_anomaly_score: Optional[float] = None
    ela_anomaly_score:          Optional[float] = None

    # Video-specific
    total_frames_analyzed:      Optional[int] = None
    temporal_inconsistency_score: Optional[float] = None
    temporal_inconsistencies:   Optional[List[Dict]] = None

    # Audio-specific
    total_segments_analyzed:    Optional[int] = None
    spectral_analysis:          Optional[List[Dict]] = None
    voice_synthesis_score:      Optional[float] = None

    # Frame-level details (video/audio)
    frame_details:              List[Dict] = field(default_factory=list)

    # Operational metadata
    processing_duration_ms:     Optional[int] = None
    inference_device:           str = "cpu"
    analysis_notes:             List[str] = field(default_factory=list)
    errors:                     List[str] = field(default_factory=list)


# =============================================================================
# VERDICT DETERMINATION HELPER
# =============================================================================

def determine_ai_verdict(
    authenticity_score: float,
    manipulation_confidence: float,
) -> str:
    """
    Determine the AI verdict from authenticity and manipulation scores.

    Thresholds:
      AUTHENTIC     — authenticity >= 0.80 AND manipulation < 0.25
      MANIPULATED   — manipulation >= 0.75
      SUSPICIOUS    — manipulation >= 0.45 OR authenticity < 0.55
      INCONCLUSIVE  — scores are ambiguous or conflicting
    """
    if authenticity_score >= 0.80 and manipulation_confidence < 0.25:
        return "AUTHENTIC"
    elif manipulation_confidence >= 0.75:
        return "MANIPULATED"
    elif manipulation_confidence >= 0.45 or authenticity_score < 0.55:
        return "SUSPICIOUS"
    else:
        return "INCONCLUSIVE"


# =============================================================================
# ABSTRACT BASE CLASS
# =============================================================================

class BaseMediaAnalyzer(ABC):
    """
    Abstract base class for all HexShield AI media analyzers.

    Every concrete analyzer (image, video, audio) must implement:
      - analyze(data, filename) -> AIAnalysisResult
      - model_name property
      - model_version property
    """

    def __init__(self, inference_device: str = "cpu"):
        self.inference_device = inference_device
        self._model_loaded = False
        logger.info(
            f"{self.__class__.__name__} initialized on device={inference_device}"
        )

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the AI model used by this analyzer."""
        pass

    @property
    @abstractmethod
    def model_version(self) -> str:
        """Version of the AI model."""
        pass

    @abstractmethod
    def analyze(self, data: bytes, filename: str) -> AIAnalysisResult:
        """
        Perform deepfake/manipulation analysis on raw file bytes.

        Args:
            data     : Raw file bytes
            filename : Original filename for format detection

        Returns:
            AIAnalysisResult with scores, verdict, and metadata
        """
        pass

    def _log_analysis_start(self, filename: str, media_type: str) -> None:
        logger.info(
            f"{self.__class__.__name__}: Starting {media_type} analysis — "
            f"file={filename}, device={self.inference_device}"
        )

    def _log_analysis_complete(
        self, filename: str, verdict: str, duration_ms: int
    ) -> None:
        logger.info(
            f"{self.__class__.__name__}: Analysis complete — "
            f"file={filename}, verdict={verdict}, duration={duration_ms}ms"
        )