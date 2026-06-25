# =============================================================================
# HexShield AI — AI Engine Orchestrator
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Main entry point for Layer 2 analysis.
# Routes files to the correct analyzer based on media type detection.
# Coordinates image, video, and audio analysis pipelines.
# =============================================================================

import time
import logging
from pathlib import Path
from typing import Optional

from app.services.ai_engine.model_base import AIAnalysisResult
from app.services.ai_engine.image_analyzer import ImageDeepfakeAnalyzer
from app.services.ai_engine.video_analyzer import VideoDeepfakeAnalyzer
from app.services.ai_engine.audio_analyzer import AudioDeepfakeAnalyzer
from app.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# MEDIA TYPE ROUTING
# =============================================================================

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif"
}

VIDEO_EXTENSIONS = {
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm"
}

AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma"
}


def detect_media_type(filename: str) -> Optional[str]:
    """
    Determine media type from file extension.

    Returns:
        'IMAGE' | 'VIDEO' | 'AUDIO' | None
    """
    ext = Path(filename).suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return "IMAGE"
    elif ext in VIDEO_EXTENSIONS:
        return "VIDEO"
    elif ext in AUDIO_EXTENSIONS:
        return "AUDIO"
    return None


# =============================================================================
# AI ENGINE ORCHESTRATOR
# =============================================================================

class AIDeepfakeEngine:
    """
    Layer 2: Multimodal AI Deepfake Detection Engine.

    Routes files to the appropriate analyzer:
      - Images  -> ImageDeepfakeAnalyzer (ELA, noise, compression, faces)
      - Videos  -> VideoDeepfakeAnalyzer (frame analysis, temporal consistency)
      - Audio   -> AudioDeepfakeAnalyzer (MFCC, spectral, voice synthesis)

    Usage:
        engine = AIDeepfakeEngine()
        result = engine.analyze_file(file_path)
        result = engine.analyze_bytes(data, filename)
    """

    def __init__(self, inference_device: str = None):
        self.inference_device = (
            inference_device or settings.AI_INFERENCE_DEVICE
        )
        self._image_analyzer = None
        self._video_analyzer = None
        self._audio_analyzer = None
        logger.info(
            f"AIDeepfakeEngine initialized — device={self.inference_device}"
        )

    # -------------------------------------------------------------------------
    # Lazy Initialization — Analyzers loaded on first use
    # -------------------------------------------------------------------------

    @property
    def image_analyzer(self) -> ImageDeepfakeAnalyzer:
        if self._image_analyzer is None:
            self._image_analyzer = ImageDeepfakeAnalyzer(
                self.inference_device
            )
        return self._image_analyzer

    @property
    def video_analyzer(self) -> VideoDeepfakeAnalyzer:
        if self._video_analyzer is None:
            self._video_analyzer = VideoDeepfakeAnalyzer(
                self.inference_device
            )
        return self._video_analyzer

    @property
    def audio_analyzer(self) -> AudioDeepfakeAnalyzer:
        if self._audio_analyzer is None:
            self._audio_analyzer = AudioDeepfakeAnalyzer(
                self.inference_device
            )
        return self._audio_analyzer

    # -------------------------------------------------------------------------
    # PUBLIC — Main Analysis Entry Points
    # -------------------------------------------------------------------------

    def analyze_file(
        self,
        file_path: str,
        declared_mime_type: Optional[str] = None,
    ) -> AIAnalysisResult:
        """
        Analyze a file from disk path.

        Args:
            file_path          : Path to the file on disk
            declared_mime_type : Optional declared MIME type

        Returns:
            AIAnalysisResult with deepfake detection findings
        """
        path = Path(file_path)
        if not path.exists():
            return self._file_not_found_result(str(path.name))

        file_bytes = path.read_bytes()
        return self.analyze_bytes(file_bytes, path.name)

    def analyze_bytes(
        self,
        data: bytes,
        filename: str,
    ) -> AIAnalysisResult:
        """
        Analyze raw bytes directly.

        Args:
            data     : Raw file bytes
            filename : Original filename for type detection

        Returns:
            AIAnalysisResult with deepfake detection findings
        """
        media_type = detect_media_type(filename)

        if media_type is None:
            return self._unsupported_media_result(filename)

        logger.info(
            f"AIDeepfakeEngine: Routing {filename} to "
            f"{media_type} analyzer."
        )

        if media_type == "IMAGE":
            return self.image_analyzer.analyze(data, filename)
        elif media_type == "VIDEO":
            return self.video_analyzer.analyze(data, filename)
        elif media_type == "AUDIO":
            return self.audio_analyzer.analyze(data, filename)

        return self._unsupported_media_result(filename)

    # -------------------------------------------------------------------------
    # PRIVATE — Error Results
    # -------------------------------------------------------------------------

    def _unsupported_media_result(self, filename: str) -> AIAnalysisResult:
        ext = Path(filename).suffix.lower()
        return AIAnalysisResult(
            media_type="UNKNOWN",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name="HexShield-AI-Engine",
            model_version="1.0.0",
            analysis_notes=[
                f"Unsupported media type: '{ext}'. "
                f"Supported formats: "
                f"Images ({', '.join(IMAGE_EXTENSIONS)}), "
                f"Video ({', '.join(VIDEO_EXTENSIONS)}), "
                f"Audio ({', '.join(AUDIO_EXTENSIONS)})."
            ],
            errors=[f"Unsupported media type: {ext}"],
        )

    def _file_not_found_result(self, filename: str) -> AIAnalysisResult:
        return AIAnalysisResult(
            media_type="UNKNOWN",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name="HexShield-AI-Engine",
            model_version="1.0.0",
            analysis_notes=[f"File not found: {filename}"],
            errors=[f"File not found: {filename}"],
        )