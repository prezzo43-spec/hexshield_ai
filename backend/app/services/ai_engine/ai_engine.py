# =============================================================================
# HexShield AI — AI Engine Orchestrator
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Routes files to the correct analyzer based on media type.
# Uses Hugging Face API for real deepfake detection.
# Falls back to classical analysis if HF API is unavailable.
# =============================================================================

import time
import logging
from pathlib import Path
from typing import Optional

from app.services.ai_engine.model_base import AIAnalysisResult, determine_ai_verdict
from app.services.ai_engine.huggingface_analyzer import (
    HuggingFaceDeepfakeAnalyzer,
    IMAGE_EXTENSIONS,
    VIDEO_EXTENSIONS,
    AUDIO_EXTENSIONS,
)
from app.config import settings

logger = logging.getLogger(__name__)


def detect_media_type(filename: str) -> Optional[str]:
    """
    Determine media type from file extension.
    Returns: 'IMAGE' | 'VIDEO' | 'AUDIO' | None
    """
    ext = Path(filename).suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return "IMAGE"
    elif ext in VIDEO_EXTENSIONS:
        return "VIDEO"
    elif ext in AUDIO_EXTENSIONS:
        return "AUDIO"
    return None


class AIDeepfakeEngine:
    """
    Layer 2: Multimodal AI Deepfake Detection Engine.
    Uses Hugging Face Inference API for real deepfake detection.
    """

    def __init__(self, inference_device: str = None):
        self.inference_device = (
            inference_device or settings.AI_INFERENCE_DEVICE
        )
        self._hf_analyzer = None
        logger.info(
            f"AIDeepfakeEngine initialized — device={self.inference_device}"
        )

    @property
    def hf_analyzer(self) -> HuggingFaceDeepfakeAnalyzer:
        if self._hf_analyzer is None:
            self._hf_analyzer = HuggingFaceDeepfakeAnalyzer()
        return self._hf_analyzer

    def analyze_file(
        self,
        file_path: str,
        declared_mime_type: Optional[str] = None,
    ) -> AIAnalysisResult:
        """Analyze a file from disk path."""
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
        """Analyze raw bytes directly."""
        media_type = detect_media_type(filename)

        if media_type is None:
            return self._unsupported_media_result(filename)

        logger.info(
            f"AIDeepfakeEngine: Routing {filename} "
            f"({media_type}) to HF analyzer."
        )

        # Run Hugging Face analysis
        result_dict = self.hf_analyzer.analyze(data, filename)

        # Convert dict result to AIAnalysisResult
        return AIAnalysisResult(
            media_type=result_dict.get("media_type", media_type),
            authenticity_score=result_dict.get("authenticity_score", 0.0),
            manipulation_confidence=result_dict.get("manipulation_confidence", 0.0),
            verdict=result_dict.get("verdict", "INCONCLUSIVE"),
            model_name=result_dict.get("model_name", "HexShield-AI-Engine"),
            model_version=result_dict.get("model_version", "1.0.0"),
            face_regions_detected=result_dict.get("face_regions_detected"),
            compression_artifact_score=result_dict.get("compression_artifact_score"),
            noise_pattern_anomaly_score=result_dict.get("noise_pattern_anomaly_score"),
            ela_anomaly_score=result_dict.get("ela_anomaly_score"),
            total_frames_analyzed=result_dict.get("total_frames_analyzed"),
            temporal_inconsistency_score=result_dict.get("temporal_inconsistency_score"),
            temporal_inconsistencies=result_dict.get("temporal_inconsistencies"),
            total_segments_analyzed=result_dict.get("total_segments_analyzed"),
            spectral_analysis=result_dict.get("spectral_analysis"),
            voice_synthesis_score=result_dict.get("voice_synthesis_score"),
            frame_details=result_dict.get("frame_details", []),
            processing_duration_ms=result_dict.get("processing_duration_ms"),
            inference_device=self.inference_device,
            analysis_notes=result_dict.get("analysis_notes", []),
            errors=result_dict.get("errors", []),
        )

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
                f"Supported: images, video, audio."
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