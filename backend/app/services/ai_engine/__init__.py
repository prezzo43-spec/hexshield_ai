# =============================================================================
# HexShield AI — AI Engine Package
# Exposes the public API for Layer 2: Multimodal AI Deepfake Detection Engine
# =============================================================================

from app.services.ai_engine.ai_engine import AIDeepfakeEngine, detect_media_type
from app.services.ai_engine.model_base import AIAnalysisResult, determine_ai_verdict
from app.services.ai_engine.image_analyzer import ImageDeepfakeAnalyzer
from app.services.ai_engine.video_analyzer import VideoDeepfakeAnalyzer
from app.services.ai_engine.audio_analyzer import AudioDeepfakeAnalyzer
from app.services.ai_engine.consensus_engine import ForensicConsensusEngine

__all__ = [
    "AIDeepfakeEngine",
    "detect_media_type",
    "AIAnalysisResult",
    "determine_ai_verdict",
    "ImageDeepfakeAnalyzer",
    "VideoDeepfakeAnalyzer",
    "AudioDeepfakeAnalyzer",
    "ForensicConsensusEngine",
]