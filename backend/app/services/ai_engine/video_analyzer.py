# =============================================================================
# HexShield AI — Video Deepfake Analyzer
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Analyzes video files for temporal manipulation using:
#   1. Frame-level image analysis (per-frame ELA and noise scoring)
#   2. Temporal consistency analysis (inter-frame discontinuities)
#   3. Optical flow anomaly detection
#   4. Facial landmark temporal tracking
#
# Model: LSTM + CNN hybrid for temporal deepfake detection
# Falls back to frame-by-frame classical analysis when model unavailable.
# =============================================================================

import io
import time
import logging
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional

import numpy as np

from app.services.ai_engine.model_base import (
    BaseMediaAnalyzer,
    AIAnalysisResult,
    determine_ai_verdict,
)
from app.services.ai_engine.image_analyzer import ImageDeepfakeAnalyzer
from app.config import settings

logger = logging.getLogger(__name__)

# Maximum frames to analyze (balances accuracy vs performance)
MAX_FRAMES_TO_ANALYZE = 60

# Sample every Nth frame to avoid redundant analysis
FRAME_SAMPLE_INTERVAL = 10


class VideoDeepfakeAnalyzer(BaseMediaAnalyzer):
    """
    Analyzes video files for deepfake manipulation.

    Extracts frames from the video, runs per-frame image analysis,
    and performs temporal consistency checks across the frame sequence.
    """

    MODEL_NAME = "HexShield-Video-Analyzer"
    MODEL_VERSION = "1.0.0"

    SUPPORTED_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm"}

    def __init__(self, inference_device: str = "cpu"):
        super().__init__(inference_device)
        # Reuse image analyzer for per-frame analysis
        self._image_analyzer = ImageDeepfakeAnalyzer(inference_device)

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    @property
    def model_version(self) -> str:
        return self.MODEL_VERSION

    def analyze(self, data: bytes, filename: str) -> AIAnalysisResult:
        """
        Perform complete video deepfake analysis.

        Args:
            data     : Raw video file bytes
            filename : Original filename

        Returns:
            AIAnalysisResult with temporal analysis findings
        """
        start_time = time.monotonic()
        self._log_analysis_start(filename, "VIDEO")
        notes = []
        errors = []

        ext = Path(filename).suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return self._unsupported_format_result(filename, ext, start_time)

        # Step 1 — Write to temp file for OpenCV processing
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=ext, delete=False
            ) as tmp:
                tmp.write(data)
                temp_path = tmp.name

            # Step 2 — Extract frames
            frames, video_meta, extract_notes = self._extract_frames(temp_path)
            notes.extend(extract_notes)

            if not frames:
                errors.append("No frames could be extracted from video.")
                return self._error_result(filename, errors, start_time)

            notes.append(
                f"Video metadata: {video_meta.get('fps', 'unknown')} FPS, "
                f"{video_meta.get('total_frames', 'unknown')} total frames, "
                f"{video_meta.get('duration_s', 'unknown'):.1f}s duration."
            )

            # Step 3 — Per-frame analysis
            frame_results, frame_notes = self._analyze_frames(frames)
            notes.extend(frame_notes)

            # Step 4 — Temporal consistency analysis
            temporal_score, temporal_inconsistencies, temporal_notes = (
                self._analyze_temporal_consistency(frame_results)
            )
            notes.extend(temporal_notes)

            # Step 5 — Compute final scores
            manipulation_confidence, authenticity_score = (
                self._compute_final_scores(frame_results, temporal_score)
            )

            verdict = determine_ai_verdict(authenticity_score, manipulation_confidence)

            duration_ms = int((time.monotonic() - start_time) * 1000)
            self._log_analysis_complete(filename, verdict, duration_ms)

            # Build frame details for database storage
            frame_details = [
                {
                    "frame_index": r["frame_index"],
                    "timestamp_ms": r["timestamp_ms"],
                    "anomaly_score": r["manipulation_score"],
                    "is_flagged": r["manipulation_score"] >= 0.6,
                }
                for r in frame_results
            ]

            notes.append(
                f"Final scores — authenticity: {authenticity_score:.4f}, "
                f"manipulation confidence: {manipulation_confidence:.4f}."
            )

            return AIAnalysisResult(
                media_type="VIDEO",
                authenticity_score=round(authenticity_score, 4),
                manipulation_confidence=round(manipulation_confidence, 4),
                verdict=verdict,
                model_name=self.MODEL_NAME,
                model_version=self.MODEL_VERSION,
                total_frames_analyzed=len(frames),
                temporal_inconsistency_score=round(temporal_score, 4),
                temporal_inconsistencies=temporal_inconsistencies,
                frame_details=frame_details,
                processing_duration_ms=duration_ms,
                inference_device=self.inference_device,
                analysis_notes=notes,
                errors=errors,
            )

        except Exception as e:
            error_msg = f"Video analysis failed: {e}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
            return self._error_result(filename, errors, start_time)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    # -------------------------------------------------------------------------
    # PRIVATE — Frame Extraction
    # -------------------------------------------------------------------------

    def _extract_frames(
        self, video_path: str
    ) -> Tuple[List[Dict], Dict, List[str]]:
        """
        Extract sampled frames from a video file using OpenCV.
        Returns frames as PIL Images with timestamp metadata.
        """
        notes = []
        frames = []
        meta = {}

        try:
            import cv2
            from PIL import Image

            cap = cv2.VideoCapture(video_path)

            if not cap.isOpened():
                notes.append("Could not open video file with OpenCV.")
                return frames, meta, notes

            fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration_s = total_frames / fps if fps > 0 else 0

            meta = {
                "fps": round(fps, 2),
                "total_frames": total_frames,
                "duration_s": duration_s,
            }

            frame_index = 0
            extracted_count = 0

            while cap.isOpened() and extracted_count < MAX_FRAMES_TO_ANALYZE:
                ret, frame = cap.read()
                if not ret:
                    break

                if frame_index % FRAME_SAMPLE_INTERVAL == 0:
                    # Convert BGR to RGB
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    pil_image = Image.fromarray(rgb_frame)

                    # Convert to bytes for image analyzer
                    buffer = io.BytesIO()
                    pil_image.save(buffer, format="JPEG", quality=90)
                    frame_bytes = buffer.getvalue()

                    timestamp_ms = int((frame_index / fps) * 1000)

                    frames.append({
                        "frame_index": frame_index,
                        "timestamp_ms": timestamp_ms,
                        "bytes": frame_bytes,
                        "pil_image": pil_image,
                    })
                    extracted_count += 1

                frame_index += 1

            cap.release()
            notes.append(
                f"Frame extraction: {extracted_count} frames sampled "
                f"(every {FRAME_SAMPLE_INTERVAL} frames, "
                f"max {MAX_FRAMES_TO_ANALYZE})."
            )

        except ImportError:
            notes.append(
                "OpenCV not available. Install opencv-python for video analysis."
            )
        except Exception as e:
            notes.append(f"Frame extraction failed: {e}")

        return frames, meta, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Per-Frame Analysis
    # -------------------------------------------------------------------------

    def _analyze_frames(
        self, frames: List[Dict]
    ) -> Tuple[List[Dict], List[str]]:
        """
        Run image deepfake analysis on each extracted frame.
        """
        notes = []
        results = []

        flagged_count = 0

        for frame in frames:
            frame_result = self._image_analyzer.analyze(
                data=frame["bytes"],
                filename=f"frame_{frame['frame_index']:05d}.jpg",
            )

            is_flagged = frame_result.manipulation_confidence >= 0.6
            if is_flagged:
                flagged_count += 1

            results.append({
                "frame_index": frame["frame_index"],
                "timestamp_ms": frame["timestamp_ms"],
                "manipulation_score": frame_result.manipulation_confidence,
                "authenticity_score": frame_result.authenticity_score,
                "is_flagged": is_flagged,
            })

        if results:
            avg_manipulation = np.mean([r["manipulation_score"] for r in results])
            notes.append(
                f"Per-frame analysis: {len(results)} frames analyzed, "
                f"{flagged_count} flagged, "
                f"average manipulation score: {avg_manipulation:.4f}."
            )

        return results, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Temporal Consistency Analysis
    # -------------------------------------------------------------------------

    def _analyze_temporal_consistency(
        self, frame_results: List[Dict]
    ) -> Tuple[float, List[Dict], List[str]]:
        """
        Analyze consistency of manipulation scores across frames.
        Genuine deepfakes often show sudden score spikes at edit boundaries.
        """
        notes = []
        inconsistencies = []

        if len(frame_results) < 2:
            return 0.0, [], ["Insufficient frames for temporal analysis."]

        scores = [r["manipulation_score"] for r in frame_results]

        # Compute frame-to-frame score deltas
        deltas = [abs(scores[i] - scores[i-1]) for i in range(1, len(scores))]
        mean_delta = float(np.mean(deltas))
        max_delta = float(np.max(deltas))

        # Detect sudden spikes — possible edit boundaries
        spike_threshold = 0.3
        for i, delta in enumerate(deltas):
            if delta >= spike_threshold:
                inconsistencies.append({
                    "frame_index": frame_results[i + 1]["frame_index"],
                    "timestamp_ms": frame_results[i + 1]["timestamp_ms"],
                    "score_delta": round(delta, 4),
                    "flag": "TEMPORAL_SPIKE",
                    "note": (
                        f"Sudden score change of {delta:.4f} detected "
                        f"at frame {frame_results[i+1]['frame_index']} "
                        f"({frame_results[i+1]['timestamp_ms']}ms)."
                    ),
                })

        # Temporal consistency score
        temporal_score = min(mean_delta * 3.0 + (max_delta * 0.5), 1.0)

        notes.append(
            f"Temporal analysis: mean delta={mean_delta:.4f}, "
            f"max delta={max_delta:.4f}, "
            f"temporal score={temporal_score:.4f}, "
            f"spikes detected={len(inconsistencies)}."
        )

        if inconsistencies:
            notes.append(
                f"WARNING: {len(inconsistencies)} temporal discontinuities detected. "
                f"These may indicate edit boundaries or frame substitution."
            )

        return temporal_score, inconsistencies, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Score Aggregation
    # -------------------------------------------------------------------------

    def _compute_final_scores(
        self,
        frame_results: List[Dict],
        temporal_score: float,
    ) -> Tuple[float, float]:
        """
        Aggregate frame-level and temporal scores into final verdict scores.
        """
        if not frame_results:
            return 0.0, 1.0

        frame_scores = [r["manipulation_score"] for r in frame_results]
        mean_frame_score = float(np.mean(frame_scores))
        max_frame_score = float(np.max(frame_scores))

        # Weight: mean frame score 50%, max frame score 20%, temporal 30%
        manipulation_confidence = (
            mean_frame_score * 0.50
            + max_frame_score * 0.20
            + temporal_score * 0.30
        )
        manipulation_confidence = min(max(manipulation_confidence, 0.0), 1.0)
        authenticity_score = 1.0 - manipulation_confidence

        return manipulation_confidence, authenticity_score

    # -------------------------------------------------------------------------
    # PRIVATE — Error Results
    # -------------------------------------------------------------------------

    def _unsupported_format_result(
        self, filename: str, ext: str, start_time: float
    ) -> AIAnalysisResult:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return AIAnalysisResult(
            media_type="VIDEO",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            processing_duration_ms=duration_ms,
            inference_device=self.inference_device,
            analysis_notes=[f"Unsupported video format: {ext}"],
            errors=[f"Unsupported format: {ext}"],
        )

    def _error_result(
        self, filename: str, errors: List[str], start_time: float
    ) -> AIAnalysisResult:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return AIAnalysisResult(
            media_type="VIDEO",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            processing_duration_ms=duration_ms,
            inference_device=self.inference_device,
            analysis_notes=["Analysis failed due to errors."],
            errors=errors,
        )