# =============================================================================
# HexShield AI — Hugging Face AI Deepfake Analyzer
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Uses Hugging Face Inference API to run real deepfake detection models:
#   - Image: dima806/deepfake_vs_real_image_detection
#   - Video: Frame-by-frame analysis using image model
#   - Audio: Classical feature extraction with librosa
# =============================================================================

import io
import time
import logging
import requests
import tempfile
import os
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import numpy as np
from PIL import Image

from app.config import settings

logger = logging.getLogger(__name__)

# Hugging Face model endpoints
HF_API_BASE = "https://api-inference.huggingface.co/models"

IMAGE_MODEL = "dima806/deepfake_vs_real_image_detection"
AUDIO_MODEL = "facebook/wav2vec2-base"

# Supported formats
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac"}

MAX_FRAMES_FOR_VIDEO = 10


class HuggingFaceDeepfakeAnalyzer:
    """
    Deepfake detection using Hugging Face Inference API.
    Supports images, video (frame-by-frame), and audio.
    """

    def __init__(self):
        self.token = settings.HUGGINGFACE_API_TOKEN
        self.headers = {"Authorization": f"Bearer {self.token}"}
        logger.info("HuggingFaceDeepfakeAnalyzer initialized.")

    # -------------------------------------------------------------------------
    # PUBLIC — Main Analysis Entry Point
    # -------------------------------------------------------------------------

    def analyze(self, data: bytes, filename: str) -> dict:
        """
        Analyze media file for deepfake manipulation.
        """
        ext = Path(filename).suffix.lower()
        start_time = time.monotonic()

        if ext in IMAGE_EXTENSIONS:
            result = self._analyze_image(data, filename)
        elif ext in VIDEO_EXTENSIONS:
            result = self._analyze_video(data, filename)
        elif ext in AUDIO_EXTENSIONS:
            result = self._analyze_audio(data, filename)
        else:
            return self._unsupported_result(filename, ext)

        duration_ms = int((time.monotonic() - start_time) * 1000)
        result["processing_duration_ms"] = duration_ms
        return result

    # -------------------------------------------------------------------------
    # PRIVATE — Image Analysis
    # -------------------------------------------------------------------------

    def _analyze_image(self, data: bytes, filename: str) -> dict:
        """
        Detect deepfake manipulation in an image using
        dima806/deepfake_vs_real_image_detection model.
        """
        logger.info(f"Running HF image deepfake detection: {filename}")

        try:
            response = requests.post(
                f"{HF_API_BASE}/{IMAGE_MODEL}",
                headers=self.headers,
                data=data,
                timeout=30,
            )

            if response.status_code == 503:
                logger.info("Model loading, waiting 20 seconds...")
                time.sleep(20)
                response = requests.post(
                    f"{HF_API_BASE}/{IMAGE_MODEL}",
                    headers=self.headers,
                    data=data,
                    timeout=30,
                )

            if response.status_code != 200:
                logger.error(
                    f"HF API error: {response.status_code} - {response.text}"
                )
                return self._fallback_image_result(data, filename)

            predictions = response.json()
            logger.info(f"HF image predictions: {predictions}")

            fake_score = 0.0
            real_score = 0.0

            if isinstance(predictions, list):
                for pred in predictions:
                    label = str(pred.get("label", "")).lower()
                    score = pred.get("score", 0.0)
                    if "fake" in label or "deepfake" in label or "artificial" in label:
                        fake_score = score
                    elif "real" in label or "authentic" in label:
                        real_score = score

                if fake_score == 0.0 and real_score == 0.0 and predictions:
                    first = predictions[0]
                    if first.get("score", 0) > 0.5:
                        fake_score = first["score"]
                        real_score = 1.0 - fake_score

            manipulation_confidence = round(fake_score, 4)
            if real_score > 0:
                authenticity_score = round(real_score, 4)
            else:
                authenticity_score = round(1.0 - fake_score, 4)

            verdict = self._determine_verdict(authenticity_score, manipulation_confidence)

            return {
                "media_type": "IMAGE",
                "verdict": verdict,
                "authenticity_score": authenticity_score,
                "manipulation_confidence": manipulation_confidence,
                "model_name": IMAGE_MODEL,
                "model_version": "1.0.0",
                "analysis_notes": [
                    f"Hugging Face model: {IMAGE_MODEL}",
                    f"Deepfake probability: {manipulation_confidence * 100:.1f}%",
                    f"Authenticity probability: {authenticity_score * 100:.1f}%",
                    f"Verdict: {verdict}",
                ],
                "errors": [],
            }

        except requests.exceptions.Timeout:
            logger.error("HF API timeout for image analysis")
            return self._fallback_image_result(data, filename)
        except Exception as e:
            logger.error(f"HF image analysis error: {e}")
            return self._fallback_image_result(data, filename)

    # -------------------------------------------------------------------------
    # PRIVATE — Video Analysis
    # -------------------------------------------------------------------------

    def _analyze_video(self, data: bytes, filename: str) -> dict:
        """
        Analyze video by extracting frames and running image
        deepfake detection on each frame.
        """
        logger.info(f"Running HF video deepfake detection: {filename}")

        ext = Path(filename).suffix.lower()
        frame_results = []
        notes = []
        errors = []
        temp_path = None

        try:
            import cv2

            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(data)
                temp_path = tmp.name

            cap = cv2.VideoCapture(temp_path)
            fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            duration_s = total_frames / fps if fps > 0 else 0.0

            notes.append(
                f"Video: {total_frames} frames, {fps:.1f} FPS, "
                f"{duration_s:.1f}s duration."
            )

            interval = max(1, total_frames // MAX_FRAMES_FOR_VIDEO) if total_frames > 0 else 1
            frame_index = 0
            analyzed = 0

            while cap.isOpened() and analyzed < MAX_FRAMES_FOR_VIDEO:
                ret, frame = cap.read()
                if not ret:
                    break

                if frame_index % interval == 0:
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    pil_image = Image.fromarray(rgb)
                    buf = io.BytesIO()
                    pil_image.save(buf, format="JPEG", quality=85)
                    frame_bytes = buf.getvalue()

                    timestamp_ms = int((frame_index / fps) * 1000)

                    frame_result = self._analyze_image(frame_bytes, "frame.jpg")
                    frame_results.append({
                        "frame_index": frame_index,
                        "timestamp_ms": timestamp_ms,
                        "anomaly_score": frame_result.get("manipulation_confidence", 0.0),
                        "is_flagged": frame_result.get("manipulation_confidence", 0.0) >= 0.5,
                        "verdict": frame_result.get("verdict", "INCONCLUSIVE"),
                    })
                    analyzed += 1

                frame_index += 1

            cap.release()

            if not frame_results:
                return self._error_result("VIDEO", filename, ["No frames extracted"])

            scores = [r["anomaly_score"] for r in frame_results]
            mean_score = float(np.mean(scores))
            max_score = float(np.max(scores))
            flagged_count = sum(1 for r in frame_results if r["is_flagged"])

            manipulation_confidence = round(
                (mean_score * 0.6) + (max_score * 0.4), 4
            )
            authenticity_score = round(1.0 - manipulation_confidence, 4)
            verdict = self._determine_verdict(authenticity_score, manipulation_confidence)

            notes.append(
                f"Analyzed {len(frame_results)} frames. "
                f"{flagged_count} flagged as potentially manipulated."
            )
            notes.append(
                f"Average manipulation score: {mean_score * 100:.1f}%. "
                f"Peak score: {max_score * 100:.1f}%."
            )

            return {
                "media_type": "VIDEO",
                "verdict": verdict,
                "authenticity_score": authenticity_score,
                "manipulation_confidence": manipulation_confidence,
                "model_name": f"{IMAGE_MODEL} (frame analysis)",
                "model_version": "1.0.0",
                "total_frames_analyzed": len(frame_results),
                "temporal_inconsistency_score": round(float(np.std(scores)), 4),
                "frame_details": frame_results,
                "analysis_notes": notes,
                "errors": errors,
            }

        except ImportError:
            return self._error_result(
                "VIDEO", filename,
                ["OpenCV not available for video frame extraction."]
            )
        except Exception as e:
            logger.error(f"Video analysis error: {e}")
            return self._error_result("VIDEO", filename, [str(e)])
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    # -------------------------------------------------------------------------
    # PRIVATE — Audio Analysis
    # -------------------------------------------------------------------------

    def _analyze_audio(self, data: bytes, filename: str) -> dict:
        """
        Analyze audio for synthetic voice generation artifacts
        using librosa for feature extraction and statistical analysis.
        """
        logger.info(f"Running audio deepfake detection: {filename}")

        ext = Path(filename).suffix.lower()
        notes = []
        errors = []
        temp_path = None

        try:
            import librosa

            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(data)
                temp_path = tmp.name

            audio, sr = librosa.load(temp_path, sr=22050, mono=True)

            duration_s = len(audio) / sr
            notes.append(f"Audio loaded: {duration_s:.2f}s at {sr}Hz.")

            mfcc = librosa.feature.mfcc(y=audio, sr=sr, n_mfcc=40)
            mfcc_delta = librosa.feature.delta(mfcc)

            zcr = librosa.feature.zero_crossing_rate(audio)
            spectral_centroid = librosa.feature.spectral_centroid(y=audio, sr=sr)
            spectral_bandwidth = librosa.feature.spectral_bandwidth(y=audio, sr=sr)
            rms = librosa.feature.rms(y=audio)

            try:
                f0, voiced_flag, _ = librosa.pyin(
                    audio,
                    fmin=librosa.note_to_hz("C2"),
                    fmax=librosa.note_to_hz("C7"),
                    sr=sr,
                )
                valid_f0 = f0[~np.isnan(f0)] if f0 is not None else np.array([])
                pitch_std = float(np.std(valid_f0)) if len(valid_f0) > 10 else 30.0
            except Exception:
                pitch_std = 30.0

            mfcc_uniformity = 1.0 - min(float(np.std(mfcc_delta)) / 10.0, 1.0)
            zcr_anomaly = min(abs(float(np.mean(zcr)) - 0.08) / 0.1, 1.0)
            pitch_uniformity = 1.0 - min(pitch_std / 30.0, 1.0)
            centroid_anomaly = min(
                abs(float(np.mean(spectral_centroid)) - 2000.0) / 3000.0, 1.0
            )

            manipulation_confidence = round(
                (mfcc_uniformity * 0.35)
                + (pitch_uniformity * 0.35)
                + (zcr_anomaly * 0.15)
                + (centroid_anomaly * 0.15),
                4,
            )
            authenticity_score = round(1.0 - manipulation_confidence, 4)
            verdict = self._determine_verdict(authenticity_score, manipulation_confidence)

            notes.extend([
                f"MFCC uniformity score: {mfcc_uniformity:.4f}",
                f"Pitch uniformity score: {pitch_uniformity:.4f} "
                f"(pitch std: {pitch_std:.1f}Hz)",
                f"ZCR anomaly: {zcr_anomaly:.4f}",
                f"Spectral centroid anomaly: {centroid_anomaly:.4f}",
                f"Overall manipulation confidence: {manipulation_confidence * 100:.1f}%",
                f"Verdict: {verdict}",
            ])

            if manipulation_confidence > 0.7:
                notes.append(
                    "WARNING: High synthesis probability detected. "
                    "Audio shows characteristics consistent with "
                    "text-to-speech or voice conversion systems."
                )

            spectral_data = [
                {"feature": "mfcc_mean", "value": round(float(np.mean(mfcc)), 4)},
                {"feature": "mfcc_std", "value": round(float(np.std(mfcc)), 4)},
                {"feature": "zcr_mean", "value": round(float(np.mean(zcr)), 6)},
                {"feature": "spectral_centroid_mean", "value": round(float(np.mean(spectral_centroid)), 2)},
                {"feature": "spectral_bandwidth_mean", "value": round(float(np.mean(spectral_bandwidth)), 2)},
                {"feature": "rms_mean", "value": round(float(np.mean(rms)), 6)},
                {"feature": "pitch_std_hz", "value": round(pitch_std, 2)},
            ]

            return {
                "media_type": "AUDIO",
                "verdict": verdict,
                "authenticity_score": authenticity_score,
                "manipulation_confidence": manipulation_confidence,
                "model_name": "HexShield-Audio-Analyzer-v2",
                "model_version": "2.0.0",
                "total_segments_analyzed": 1,
                "voice_synthesis_score": round(pitch_uniformity, 4),
                "spectral_analysis": spectral_data,
                "analysis_notes": notes,
                "errors": errors,
            }

        except ImportError:
            return self._error_result(
                "AUDIO", filename,
                ["librosa not available for audio analysis."]
            )
        except Exception as e:
            logger.error(f"Audio analysis error: {e}", exc_info=True)
            return self._error_result("AUDIO", filename, [str(e)])
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    # -------------------------------------------------------------------------
    # PRIVATE — Helpers
    # -------------------------------------------------------------------------

    def _determine_verdict(
        self,
        authenticity_score: float,
        manipulation_confidence: float,
    ) -> str:
        if authenticity_score >= 0.80 and manipulation_confidence < 0.25:
            return "AUTHENTIC"
        elif manipulation_confidence >= 0.75:
            return "MANIPULATED"
        elif manipulation_confidence >= 0.45 or authenticity_score < 0.55:
            return "SUSPICIOUS"
        else:
            return "INCONCLUSIVE"

    def _fallback_image_result(self, data: bytes, filename: str) -> dict:
        """Fall back to classical ELA analysis if HF API fails."""
        logger.info(f"Falling back to classical analysis for {filename}")
        from app.services.ai_engine.image_analyzer import ImageDeepfakeAnalyzer
        analyzer = ImageDeepfakeAnalyzer()
        result = analyzer.analyze(data, filename)
        return {
            "media_type": "IMAGE",
            "verdict": result.verdict,
            "authenticity_score": result.authenticity_score,
            "manipulation_confidence": result.manipulation_confidence,
            "model_name": f"{result.model_name} (classical fallback)",
            "model_version": result.model_version,
            "analysis_notes": result.analysis_notes + [
                "Note: Hugging Face API unavailable. Classical signal processing used."
            ],
            "errors": result.errors,
        }

    def _unsupported_result(self, filename: str, ext: str) -> dict:
        return {
            "media_type": "UNKNOWN",
            "verdict": "INCONCLUSIVE",
            "authenticity_score": 0.0,
            "manipulation_confidence": 0.0,
            "model_name": "HexShield-AI-Engine",
            "model_version": "1.0.0",
            "analysis_notes": [f"Unsupported format: {ext}"],
            "errors": [f"Unsupported format: {ext}"],
            "processing_duration_ms": 0,
        }

    def _error_result(
        self, media_type: str, filename: str, errors: List[str]
    ) -> dict:
        return {
            "media_type": media_type,
            "verdict": "INCONCLUSIVE",
            "authenticity_score": 0.0,
            "manipulation_confidence": 0.0,
            "model_name": "HexShield-AI-Engine",
            "model_version": "1.0.0",
            "analysis_notes": ["Analysis failed."],
            "errors": errors,
            "processing_duration_ms": 0,
        }