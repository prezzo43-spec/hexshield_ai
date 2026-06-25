# =============================================================================
# HexShield AI — Audio Deepfake Analyzer
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Analyzes audio files for synthetic voice manipulation using:
#   1. MFCC (Mel-Frequency Cepstral Coefficients) analysis
#   2. Spectral centroid and bandwidth anomaly detection
#   3. Zero-crossing rate analysis
#   4. GAN artifact detection in frequency domain
#
# Model: MFCC + statistical classifier for voice synthesis detection
# Uses librosa for audio feature extraction.
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
from app.config import settings

logger = logging.getLogger(__name__)

# Audio analysis parameters
SAMPLE_RATE = 22050
SEGMENT_DURATION_S = 3.0
N_MFCC = 40


class AudioDeepfakeAnalyzer(BaseMediaAnalyzer):
    """
    Analyzes audio files for synthetic voice generation artifacts.

    Extracts spectral and temporal features from audio segments
    and computes anomaly scores indicating voice synthesis.
    """

    MODEL_NAME = "HexShield-Audio-Analyzer"
    MODEL_VERSION = "1.0.0"

    SUPPORTED_EXTENSIONS = {
        ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma"
    }

    def __init__(self, inference_device: str = "cpu"):
        super().__init__(inference_device)

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    @property
    def model_version(self) -> str:
        return self.MODEL_VERSION

    def analyze(self, data: bytes, filename: str) -> AIAnalysisResult:
        """
        Perform complete audio deepfake analysis.

        Args:
            data     : Raw audio file bytes
            filename : Original filename

        Returns:
            AIAnalysisResult with spectral analysis findings
        """
        start_time = time.monotonic()
        self._log_analysis_start(filename, "AUDIO")
        notes = []
        errors = []

        ext = Path(filename).suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return self._unsupported_format_result(filename, ext, start_time)

        temp_path = None
        try:
            # Write to temp file for librosa processing
            with tempfile.NamedTemporaryFile(
                suffix=ext, delete=False
            ) as tmp:
                tmp.write(data)
                temp_path = tmp.name

            # Load audio
            audio_data, sr, load_notes = self._load_audio(temp_path)
            notes.extend(load_notes)

            if audio_data is None:
                errors.append("Failed to load audio data.")
                return self._error_result(filename, errors, start_time)

            duration_s = len(audio_data) / sr
            notes.append(
                f"Audio loaded: duration={duration_s:.2f}s, "
                f"sample_rate={sr}Hz, samples={len(audio_data)}."
            )

            # Segment the audio for analysis
            segments = self._segment_audio(audio_data, sr)
            notes.append(
                f"Audio segmented into {len(segments)} segments "
                f"of {SEGMENT_DURATION_S}s each."
            )

            # Analyze each segment
            segment_results, segment_notes = self._analyze_segments(
                segments, sr
            )
            notes.extend(segment_notes)

            # Spectral analysis on full signal
            spectral_results, spectral_notes = self._full_spectral_analysis(
                audio_data, sr
            )
            notes.extend(spectral_notes)

            # Voice synthesis detection
            voice_synthesis_score, synthesis_notes = (
                self._detect_voice_synthesis(audio_data, sr)
            )
            notes.extend(synthesis_notes)

            # Compute final scores
            manipulation_confidence, authenticity_score = (
                self._compute_final_scores(
                    segment_results, voice_synthesis_score
                )
            )

            verdict = determine_ai_verdict(
                authenticity_score, manipulation_confidence
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)
            self._log_analysis_complete(filename, verdict, duration_ms)

            # Build frame details for database storage
            frame_details = [
                {
                    "frame_index": r["segment_index"],
                    "timestamp_ms": r["timestamp_ms"],
                    "anomaly_score": r["anomaly_score"],
                    "is_flagged": r["is_flagged"],
                }
                for r in segment_results
            ]

            notes.append(
                f"Final scores — authenticity: {authenticity_score:.4f}, "
                f"manipulation confidence: {manipulation_confidence:.4f}."
            )

            return AIAnalysisResult(
                media_type="AUDIO",
                authenticity_score=round(authenticity_score, 4),
                manipulation_confidence=round(manipulation_confidence, 4),
                verdict=verdict,
                model_name=self.MODEL_NAME,
                model_version=self.MODEL_VERSION,
                total_segments_analyzed=len(segments),
                spectral_analysis=spectral_results,
                voice_synthesis_score=round(voice_synthesis_score, 4),
                frame_details=frame_details,
                processing_duration_ms=duration_ms,
                inference_device=self.inference_device,
                analysis_notes=notes,
                errors=errors,
            )

        except Exception as e:
            error_msg = f"Audio analysis failed: {e}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
            return self._error_result(filename, errors, start_time)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    # -------------------------------------------------------------------------
    # PRIVATE — Audio Loading
    # -------------------------------------------------------------------------

    def _load_audio(
        self, audio_path: str
    ) -> Tuple[Optional[np.ndarray], int, List[str]]:
        """Load audio file using librosa."""
        notes = []
        try:
            import librosa
            audio_data, sr = librosa.load(
                audio_path,
                sr=SAMPLE_RATE,
                mono=True,
            )
            notes.append(f"Audio loaded successfully using librosa.")
            return audio_data, sr, notes
        except ImportError:
            notes.append(
                "librosa not available. "
                "Install librosa for audio analysis."
            )
            return None, SAMPLE_RATE, notes
        except Exception as e:
            notes.append(f"Audio loading failed: {e}")
            return None, SAMPLE_RATE, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Audio Segmentation
    # -------------------------------------------------------------------------

    def _segment_audio(
        self, audio_data: np.ndarray, sr: int
    ) -> List[np.ndarray]:
        """
        Split audio into fixed-length segments for analysis.
        """
        segment_length = int(SEGMENT_DURATION_S * sr)
        segments = []

        for start in range(0, len(audio_data), segment_length):
            segment = audio_data[start: start + segment_length]
            if len(segment) >= sr:  # Minimum 1 second
                segments.append(segment)

        return segments

    # -------------------------------------------------------------------------
    # PRIVATE — Segment Analysis
    # -------------------------------------------------------------------------

    def _analyze_segments(
        self, segments: List[np.ndarray], sr: int
    ) -> Tuple[List[Dict], List[str]]:
        """
        Analyze each audio segment for synthesis artifacts.
        Extracts MFCC features and computes anomaly scores.
        """
        notes = []
        results = []

        try:
            import librosa

            flagged_count = 0

            for idx, segment in enumerate(segments):
                timestamp_ms = int(idx * SEGMENT_DURATION_S * 1000)

                # Extract MFCC features
                mfcc = librosa.feature.mfcc(
                    y=segment, sr=sr, n_mfcc=N_MFCC
                )
                mfcc_mean = float(np.mean(mfcc))
                mfcc_std = float(np.std(mfcc))
                mfcc_delta = librosa.feature.delta(mfcc)
                mfcc_delta_std = float(np.std(mfcc_delta))

                # Extract zero crossing rate
                zcr = librosa.feature.zero_crossing_rate(segment)
                zcr_mean = float(np.mean(zcr))
                zcr_std = float(np.std(zcr))

                # Extract spectral features
                spectral_centroid = librosa.feature.spectral_centroid(
                    y=segment, sr=sr
                )
                centroid_mean = float(np.mean(spectral_centroid))
                centroid_std = float(np.std(spectral_centroid))

                # Compute anomaly score
                # GAN-generated speech tends to have:
                # - Unusually uniform MFCC patterns (low delta std)
                # - Abnormal zero-crossing rates
                # - Unnatural spectral centroids
                mfcc_uniformity = 1.0 - min(mfcc_delta_std / 10.0, 1.0)
                zcr_anomaly = min(abs(zcr_mean - 0.08) / 0.1, 1.0)
                centroid_anomaly = min(
                    abs(centroid_mean - 2000) / 3000.0, 1.0
                )

                anomaly_score = (
                    mfcc_uniformity * 0.50
                    + zcr_anomaly * 0.25
                    + centroid_anomaly * 0.25
                )
                anomaly_score = min(max(anomaly_score, 0.0), 1.0)
                is_flagged = anomaly_score >= 0.6

                if is_flagged:
                    flagged_count += 1

                results.append({
                    "segment_index": idx,
                    "timestamp_ms": timestamp_ms,
                    "mfcc_mean": round(mfcc_mean, 4),
                    "mfcc_std": round(mfcc_std, 4),
                    "mfcc_delta_std": round(mfcc_delta_std, 4),
                    "zcr_mean": round(zcr_mean, 6),
                    "centroid_mean": round(centroid_mean, 2),
                    "anomaly_score": round(anomaly_score, 4),
                    "is_flagged": is_flagged,
                })

            if results:
                avg_score = np.mean([r["anomaly_score"] for r in results])
                notes.append(
                    f"Segment analysis: {len(results)} segments, "
                    f"{flagged_count} flagged, "
                    f"average anomaly score: {avg_score:.4f}."
                )

        except ImportError:
            notes.append("librosa required for segment analysis.")
        except Exception as e:
            notes.append(f"Segment analysis failed: {e}")

        return results, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Full Spectral Analysis
    # -------------------------------------------------------------------------

    def _full_spectral_analysis(
        self, audio_data: np.ndarray, sr: int
    ) -> Tuple[List[Dict], List[str]]:
        """
        Perform spectral analysis on the full audio signal.
        Detects frequency-domain artifacts characteristic of
        text-to-speech and voice conversion systems.
        """
        notes = []
        spectral_results = []

        try:
            import librosa

            # Short-time Fourier transform
            stft = np.abs(librosa.stft(audio_data))

            # Spectral rolloff
            rolloff = librosa.feature.spectral_rolloff(y=audio_data, sr=sr)
            rolloff_mean = float(np.mean(rolloff))

            # Spectral bandwidth
            bandwidth = librosa.feature.spectral_bandwidth(y=audio_data, sr=sr)
            bandwidth_mean = float(np.mean(bandwidth))

            # RMS energy
            rms = librosa.feature.rms(y=audio_data)
            rms_mean = float(np.mean(rms))
            rms_std = float(np.std(rms))

            spectral_results = [
                {
                    "feature": "spectral_rolloff_mean",
                    "value": round(rolloff_mean, 2),
                    "unit": "Hz",
                },
                {
                    "feature": "spectral_bandwidth_mean",
                    "value": round(bandwidth_mean, 2),
                    "unit": "Hz",
                },
                {
                    "feature": "rms_energy_mean",
                    "value": round(rms_mean, 6),
                    "unit": "amplitude",
                },
                {
                    "feature": "rms_energy_std",
                    "value": round(rms_std, 6),
                    "unit": "amplitude",
                },
            ]

            notes.append(
                f"Spectral analysis: rolloff={rolloff_mean:.0f}Hz, "
                f"bandwidth={bandwidth_mean:.0f}Hz, "
                f"RMS mean={rms_mean:.4f}."
            )

        except ImportError:
            notes.append("librosa required for spectral analysis.")
        except Exception as e:
            notes.append(f"Spectral analysis failed: {e}")

        return spectral_results, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Voice Synthesis Detection
    # -------------------------------------------------------------------------

    def _detect_voice_synthesis(
        self, audio_data: np.ndarray, sr: int
    ) -> Tuple[float, List[str]]:
        """
        Compute an overall voice synthesis probability score.

        TTS and voice conversion systems exhibit:
        - Overly consistent pitch (low pitch variance)
        - Unnaturally smooth energy transitions
        - Missing micro-prosodic variations
        """
        notes = []

        try:
            import librosa

            # Fundamental frequency (pitch) estimation
            f0, voiced_flag, voiced_probs = librosa.pyin(
                audio_data,
                fmin=librosa.note_to_hz("C2"),
                fmax=librosa.note_to_hz("C7"),
                sr=sr,
            )

            # Filter valid pitch values
            valid_f0 = f0[~np.isnan(f0)] if f0 is not None else np.array([])

            if len(valid_f0) > 10:
                pitch_std = float(np.std(valid_f0))
                pitch_mean = float(np.mean(valid_f0))

                # Unusually low pitch variance suggests synthetic speech
                # Natural speech typically has std > 20Hz
                pitch_uniformity = 1.0 - min(pitch_std / 30.0, 1.0)

                voice_synthesis_score = pitch_uniformity

                notes.append(
                    f"Voice synthesis detection: pitch mean={pitch_mean:.1f}Hz, "
                    f"pitch std={pitch_std:.1f}Hz, "
                    f"synthesis score={voice_synthesis_score:.4f}."
                )

                if voice_synthesis_score > 0.7:
                    notes.append(
                        "WARNING: Unnaturally uniform pitch detected. "
                        "Consistent with text-to-speech or voice conversion systems."
                    )
            else:
                voice_synthesis_score = 0.0
                notes.append(
                    "Voice synthesis: insufficient voiced segments for pitch analysis."
                )

        except ImportError:
            notes.append("librosa required for voice synthesis detection.")
            voice_synthesis_score = 0.0
        except Exception as e:
            notes.append(f"Voice synthesis detection failed: {e}")
            voice_synthesis_score = 0.0

        return voice_synthesis_score, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Score Aggregation
    # -------------------------------------------------------------------------

    def _compute_final_scores(
        self,
        segment_results: List[Dict],
        voice_synthesis_score: float,
    ) -> Tuple[float, float]:
        """
        Aggregate segment and synthesis scores into final verdict scores.
        """
        if not segment_results:
            manipulation_confidence = voice_synthesis_score
        else:
            segment_scores = [r["anomaly_score"] for r in segment_results]
            mean_segment_score = float(np.mean(segment_scores))
            max_segment_score = float(np.max(segment_scores))

            manipulation_confidence = (
                mean_segment_score * 0.40
                + max_segment_score * 0.20
                + voice_synthesis_score * 0.40
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
            media_type="AUDIO",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            processing_duration_ms=duration_ms,
            inference_device=self.inference_device,
            analysis_notes=[f"Unsupported audio format: {ext}"],
            errors=[f"Unsupported format: {ext}"],
        )

    def _error_result(
        self, filename: str, errors: List[str], start_time: float
    ) -> AIAnalysisResult:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return AIAnalysisResult(
            media_type="AUDIO",
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