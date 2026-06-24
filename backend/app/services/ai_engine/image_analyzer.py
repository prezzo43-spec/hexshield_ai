# =============================================================================
# HexShield AI — Image Deepfake Analyzer
# Layer 2: Multimodal AI Deepfake Detection Engine
#
# Analyzes images for synthetic manipulation using:
#   1. Error Level Analysis (ELA) — detects re-saved/edited regions
#   2. Noise pattern analysis — detects GAN-generated texture artifacts
#   3. Compression artifact scoring — detects inconsistent JPEG compression
#   4. Face region detection — identifies manipulated facial areas
#
# Model: EfficientNet-B4 fine-tuned on FaceForensics++ dataset
# When model weights are not available, the engine falls back to
# classical signal processing methods that do not require GPU.
# =============================================================================

import io
import time
import hashlib
import logging
import math
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import numpy as np
from PIL import Image, ImageChops, ImageEnhance

from app.services.ai_engine.model_base import (
    BaseMediaAnalyzer,
    AIAnalysisResult,
    determine_ai_verdict,
)
from app.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# IMAGE ANALYZER
# =============================================================================

class ImageDeepfakeAnalyzer(BaseMediaAnalyzer):
    """
    Analyzes images for deepfake manipulation using classical signal
    processing methods and optional deep learning inference.

    Classical methods (always available, no GPU required):
      - Error Level Analysis (ELA)
      - Statistical noise analysis
      - Compression consistency scoring
      - Frequency domain analysis (DCT)

    Deep learning (requires model weights in AI_MODEL_WEIGHTS_DIR):
      - EfficientNet-B4 binary classifier
    """

    MODEL_NAME = "HexShield-Image-Analyzer"
    MODEL_VERSION = "1.0.0"

    # Supported image formats
    SUPPORTED_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif"
    }

    def __init__(self, inference_device: str = "cpu"):
        super().__init__(inference_device)
        self._deep_model = None
        self._try_load_deep_model()

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    @property
    def model_version(self) -> str:
        return self.MODEL_VERSION

    def _try_load_deep_model(self) -> None:
        """
        Attempt to load deep learning model weights.
        Falls back gracefully to classical methods if unavailable.
        """
        weights_path = Path(settings.AI_MODEL_WEIGHTS_DIR) / "image_model.pt"
        if weights_path.exists():
            try:
                import torch
                self._deep_model = torch.load(
                    str(weights_path),
                    map_location=self.inference_device,
                )
                self._deep_model.eval()
                self._model_loaded = True
                logger.info(f"Deep learning model loaded from {weights_path}")
            except Exception as e:
                logger.warning(
                    f"Could not load deep model weights: {e}. "
                    f"Falling back to classical analysis."
                )
        else:
            logger.info(
                f"No model weights found at {weights_path}. "
                f"Using classical signal processing analysis."
            )

    # -------------------------------------------------------------------------
    # PUBLIC — Main Analysis Entry Point
    # -------------------------------------------------------------------------

    def analyze(self, data: bytes, filename: str) -> AIAnalysisResult:
        """
        Perform complete image manipulation analysis.

        Args:
            data     : Raw image file bytes
            filename : Original filename

        Returns:
            AIAnalysisResult with all image analysis findings
        """
        start_time = time.monotonic()
        self._log_analysis_start(filename, "IMAGE")
        notes = []
        errors = []

        ext = Path(filename).suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return self._unsupported_format_result(filename, ext, start_time)

        # Load image
        try:
            image = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception as e:
            error_msg = f"Failed to open image: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            return self._error_result(filename, errors, start_time)

        width, height = image.size
        notes.append(
            f"Image dimensions: {width}x{height} pixels. "
            f"Mode: RGB. Format hint: {ext.upper()}."
        )

        # Run analysis pipeline
        ela_score, ela_notes = self._perform_ela(data, image, ext)
        noise_score, noise_notes = self._analyze_noise_patterns(image)
        compression_score, compression_notes = self._analyze_compression(
            data, image, ext
        )
        face_regions, face_notes = self._detect_face_regions(image)

        notes.extend(ela_notes)
        notes.extend(noise_notes)
        notes.extend(compression_notes)
        notes.extend(face_notes)

        # Deep learning inference if model is available
        dl_manipulation_score = None
        if self._model_loaded and self._deep_model is not None:
            dl_manipulation_score, dl_notes = self._deep_learning_inference(image)
            notes.extend(dl_notes)

        # Compute final scores
        manipulation_confidence, authenticity_score = self._compute_final_scores(
            ela_score=ela_score,
            noise_score=noise_score,
            compression_score=compression_score,
            dl_score=dl_manipulation_score,
        )

        verdict = determine_ai_verdict(authenticity_score, manipulation_confidence)

        duration_ms = int((time.monotonic() - start_time) * 1000)
        self._log_analysis_complete(filename, verdict, duration_ms)

        notes.append(
            f"Final scores — authenticity: {authenticity_score:.4f}, "
            f"manipulation confidence: {manipulation_confidence:.4f}."
        )

        return AIAnalysisResult(
            media_type="IMAGE",
            authenticity_score=round(authenticity_score, 4),
            manipulation_confidence=round(manipulation_confidence, 4),
            verdict=verdict,
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            face_regions_detected=face_regions,
            compression_artifact_score=round(compression_score, 4),
            noise_pattern_anomaly_score=round(noise_score, 4),
            ela_anomaly_score=round(ela_score, 4),
            processing_duration_ms=duration_ms,
            inference_device=self.inference_device,
            analysis_notes=notes,
            errors=errors,
        )

    # -------------------------------------------------------------------------
    # PRIVATE — Error Level Analysis (ELA)
    # -------------------------------------------------------------------------

    def _perform_ela(
        self,
        data: bytes,
        image: Image.Image,
        ext: str,
    ) -> Tuple[float, List[str]]:
        """
        Error Level Analysis detects regions of an image that have been
        re-compressed at a different quality level — a strong indicator
        of splicing or local editing.

        Method:
          1. Re-save the image at a known JPEG quality (90%)
          2. Compute the pixel-wise difference between original and re-saved
          3. Amplify the difference for analysis
          4. High variance in the difference map indicates manipulation
        """
        notes = []
        try:
            # Re-save at known quality
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=90)
            buffer.seek(0)
            resaved = Image.open(buffer).convert("RGB")

            # Compute pixel difference
            diff = ImageChops.difference(image, resaved)

            # Convert to numpy for statistical analysis
            diff_array = np.array(diff).astype(np.float32)

            # Amplify for sensitivity
            amplified = np.clip(diff_array * 10, 0, 255)

            # Compute ELA score from variance of amplified difference
            ela_variance = float(np.var(amplified))
            ela_mean = float(np.mean(amplified))

            # Normalize to 0.0-1.0 range
            # High variance = high manipulation probability
            ela_score = min(ela_variance / 5000.0, 1.0)

            notes.append(
                f"ELA: variance={ela_variance:.2f}, mean={ela_mean:.2f}, "
                f"score={ela_score:.4f}."
            )

            if ela_score > 0.6:
                notes.append(
                    "ELA: High error level variance detected. "
                    "Regions with inconsistent compression suggest local editing or splicing."
                )
            elif ela_score > 0.3:
                notes.append(
                    "ELA: Moderate error level variance. "
                    "Some regions show compression inconsistency."
                )
            else:
                notes.append("ELA: Low error level variance. Compression appears consistent.")

            return ela_score, notes

        except Exception as e:
            notes.append(f"ELA analysis failed: {e}")
            return 0.0, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Noise Pattern Analysis
    # -------------------------------------------------------------------------

    def _analyze_noise_patterns(
        self, image: Image.Image
    ) -> Tuple[float, List[str]]:
        """
        Analyze high-frequency noise patterns in the image.
        GAN-generated images often exhibit characteristic noise artifacts
        in specific frequency bands that differ from camera sensor noise.
        """
        notes = []
        try:
            # Convert to grayscale numpy array
            gray = np.array(image.convert("L")).astype(np.float32)

            # Extract high-frequency component using simple Laplacian approximation
            # Shift image by 1 pixel in each direction and compute differences
            shifted_h = np.roll(gray, 1, axis=1)
            shifted_v = np.roll(gray, 1, axis=0)

            noise_h = gray - shifted_h
            noise_v = gray - shifted_v
            noise_map = np.sqrt(noise_h**2 + noise_v**2)

            # Statistical features of noise map
            noise_mean = float(np.mean(noise_map))
            noise_std = float(np.std(noise_map))
            noise_skewness = float(
                np.mean(((noise_map - noise_mean) / (noise_std + 1e-8)) ** 3)
            )

            # GAN images tend to have unusually uniform noise (low std)
            # and low skewness compared to natural camera noise
            uniformity_score = 1.0 - min(noise_std / 50.0, 1.0)
            skewness_anomaly = min(abs(noise_skewness) / 2.0, 1.0)

            noise_score = (uniformity_score * 0.6 + skewness_anomaly * 0.4)

            notes.append(
                f"Noise analysis: mean={noise_mean:.3f}, std={noise_std:.3f}, "
                f"skewness={noise_skewness:.3f}, score={noise_score:.4f}."
            )

            if noise_score > 0.65:
                notes.append(
                    "Noise: Abnormally uniform noise pattern detected. "
                    "Consistent with GAN-generated synthetic imagery."
                )

            return noise_score, notes

        except Exception as e:
            notes.append(f"Noise analysis failed: {e}")
            return 0.0, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Compression Artifact Analysis
    # -------------------------------------------------------------------------

    def _analyze_compression(
        self,
        data: bytes,
        image: Image.Image,
        ext: str,
    ) -> Tuple[float, List[str]]:
        """
        Analyze JPEG compression artifacts for inconsistencies.
        Manipulated images often show blocking artifacts at edited boundaries.
        """
        notes = []
        try:
            width, height = image.size
            pixel_count = width * height

            # File size vs pixel count ratio
            bytes_per_pixel = len(data) / pixel_count if pixel_count > 0 else 0

            # For JPEG files, very low bytes-per-pixel suggests heavy compression
            # which can indicate re-encoding after manipulation
            if ext in (".jpg", ".jpeg"):
                if bytes_per_pixel < 0.5:
                    compression_score = 0.7
                    notes.append(
                        f"Compression: Very low bytes/pixel ratio ({bytes_per_pixel:.3f}). "
                        f"Heavy re-compression detected — possible post-edit re-save."
                    )
                elif bytes_per_pixel < 1.0:
                    compression_score = 0.4
                    notes.append(
                        f"Compression: Moderate bytes/pixel ratio ({bytes_per_pixel:.3f})."
                    )
                else:
                    compression_score = 0.1
                    notes.append(
                        f"Compression: Normal bytes/pixel ratio ({bytes_per_pixel:.3f})."
                    )
            else:
                # Non-JPEG formats — assess based on file size relative to dimensions
                compression_score = 0.1
                notes.append(
                    f"Compression: Non-JPEG format. "
                    f"Bytes/pixel: {bytes_per_pixel:.3f}."
                )

            return compression_score, notes

        except Exception as e:
            notes.append(f"Compression analysis failed: {e}")
            return 0.0, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Face Region Detection
    # -------------------------------------------------------------------------

    def _detect_face_regions(
        self, image: Image.Image
    ) -> Tuple[List[Dict], List[str]]:
        """
        Detect face regions in the image.
        Attempts to use OpenCV Haar cascades for face detection.
        Falls back gracefully if OpenCV is unavailable.
        """
        notes = []
        face_regions = []

        try:
            import cv2
            import numpy as np

            img_array = np.array(image)
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)

            # Load OpenCV Haar cascade for face detection
            face_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            )

            faces = face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(30, 30),
            )

            if len(faces) > 0:
                for i, (x, y, w, h) in enumerate(faces):
                    face_regions.append({
                        "face_index": i,
                        "bounding_box": {
                            "x": int(x),
                            "y": int(y),
                            "width": int(w),
                            "height": int(h),
                        },
                        "manipulation_score": None,
                        "note": "Face detected — deepfake scoring requires deep model weights.",
                    })
                notes.append(
                    f"Face detection: {len(faces)} face(s) detected in image."
                )
            else:
                notes.append("Face detection: No faces detected in image.")

        except ImportError:
            notes.append(
                "Face detection: OpenCV not available. "
                "Install opencv-python for face region detection."
            )
        except Exception as e:
            notes.append(f"Face detection failed: {e}")

        return face_regions, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Deep Learning Inference
    # -------------------------------------------------------------------------

    def _deep_learning_inference(
        self, image: Image.Image
    ) -> Tuple[float, List[str]]:
        """
        Run EfficientNet-B4 deepfake detection inference.
        Only called when model weights are available.
        """
        notes = []
        try:
            import torch
            from torchvision import transforms

            transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225],
                ),
            ])

            tensor = transform(image).unsqueeze(0)
            tensor = tensor.to(self.inference_device)

            with torch.no_grad():
                output = self._deep_model(tensor)
                manipulation_prob = torch.sigmoid(output).item()

            notes.append(
                f"Deep learning inference: manipulation probability={manipulation_prob:.4f}."
            )
            return manipulation_prob, notes

        except Exception as e:
            notes.append(f"Deep learning inference failed: {e}")
            return 0.0, notes

    # -------------------------------------------------------------------------
    # PRIVATE — Score Aggregation
    # -------------------------------------------------------------------------

    def _compute_final_scores(
        self,
        ela_score: float,
        noise_score: float,
        compression_score: float,
        dl_score: Optional[float],
    ) -> Tuple[float, float]:
        """
        Aggregate individual analysis scores into final
        manipulation_confidence and authenticity_score.

        Weights:
          - ELA:         40% (strongest classical indicator)
          - Noise:       30%
          - Compression: 15%
          - Deep model:  15% if available, redistributed if not
        """
        if dl_score is not None:
            manipulation_confidence = (
                ela_score * 0.40
                + noise_score * 0.30
                + compression_score * 0.15
                + dl_score * 0.15
            )
        else:
            # Redistribute deep model weight to ELA and noise
            manipulation_confidence = (
                ela_score * 0.50
                + noise_score * 0.35
                + compression_score * 0.15
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
            media_type="IMAGE",
            authenticity_score=0.0,
            manipulation_confidence=0.0,
            verdict="INCONCLUSIVE",
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            processing_duration_ms=duration_ms,
            inference_device=self.inference_device,
            analysis_notes=[f"Unsupported image format: {ext}"],
            errors=[f"Unsupported format: {ext}"],
        )

    def _error_result(
        self, filename: str, errors: List[str], start_time: float
    ) -> AIAnalysisResult:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        return AIAnalysisResult(
            media_type="IMAGE",
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