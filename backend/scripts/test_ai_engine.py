import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.ai_engine import AIDeepfakeEngine, detect_media_type

engine = AIDeepfakeEngine()
print("AI Engine loaded successfully")
print(f"Device: {engine.inference_device}")
print(f"Image type detection: {detect_media_type('photo.jpg')}")
print(f"Video type detection: {detect_media_type('clip.mp4')}")
print(f"Audio type detection: {detect_media_type('voice.wav')}")
print(f"Unknown type detection: {detect_media_type('document.xyz')}")