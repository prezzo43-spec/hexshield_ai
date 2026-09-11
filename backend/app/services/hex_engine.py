import math
from pathlib import Path
import time

class EntropyResult:
    def __init__(self, entropy_value: float, elevated_threshold: float, verdict: str, byte_distribution: dict):
        self.entropy_value = entropy_value
        self.elevated_threshold = elevated_threshold
        self.verdict = verdict
        self.byte_distribution = byte_distribution

class MatchedSignature:
    def __init__(self, format_name: str, threat_relevance: str):
        self.format_name = format_name
        self.threat_relevance = threat_relevance

class HexAnalysisOutput:
    def __init__(self, entropy_result, magic_bytes_hex: str, mime_spoof_detected: bool, 
                 mime_spoof_details: str, file_header_valid: bool, header_anomalies_detected: bool, 
                 header_anomaly_details: str, suspicious_sections: list, overall_risk_level: str, 
                 risk_summary: str, mime_type_detected: str, matched_signature, 
                 analysis_duration_ms: float, engine_version: str = "1.0.0"):
        self.entropy_result = entropy_result
        self.magic_bytes_hex = magic_bytes_hex
        self.mime_spoof_detected = mime_spoof_detected
        self.mime_spoof_details = mime_spoof_details
        self.file_header_valid = file_header_valid
        self.header_anomalies_detected = header_anomalies_detected
        self.header_anomaly_details = header_anomaly_details
        self.suspicious_sections = suspicious_sections
        self.overall_risk_level = overall_risk_level
        self.risk_summary = risk_summary
        self.mime_type_detected = mime_type_detected
        self.matched_signature = matched_signature
        self.analysis_duration_ms = analysis_duration_ms
        self.engine_version = engine_version

class HexTriageEngine:
    def __init__(self):
        # Fallback database signatures if DB table isn't populated
        self.signatures = {
            b"\x89PNG\r\n\x1a\n": ("image/png", "PNG Image"),
            b"\xff\xd8\xff": ("image/jpeg", "JPEG Image"),
            b"%PDF": ("application/pdf", "PDF Document"),
            b"RIFF": ("audio/wav", "WAV Audio File"),  # Simplified validation check
            b"\x00\x00\x00\x18ftyp": ("video/mp4", "MP4 Video Container")
        }

    def calculate_entropy(self, data: bytes) -> EntropyResult:
        if not data:
            return EntropyResult(0.0, 7.2, "LOW", {})
        
        # Count frequency of each byte value
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
            
        entropy = 0.0
        total_len = len(data)
        byte_distribution = {}
        
        for i, count in enumerate(counts):
            if count == 0:
                continue
            p = count / total_len
            entropy -= p * math.log2(p)
            if count > (total_len * 0.01):  # Keep track of structural byte visibility > 1%
                byte_distribution[f"0x{i:02x}"] = round(p, 4)

        threshold = 7.2
        verdict = "SUSPICIOUS_HIGH_ENTROPY" if entropy > threshold else "NORMAL"
        return EntropyResult(entropy, threshold, verdict, byte_distribution)

    def analyze_file(self, file_path: str, declared_mime_type: str) -> HexAnalysisOutput:
        start_time = time.time()
        path = Path(file_path)
        file_bytes = path.read_bytes()
        
        # Extract leading magic signatures
        magic_bytes_hex = file_bytes[:8].hex().upper()
        
        # Evaluate matched signatures
        detected_mime = "application/octet-stream"
        format_name = "Unknown"
        file_header_valid = False
        
        for signature, (mime, fmt) in self.signatures.items():
            if file_bytes.startswith(signature):
                detected_mime = mime
                format_name = fmt
                file_header_valid = True
                break

        entropy_res = self.calculate_entropy(file_bytes)
        
        # Mime Spoof Identification
        mime_spoof_detected = False
        mime_spoof_details = ""
        if declared_mime_type and detected_mime != "application/octet-stream":
            if declared_mime_type.lower().strip() != detected_mime:
                mime_spoof_detected = True
                mime_spoof_details = f"Header maps to {detected_mime} while payload metadata declares {declared_mime_type}"

        # Anomaly checking
        suspicious_sections = []
        header_anomalies_detected = False
        header_anomaly_details = ""
        
        if mime_spoof_detected:
            suspicious_sections.append({"type": "MIME_SPOOF", "offset": 0, "severity": "HIGH"})
        if entropy_res.verdict == "SUSPICIOUS_HIGH_ENTROPY":
            suspicious_sections.append({"type": "ENCRYPTED_EMBEDDED_PACKET", "offset": "Variable", "severity": "MEDIUM"})
            
        risk_level = "LOW"
        if len(suspicious_sections) > 0:
            risk_level = "HIGH" if mime_spoof_detected else "MEDIUM"

        duration = (time.time() - start_time) * 1000
        
        return HexAnalysisOutput(
            entropy_result=entropy_res,
            magic_bytes_hex=magic_bytes_hex,
            mime_spoof_detected=mime_spoof_detected,
            mime_spoof_details=mime_spoof_details,
            file_header_valid=file_header_valid,
            header_anomalies_detected=header_anomalies_detected,
            header_anomaly_details=header_anomaly_details,
            suspicious_sections=suspicious_sections,
            overall_risk_level=risk_level,
            risk_summary=f"Analysis complete. Found {len(suspicious_sections)} structural markers.",
            mime_type_detected=detected_mime,
            matched_signature=MatchedSignature(format_name, "MALICIOUS_CONTAINER_ALTERATION" if mime_spoof_detected else "STANDARD_VALID"),
            analysis_duration_ms=round(duration, 2)
        )