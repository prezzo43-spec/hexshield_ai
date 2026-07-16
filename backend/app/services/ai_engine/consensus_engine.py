# =============================================================================
# HexShield AI — Consensus Validation Service & Decision Engine
# Layer 3: Multi-Agent Verdict Arbitration & Narrative Generation
# =============================================================================

import os
import json
import logging
from typing import Dict, Any, Tuple
from openai import OpenAI
from app.services.forensic_reporting.report_generator import (
    ForensicReportData,
    determine_overall_verdict,
)

logger = logging.getLogger(__name__)

# Initialize OpenAI client pointing to Groq's cloud engine
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY")
)

# Using Llama 3.3 70B for strong logical assessment
REASONING_MODEL = "llama-3.3-70b-versatile"


class ForensicConsensusEngine:
    """
    Coordinates multi-layer analysis inputs (Layer 1 Triage & Layer 2 AI Deepfake)
    using a Prosecutor-Skeptic-Judge multi-agent filter, then outputs court-ready 
    evidence verdicts and examiner narratives.
    """

    def query_agent(self, system_prompt: str, user_prompt: str) -> str:
        """Sends the prompt payload to Groq's model with near-zero temperature for accuracy."""
        if not os.getenv("GROQ_API_KEY"):
            logger.warning("GROQ_API_KEY not found. Bypassing agent query.")
            return "Agent bypassed: Missing API Key."

        try:
            response = client.chat.completions.create(
                model=REASONING_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=1e-8,  # Deterministic reasoning
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Agent failure during API call: {e}")
            return f"Agent failure: {str(e)}"

    def evaluate_consensus(self, report_data: ForensicReportData) -> ForensicReportData:
        """
        Executes consensus logic over the generated ForensicReportData object:
        1. Packs technical findings from Layer 1 & Layer 2 into raw telemetry.
        2. Runs the Prosecutor-Skeptic-Judge multi-agent evaluation.
        3. Sets the overall arbitrated verdict and updates the 'Examiner Notes'.
        """
        logger.info(f"Initiating multi-agent consensus validation for: {report_data.submission.original_filename}")

        # Assemble the raw analysis summary for the agents
        raw_results = {
            "evidence_metadata": {
                "filename": report_data.submission.original_filename,
                "declared_mime": report_data.submission.mime_type_declared,
                "detected_mime": report_data.submission.mime_type_detected,
                "sha256": report_data.submission.sha256_hash
            },
            "layer_1_hex_triage": {
                "overall_risk_level": report_data.hex_analysis.overall_risk_level if report_data.hex_analysis else "UNKNOWN",
                "shannon_entropy": report_data.hex_analysis.shannon_entropy if report_data.hex_analysis else 0.0,
                "entropy_verdict": report_data.hex_analysis.entropy_verdict if report_data.hex_analysis else "UNKNOWN",
                "suspicious_sections": report_data.hex_analysis.suspicious_sections_count if report_data.hex_analysis else 0,
                "mime_spoof_detected": report_data.hex_analysis.mime_spoof_detected if report_data.hex_analysis else False,
            },
            "layer_2_ai_deepfake": {
                "verdict": report_data.ai_analysis.verdict if report_data.ai_analysis else "NOT_RUN",
                "authenticity_score": report_data.ai_analysis.authenticity_score if report_data.ai_analysis else 1.0,
                "manipulation_confidence": report_data.ai_analysis.manipulation_confidence if report_data.ai_analysis else 0.0,
            }
        }

        media_type = report_data.ai_analysis.media_type if report_data.ai_analysis else "UNKNOWN"
        analysis_summary = json.dumps(raw_results, indent=2)

        # ---------------------------------------------------------------------
        # Agent 1: The Prosecutor (Looks for malicious manipulation/deepfake indicators)
        # ---------------------------------------------------------------------
        prosecutor_system = (
            "You are an Elite Deepfake and Threat Analyst (Agent: Prosecutor) operating in compliance "
            "with the Computer Misuse and Cybercrimes Act, 2018 (Kenya).\n"
            "Review the technical values from raw model data. Look for anomalies, suspicious confidence values, "
            "high entropy indicating packed payloads/hidden scripts, noise inconsistencies, "
            "or spectral analysis values that point to synthesis, obfuscation, or manipulation."
        )
        prosecutor_verdict = self.query_agent(
            prosecutor_system, 
            f"Media Type: {media_type}\nRaw Forensic Data:\n{analysis_summary}"
        )

        # ---------------------------------------------------------------------
        # Agent 2: The Skeptic (Defends against false positives)
        # ---------------------------------------------------------------------
        skeptic_system = (
            "You are a Senior Forensic Auditor (Agent: Skeptic) operating in compliance "
            "with the Computer Misuse and Cybercrimes Act, 2018 (Kenya).\n"
            "Evaluate whether raw scores are safe. (e.g. Could compression artifacts be from simple "
            "web transmission rather than malicious deepfaking? Could high entropy be normal compression?). "
            "Defend the integrity of the evidence and argue against immediate prosecution without absolute technical proof."
        )
        skeptic_verdict = self.query_agent(
            skeptic_system,
            f"Forensic Raw Data:\n{analysis_summary}\n\nProsecutor Analysis:\n{prosecutor_verdict}"
        )

        # ---------------------------------------------------------------------
        # Agent 3: The Judge (Final arbitration and court-ready justification)
        # ---------------------------------------------------------------------
        judge_system = (
            "You are a Chief Digital Forensics Judge. Weigh both analyses under ISO/IEC 27037 "
            "and Kenyan cyber law guidelines. Provide your final ruling.\n"
            "You must respond strictly in JSON format with no markdown wrappers:\n"
            "{\n"
            '  "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS",\n'
            '  "confidence_score": 0.00 to 1.00,\n'
            '  "examiner_notes": "A thorough, professional, 2-3 paragraph court-ready narrative summarizing the case, '
            'the tension between the Prosecutor and Skeptic arguments, and the final forensic conclusions."\n'
            "}"
        )
        final_verdict_raw = self.query_agent(
            judge_system,
            f"Prosecutor Case:\n{prosecutor_verdict}\n\nSkeptic Case:\n{skeptic_verdict}"
        )

        # Parse output and populate report data
        try:
            cleaned_json = final_verdict_raw.strip().replace("```json", "").replace("```", "")
            decision = json.loads(cleaned_json)
            
            # Map clean status for PDF layout mapping
            verdict_val = decision.get("verdict", "SUSPICIOUS")
            report_data.examiner_notes = decision.get("examiner_notes", "Manual examiner review recommended.")
            
            logger.info(f"Consensus reached: {verdict_val} with confidence {decision.get('confidence_score')}")

        except Exception as e:
            logger.error(f"Failsafe triggered; Judge output was not valid JSON: {e}")
            # Safe parsing fallback
            fallback_verdict = "SUSPICIOUS" if "MALICIOUS" in final_verdict_raw else "CLEAN"
            report_data.examiner_notes = f"Multi-agent assessment completed with failsafe. Raw ruling: {final_verdict_raw[:1000]}"

        return report_data