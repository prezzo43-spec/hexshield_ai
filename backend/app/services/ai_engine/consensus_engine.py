# =============================================================================
# HexShield AI — Consensus Validation Service
# =============================================================================

import os
import json
from typing import Dict, Any
from openai import OpenAI

# Initialize OpenAI client pointing to Groq's cloud engine
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY")
)

# Using Llama 3.3 70B for strong logical assessment
REASONING_MODEL = "llama-3.3-70b-versatile"

class ForensicConsensusEngine:
    def query_agent(self, system_prompt: str, user_prompt: str) -> str:
        """Sends the prompt payload to Groq's model with zero temperature for accuracy."""
        try:
            response = client.chat.completions.create(
                model=REASONING_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=1e-8, # Deterministic reasoning
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Agent failure: {str(e)}"

    def evaluate_analysis(self, media_type: str, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes raw scores from your HuggingFace/heuristic models and runs 
        them through the Prosecutor/Skeptic multi-agent filter to verify.
        """
        analysis_summary = json.dumps(raw_results, indent=2)

        # Agent 1: The Prosecutor (Looks for malicious manipulation/deepfake indicators)
        prosecutor_system = (
            "You are an Elite Deepfake Analyst (Agent: Prosecutor).\n"
            "Review the technical values from raw model data. Look for anomalies, suspicious confidence values, "
            "noise inconsistencies, or spectral analysis values that point to synthesis or manipulation."
        )
        prosecutor_verdict = self.query_agent(
            prosecutor_system, 
            f"Media Type: {media_type}\nRaw Forensic Data:\n{analysis_summary}"
        )

        # Agent 2: The Skeptic (Defends against false positives)
        skeptic_system = (
            "You are a Senior Forensic Auditor (Agent: Skeptic).\n"
            "Evaluate whether raw scores are safe. (e.g. Could compression artifacts be from simple "
            "web transmission rather than malicious deepfaking?). Argue against immediate prosecution."
        )
        skeptic_verdict = self.query_agent(
            skeptic_system,
            f"Forensic Raw Data:\n{analysis_summary}\n\nProsecutor Analysis:\n{prosecutor_verdict}"
        )

        # Agent 3: The Judge
        judge_system = (
            "You are a Chief Digital Forensics Judge. Weigh both analyses and provide a final verdict.\n"
            "Respond ONLY in a JSON format with no markdown wrappers:\n"
            "{\n"
            '  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",\n'
            '  "confidence_score": 0.00 to 1.00,\n'
            '  "justification": "Why this decision was made."\n'
            "}"
        )
        final_verdict_raw = self.query_agent(
            judge_system,
            f"Prosecutor Case:\n{prosecutor_verdict}\n\nSkeptic Case:\n{skeptic_verdict}"
        )

        try:
            cleaned_json = final_verdict_raw.strip().replace("```json", "").replace("```", "")
            return json.loads(cleaned_json)
        except Exception:
            # Safe parsing fallback
            return {
                "verdict": "SUSPICIOUS" if "MALICIOUS" in final_verdict_raw else "SAFE",
                "confidence_score": 0.85,
                "justification": f"Failsafe triggered. Summary: {final_verdict_raw[:150]}"
            }