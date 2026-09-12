# =============================================================================
# HexShield AI — Forensic Consensus Engine
# Multi-Agent Verdict Arbitration using Nebius or Groq LLM
#
# Three-agent system:
#   Agent 1 — Prosecutor: finds malicious indicators
#   Agent 2 — Skeptic: defends against false positives
#   Agent 3 — Judge: final arbitration and court-ready justification
#
# Falls back gracefully when no supported provider is configured.
# =============================================================================

import json
import logging
from typing import Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)


class ForensicConsensusEngine:
    """
    Multi-agent forensic consensus system.
    Validates and cross-checks AI deepfake detection results
    using a Prosecutor-Skeptic-Judge pipeline via Nebius or Groq LLM.
    """

    def __init__(self):
        self.api_key = ""
        self.base_url = ""
        self.model = ""
        self.provider = ""
        self.client = None
        if settings.NEBIUS_API_KEY:
            self.api_key = settings.NEBIUS_API_KEY
            self.base_url = settings.NEBIUS_BASE_URL
            self.model = settings.NEBIUS_MODEL
            self.provider = "Nebius"
        elif settings.GROQ_API_KEY:
            self.api_key = settings.GROQ_API_KEY
            self.base_url = "https://api.groq.com/openai/v1"
            self.model = "llama-3.3-70b-versatile"
            self.provider = "Groq"

        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    base_url=self.base_url,
                    api_key=self.api_key,
                )
                logger.info(
                    "ForensicConsensusEngine: %s client initialized with model %s.",
                    self.provider,
                    self.model,
                )
            except ImportError:
                logger.warning("openai package not installed. Consensus engine disabled.")
        else:
            logger.info(
                "No NEBIUS_API_KEY or GROQ_API_KEY set. "
                "Consensus engine will use fallback mode."
            )

    def evaluate_consensus(
        self,
        media_type: str,
        raw_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run multi-agent consensus evaluation on raw AI analysis results.

        Args:
            media_type  : IMAGE | VIDEO | AUDIO
            raw_results : Raw dict from HuggingFaceDeepfakeAnalyzer

        Returns:
            Dict with keys: verdict, confidence_score, justification
        """
        # If no Groq client available, return passthrough result
        if not self.client:
            return self._fallback_result(raw_results)

        analysis_summary = json.dumps({
            "media_type": media_type,
            "verdict_from_hf": raw_results.get("verdict", "INCONCLUSIVE"),
            "authenticity_score": raw_results.get("authenticity_score", 0.0),
            "manipulation_confidence": raw_results.get("manipulation_confidence", 0.0),
            "analysis_notes": raw_results.get("analysis_notes", []),
        }, indent=2)

        # Agent 1 — Prosecutor
        prosecutor_verdict = self._query_agent(
            system_prompt=(
                "You are an Elite Deepfake and Threat Analyst (Prosecutor) "
                "operating under the Computer Misuse and Cybercrimes Act, 2018 (Kenya) "
                "and ISO/IEC 27037 digital evidence standards. "
                "Review the technical values. Find anomalies, suspicious scores, "
                "noise inconsistencies, or spectral values pointing to synthesis or manipulation. "
                "Be concise — 3 sentences maximum."
            ),
            user_prompt=f"Media Type: {media_type}\nRaw Forensic Data:\n{analysis_summary}",
        )

        # Agent 2 — Skeptic
        skeptic_verdict = self._query_agent(
            system_prompt=(
                "You are a Senior Forensic Auditor (Skeptic) "
                "operating under the Computer Misuse and Cybercrimes Act, 2018 (Kenya). "
                "Evaluate whether the raw scores could be explained by innocent causes "
                "(e.g. normal compression artifacts, web transmission noise). "
                "Defend against false positives. Be concise — 3 sentences maximum."
            ),
            user_prompt=(
                f"Forensic Data:\n{analysis_summary}\n\n"
                f"Prosecutor Analysis:\n{prosecutor_verdict}"
            ),
        )

        # Agent 3 — Judge (final ruling)
        judge_response = self._query_agent(
            system_prompt=(
                "You are a Chief Digital Forensics Judge. "
                "Weigh both analyses under ISO/IEC 27037 and Kenyan cyber law. "
                "Respond ONLY in this exact JSON format with no markdown:\n"
                "{\n"
                '  "verdict": "AUTHENTIC" or "SUSPICIOUS" or "MANIPULATED" or "INCONCLUSIVE",\n'
                '  "confidence_score": 0.00,\n'
                '  "justification": "One professional paragraph summarizing findings."\n'
                "}"
            ),
            user_prompt=(
                f"Prosecutor:\n{prosecutor_verdict}\n\n"
                f"Skeptic:\n{skeptic_verdict}"
            ),
        )

        # Parse judge response
        try:
            cleaned = judge_response.strip().replace("```json", "").replace("```", "").strip()
            decision = json.loads(cleaned)
            verdict = decision.get("verdict", "INCONCLUSIVE")
            confidence = float(decision.get("confidence_score", 0.5))
            justification = decision.get("justification", "Multi-agent consensus completed.")

            logger.info(f"Consensus verdict: {verdict} (confidence: {confidence:.2f})")

            return {
                "verdict": verdict,
                "confidence_score": confidence,
                "justification": justification,
                "prosecutor_finding": prosecutor_verdict,
                "skeptic_finding": skeptic_verdict,
            }

        except Exception as e:
            logger.error(f"Judge JSON parse failed: {e}. Raw: {judge_response[:200]}")
            return self._fallback_result(raw_results)

    def _query_agent(self, system_prompt: str, user_prompt: str) -> str:
        """Send a reasoning prompt to the configured OpenAI-compatible provider."""
        try:
            response = self.client.chat.completions.create(
            model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=512,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"Agent query failed: {e}")
            return f"Agent unavailable: {str(e)}"

    def _fallback_result(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return passthrough result when the reasoning provider is unavailable.
        Uses the HF model verdict directly.
        """
        verdict = raw_results.get("verdict", "INCONCLUSIVE")
        confidence = raw_results.get("manipulation_confidence", 0.0)
        return {
            "verdict": verdict,
            "confidence_score": confidence,
            "justification": (
                "Consensus engine unavailable. "
                "Verdict based on primary Hugging Face model analysis. "
                f"HF verdict: {verdict}, manipulation confidence: {confidence:.2f}."
            ),
        }