# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:18:00 UTC
# Status: Created
# Telegram: https://t.me/easyprotech

"""
AI Correlation Agent

Correlates reconnaissance, vulnerability findings, active test results,
and threat intelligence to produce high-signal insights and attack chains.
"""

from typing import Dict, Any
import json

from .base import BaseAIAgent


class CorrelationAgent(BaseAIAgent):
    """AI agent for cross-domain correlation and insight generation."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "Correlation", cost_tracker)

    async def correlate(self,
                        recon_results: Dict[str, Any],
                        vuln_results: Dict[str, Any],
                        active_test_analysis: Dict[str, Any],
                        threat_intel: Dict[str, Any],
                        risk_model: Dict[str, Any] | None) -> Dict[str, Any]:
        system_prompt = (
            "You are a senior security analyst specializing in correlation. "
            "Link signals across recon, vulnerabilities, active test results, and threat intel. "
            "Focus on API key → storage (S3/MinIO) exposure, default creds → management UI compromise, \n"
            "JWT/OIDC misconfig → auth bypass, and DevOps endpoints → sensitive data. Respond ONLY with JSON."
        )
        prompt = f"""
Recon: {json.dumps(recon_results, indent=2)}
Vulns: {json.dumps(vuln_results, indent=2)}
ActiveTestAnalysis: {json.dumps(active_test_analysis, indent=2)}
ThreatIntel: {json.dumps(threat_intel, indent=2)}
RiskModel: {json.dumps(risk_model or {}, indent=2)}

Return STRICT JSON:
{{
  "insights": [
    {{
      "title": "short_title",
      "severity": "low|medium|high|critical",
      "evidence": "1-2 sentence correlation rationale",
      "linked_findings": ["ids_or_short_refs"],
      "attack_chain": ["step1","step2","step3"],
      "remediation": "short action"
    }}
  ],
  "highlights": ["short_highlights"],
  "notes": ["short_notes"]
}}
"""
        return await self._query_ai(prompt, system_prompt)


