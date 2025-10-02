# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:19:30 UTC
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Compliance Mapper Agent

Maps findings to compliance frameworks (NIST 800-53, ISO 27001, PCI-DSS, GDPR)
with concise control references and remediation guidance.
"""

from typing import Dict, Any
import json

from .base import BaseAIAgent


class ComplianceMapperAgent(BaseAIAgent):
    """AI agent that maps findings to compliance controls and requirements."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "ComplianceMapper", cost_tracker)

    async def map_compliance(self, ai_results: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = (
            "You are a compliance expert. Map security findings to NIST 800-53, ISO 27001, PCI-DSS, and GDPR. "
            "Provide concise control IDs and short remediation guidance. Respond ONLY with JSON."
        )
        prompt = f"""
Findings input (subset of report data): {json.dumps({
  'threat_intelligence': ai_results.get('threat_intelligence', {}),
  'vulnerability_intelligence': ai_results.get('vulnerability_intelligence', {}),
  'risk_model': ai_results.get('risk_model', {})
}, indent=2)}

Return STRICT JSON:
{{
  "frameworks": {{
    "NIST_800_53": [{{"control": "AC-2", "finding_ref": "short_ref", "remediation": "short"}}],
    "ISO_27001": [{{"control": "A.9.2.3", "finding_ref": "short_ref", "remediation": "short"}}],
    "PCI_DSS": [{{"control": "1.1.1", "finding_ref": "short_ref", "remediation": "short"}}],
    "GDPR": [{{"article": "32", "finding_ref": "short_ref", "remediation": "short"}}]
  }},
  "summary": "2-3 sentence compliance impact summary"
}}
"""
        return await self._query_ai(prompt, system_prompt)


