import json
from typing import Dict, Any
from .base import BaseAIAgent


class ThreatIntelligenceAgent(BaseAIAgent):
    """AI agent for threat intelligence and correlation."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "ThreatIntelligence", cost_tracker)

    async def analyze_threats(self, recon_results: Dict[str, Any], vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """You are a threat intelligence analyst. Correlate security findings and assess threat landscape. Respond in JSON format."""
        prompt = f"""
Reconnaissance data: {json.dumps(recon_results, indent=2)}
Vulnerability data: {json.dumps(vuln_results, indent=2)}

Provide comprehensive threat intelligence:
{{
    "threat_assessment": {{
        "overall_risk_score": number_1_to_10,
        "attack_surface_rating": "minimal|moderate|extensive|critical",
        "exploitability_rating": "low|medium|high|critical"
    }},
    "threat_vectors": [
        {{
            "vector_type": "description",
            "likelihood": "low|medium|high",
            "impact": "low|medium|high|critical",
            "attack_complexity": "low|medium|high"
        }}
    ],
    "correlation_insights": {{
        "technology_risks": ["tech_specific_vulnerabilities"],
        "configuration_issues": ["misconfigurations_found"],
        "network_exposure": "exposure_assessment"
    }},
    "immediate_concerns": ["urgent_security_issues"],
    "strategic_recommendations": ["long_term_security_improvements"]
}}
"""
        return await self._query_ai(prompt, system_prompt)
