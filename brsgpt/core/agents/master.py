from typing import Dict, Any
from .base import BaseAIAgent


class MasterDecisionAgent(BaseAIAgent):
    """AI agent for strategic planning and decision making."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "MasterDecision", cost_tracker)

    async def analyze_target_and_create_strategy(self, target: str) -> Dict[str, Any]:
        system_prompt = """You are a senior cybersecurity strategist. Analyze the target and create an optimal security assessment strategy. Always respond with valid JSON format only."""
        prompt = f"""
Analyze target: {target}

Create a comprehensive cybersecurity assessment strategy including:
1. Target classification and risk profile
2. Optimal reconnaissance approach
3. Vulnerability scanning strategy
4. Resource allocation and timing
5. Success metrics and adaptation triggers

Respond in JSON format:
{{
    "target_classification": "web_app|api|infrastructure|unknown",
    "risk_profile": "low|medium|high|critical",
    "recon_strategy": {{
        "subdomain_priority": ["high_value_patterns"],
        "port_scan_focus": [port_numbers],
        "dns_analysis_depth": "basic|standard|comprehensive",
        "technology_detection_level": "surface|deep|comprehensive"
    }},
    "vulnerability_strategy": {{
        "xss_contexts": ["context_types_to_prioritize"],
        "parameter_discovery": "basic|aggressive|comprehensive",
        "payload_selection": "targeted|broad|exhaustive",
        "waf_evasion_level": "none|basic|advanced"
    }},
    "resource_allocation": {{
        "time_budget_minutes": number,
        "concurrent_operations": number,
        "priority_order": ["phase_names"]
    }},
    "adaptation_triggers": {{
        "findings_threshold": number,
        "time_limit_minutes": number,
        "strategy_pivot_conditions": ["conditions"]
    }}
}}
"""
        return await self._query_ai(prompt, system_prompt)
