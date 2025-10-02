import json
from typing import Dict, Any
from .base import BaseAIAgent


class ReconStrategyAgent(BaseAIAgent):
    """AI agent for intelligent reconnaissance strategy."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "ReconStrategy", cost_tracker)

    async def execute_intelligent_recon(self, target: str, master_strategy: Dict[str, Any]) -> Dict[str, Any]:
        from ...recon.subdomain_enum import SubdomainEnumerator
        from ...recon.dns_analyzer import DNSAnalyzer
        from ...recon.port_scanner import PortScanner
        from ...recon.tech_detector import TechnologyDetector
        from ...utils.http_client import HttpClient

        recon_results = {'subdomains': [], 'dns_analysis': {}, 'open_ports': [], 'technologies': {}, 'ai_insights': []}
        try:
            http_client = HttpClient(rate_limit=20.0, timeout=5)
            tasks = []
            subdomain_enum = SubdomainEnumerator(http_client, {'max_subdomains': 10, 'dns_timeout': 3, 'concurrent_requests': 16})
            import asyncio
            tasks.append(asyncio.create_task(asyncio.wait_for(subdomain_enum.enumerate(target), timeout=15.0)))
            dns_analyzer = DNSAnalyzer({'dns_timeout': 3})
            tasks.append(asyncio.create_task(asyncio.wait_for(dns_analyzer.analyze(target), timeout=10.0)))
            port_scanner = PortScanner({'port_scan_timeout': 5, 'concurrent_requests': 20})
            tasks.append(asyncio.create_task(asyncio.wait_for(port_scanner.scan(target), timeout=15.0)))
            tech_detector = TechnologyDetector(http_client, {'request_timeout': 5})
            tasks.append(asyncio.create_task(asyncio.wait_for(tech_detector.detect(f"https://{target}"), timeout=10.0)))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            if not isinstance(results[0], Exception):
                recon_results['subdomains'] = results[0]
            if not isinstance(results[1], Exception):
                recon_results['dns_analysis'] = results[1]
            if not isinstance(results[2], Exception):
                recon_results['open_ports'] = results[2]
            if not isinstance(results[3], Exception):
                recon_results['technologies'] = results[3]
            ai_insights = await self._analyze_recon_results(recon_results)
            recon_results['ai_insights'] = ai_insights
            return recon_results
        except Exception as e:
            return {"error": str(e), "agent": self.agent_name}

    async def _analyze_recon_results(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """You are a cybersecurity reconnaissance analyst. Analyze the recon data and provide strategic insights in JSON format."""
        prompt = f"""
Analyze reconnaissance results:
{json.dumps(recon_data, indent=2)}

Provide strategic insights:
1. Attack surface assessment
2. High-value targets identification
3. Security posture evaluation
4. Next phase recommendations

Respond in JSON format:
{{
    "attack_surface_score": number_1_to_10,
    "high_value_targets": ["target_list"],
    "security_posture": "weak|moderate|strong",
    "critical_findings": ["finding_list"],
    "next_phase_recommendations": {{
        "vulnerability_focus": ["areas_to_focus"],
        "scan_intensity": "light|moderate|intensive",
        "time_allocation": "minutes_recommended"
    }}
}}
"""
        return await self._query_ai(prompt, system_prompt)
