import json
from typing import Dict, List, Any
from .base import BaseAIAgent


class VulnerabilityHuntingAgent(BaseAIAgent):
    """AI agent for intelligent vulnerability discovery."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "VulnerabilityHunting", cost_tracker)

    async def hunt_vulnerabilities(self, target: str, recon_results: Dict[str, Any], master_strategy: Dict[str, Any]) -> Dict[str, Any]:
        from brsgpt.xss.vulnerability_scanner import VulnerabilityScanner
        from brsgpt.utils.http_client import HttpClient
        try:
            hunt_strategy = await self._create_hunt_strategy(target, recon_results, master_strategy)
            # Lightweight HTTP client for vuln scan
            http_client = HttpClient(rate_limit=12.0, timeout=5)
            # Apply safer defaults for hunting phase based on profile
            xss_settings = {
                'max_payloads': min(100, int(self.settings.get('xss', {}).get('max_payloads', 200))),
                'request_timeout': 5,
                'max_urls': min(3, int(self.settings.get('xss', {}).get('max_urls', 5))),
                'rate_limit': 12.0,
            }
            vuln_scanner = VulnerabilityScanner(http_client, xss_settings)
            ai_targets = hunt_strategy.get('priority_targets', [target])
            all_vulnerabilities: List[Dict[str, Any]] = []
            # Only run if recon indicates web surface
            has_web = any(p.get('port') in [80, 443, 8080, 8443, 3000] for p in recon_results.get('open_ports', []))
            if has_web:
                import asyncio
                sem = asyncio.Semaphore(2)
                async def _bounded_scan(url: str):
                    async with sem:
                        try:
                            return await asyncio.wait_for(vuln_scanner.scan_target(url), timeout=60.0)
                        except Exception:
                            return []
                tasks = []
                for scan_target in ai_targets[:3]:
                    # normalize to https:// if missing scheme
                    if not (scan_target.startswith('http://') or scan_target.startswith('https://')):
                        scan_target = f"https://{scan_target}"
                    tasks.append(_bounded_scan(scan_target))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        all_vulnerabilities.extend(r)
            prioritized_vulns = await self._prioritize_vulnerabilities(all_vulnerabilities)
            return {
                'vulnerabilities': prioritized_vulns,
                'hunt_strategy': hunt_strategy,
                'targets_scanned': ai_targets,
                'ai_analysis': await self._analyze_vulnerability_patterns(prioritized_vulns)
            }
        except Exception as e:
            return {"error": str(e), "agent": self.agent_name}

    async def _create_hunt_strategy(self, target: str, recon_results: Dict[str, Any], master_strategy: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """You are a vulnerability researcher. Create an optimal vulnerability hunting strategy based on target intelligence. Respond in JSON format."""
        prompt = f"""
Target: {target}
Reconnaissance results: {json.dumps(recon_results, indent=2)}
Master strategy: {json.dumps(master_strategy, indent=2)}

Create vulnerability hunting strategy:
{{
    "priority_targets": ["target_urls_to_scan"],
    "vulnerability_focus": ["xss", "injection", "authentication"],
    "scanning_approach": "targeted|comprehensive|stealth",
    "parameter_discovery": {{
        "methods": ["reflection", "error_based", "blind"],
        "depth_level": "surface|moderate|deep"
    }},
    "payload_strategy": {{
        "context_priority": ["html", "javascript", "attribute"],
        "evasion_techniques": ["encoding", "obfuscation", "polyglot"],
        "success_threshold": number_0_to_1
    }}
}}
"""
        return await self._query_ai(prompt, system_prompt)

    async def _prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not vulnerabilities:
            return []
        system_prompt = """You are a vulnerability analyst. Prioritize vulnerabilities by exploitability and business impact. Respond in JSON format."""
        prompt = f"""
Vulnerabilities found: {json.dumps(vulnerabilities[:10], indent=2)}

Prioritize and enhance each vulnerability with:
1. Exploitability score (1-10)
2. Business impact assessment
3. Remediation complexity
4. Attack chain potential

Return prioritized list as JSON array of vulnerability objects with added AI analysis.
"""
        result = await self._query_ai(prompt, system_prompt)
        return result.get('prioritized_vulnerabilities', vulnerabilities)

    async def _analyze_vulnerability_patterns(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        system_prompt = """You are a security researcher analyzing vulnerability patterns. Respond in JSON format."""
        prompt = f"""
Analyze vulnerability patterns: {json.dumps(vulnerabilities[:5], indent=2)}

Provide pattern analysis:
{{
    "pattern_analysis": "description_of_patterns_found",
    "attack_vectors": ["primary_attack_methods"],
    "systemic_issues": ["underlying_security_problems"],
    "exploitation_chains": ["multi_step_attack_possibilities"],
    "remediation_strategy": "strategic_fix_approach"
}}
"""
        return await self._query_ai(prompt, system_prompt)
