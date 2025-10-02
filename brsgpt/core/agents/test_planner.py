# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:36:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
AI Test Planner Agent

Generates safe, budgeted test plans to actively probe targets using
non-destructive HTTP checks. The planner focuses on maximizing security
signal under strict time and request budgets and returns a structured
JSON plan that the orchestrator can execute deterministically.
"""

from typing import Dict, Any
import json

from .base import BaseAIAgent


class TestPlannerAgent(BaseAIAgent):
    """AI agent that plans safe active tests with strict budgets."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "TestPlanner", cost_tracker)

    async def plan_tests(self, target: str, recon_results: Dict[str, Any], master_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produce a safe, strictly budgeted test plan focusing on high-signal checks.

        The plan must only include the following actions:
        - http_get: {"action": "http_get", "url": "https://host/path", "headers": {}}
        - http_post: {"action": "http_post", "url": "https://host/path", "headers": {}, "data": {}}
        - graphql_introspection: {"action": "graphql_introspection", "url": "https://host/graphql", "headers": {}, "body": {"query": "{ __schema { types { name } } }"}}

        Optional expectations per step to guide result interpretation:
        - expect.status_any: [200, 301, 302]
        - expect.header_contains: {"Header-Name": "substring"}
        - expect.body_regex: "regex"
        - expect.body_contains: "substring"
        """
        system_prompt = (
            "You are an elite penetration tester acting as a PLANNER. "
            "Generate a SAFE, NON-DESTRUCTIVE test plan using ONLY http_get/http_post actions. "
            "Target common misconfigs (GraphQL introspection, CORS wildcard+credentials, Docker Registry /v2/, Vault /v1/sys/health, "
            "RabbitMQ /api/overview, Prometheus /-/ready /metrics, OIDC /.well-known/openid-configuration). "
            "Respect strict budgets and avoid destructive or intrusive actions. Respond ONLY with JSON."
        )

        prompt = f"""
Target: {target}
Recon: {json.dumps(recon_results, indent=2)}
Master strategy: {json.dumps(master_strategy, indent=2)}

Return STRICT JSON with this structure:
{{
  "budget": {{
    "max_iterations": 3,
    "max_http_requests": 10,
    "time_limit_seconds": 60
  }},
  "iterations": [
    {{
      "iteration": 1,
      "goals": ["short_goal"],
      "steps": [
        {{"action": "http_get", "url": "https://example.com/.well-known/openid-configuration"}},
        {{"action": "http_get", "url": "https://example.com/graphql"}},
        {{"action": "http_get", "url": "https://example.com/v2/"}}
      ]
    }}
  ]
}}
"""
        return await self._query_ai(prompt, system_prompt)

    async def evaluate_results(self, target: str, plan: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Have AI interpret raw step results to produce concise findings."""
        system_prompt = (
            "You are a penetration testing expert acting as an ANALYST. "
            "Interpret HTTP step results to identify misconfigurations and exposures. "
            "Be conservative, avoid false positives, and output ONLY JSON."
        )
        prompt = f"""
Target: {target}
Plan: {json.dumps(plan, indent=2)}
Raw results: {json.dumps(results, indent=2)}

Return STRICT JSON:
{{
  "findings": [
    {{
      "title": "short_title",
      "severity": "low|medium|high|critical",
      "evidence": "1-2 sentence evidence summary",
      "references": ["optional_links_or_docs"],
      "poc": "optional single curl/httpie demonstrating the issue",
      "remediation": "short, actionable fix"
    }}
  ],
  "notes": ["short_notes"]
}}
"""
        return await self._query_ai(prompt, system_prompt)


