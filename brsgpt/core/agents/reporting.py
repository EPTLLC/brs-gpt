import json
from typing import Dict, Any
from .base import BaseAIAgent
from ...version import VERSION


class ReportingAgent(BaseAIAgent):
    """AI agent for intelligent report generation."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "Reporting", cost_tracker)

    async def generate_intelligent_report(self, ai_results: Dict[str, Any], output_path: str) -> str:
        executive_summary = await self._create_executive_summary(ai_results)
        # Enrich with cost/performance if present
        cost_info = ai_results.get('ai_metadata', {}) or {}
        perf = ai_results.get('performance', {}) or {}
        report_data = {
            'target': ai_results.get('target'),
            'start_time': ai_results.get('start_time'),
            'end_time': ai_results.get('end_time'),
            'recon_data': ai_results.get('recon_intelligence', {}),
            'xss_data': ai_results.get('vulnerability_intelligence', {}),
            'ai_analysis': {
                'final_synthesis': executive_summary,
                'live_analysis': ai_results.get('threat_intelligence', {}),
                'rationale': f"AI-controlled analysis using {self.model}"
            },
            'metadata': {
                'approach': 'AI + Deterministic Hybrid Analysis',
                'version': f'BRS-GPT v{VERSION}',
                'ai_model': self.model,
                'phases': {'ai': True, 'recon': True, 'xss': True, 'risk': True}
            },
            'cost_metrics': {
                'queries': cost_info.get('queries', cost_info.get('queries_made')),
                'tokens': cost_info.get('tokens', cost_info.get('total_tokens')),
                'cost_usd': cost_info.get('cost', cost_info.get('total_cost')),
            },
            'performance_metrics': {
                'avg_query_time': perf.get('avg_query_time'),
                'rate_limit': perf.get('rate_limit'),
                'request_timeout': perf.get('request_timeout'),
            }
        }
        from brsgpt.core.report_generator import ReportGenerator
        report_gen = ReportGenerator(self.settings.get('output', {}))
        result = await report_gen.generate_html_report(report_data, output_path)
        if result:
            return result
        from pathlib import Path
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html><head><title>BRS-GPT Analysis - {ai_results.get('target')}</title></head>
<body>
<h1>AI + Deterministic Hybrid Security Analysis</h1>
<p>Target: {ai_results.get('target')}</p>
<p>Analysis completed by AI agents</p>
<p>Executive Summary: {executive_summary.get('executive_overview', 'Analysis complete')}</p>
</body></html>""")
        return output_path

    async def _create_executive_summary(self, ai_results: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """You are a cybersecurity consultant preparing an executive briefing for senior leadership. Respond in JSON format."""
        prompt = f"""
Analysis results: {json.dumps(ai_results, indent=2)}

Create executive summary:
{{
    "security_posture_rating": "excellent|good|fair|poor|critical",
    "executive_overview": "2_sentence_summary_for_executives",
    "key_findings": [
        {{
            "finding": "business_relevant_issue",
            "business_impact": "impact_in_business_terms",
            "urgency": "low|medium|high|critical",
            "estimated_cost_to_fix": "cost_estimate"
        }}
    ],
    "immediate_actions": ["actions_needed_within_24_48_hours"],
    "strategic_recommendations": ["longer_term_security_investments"],
    "compliance_impact": "assessment_of_regulatory_implications",
    "budget_recommendations": {{
        "immediate_costs": "estimated_immediate_costs",
        "annual_security_budget": "recommended_annual_investment"
    }}
}}
"""
        return await self._query_ai(prompt, system_prompt)
