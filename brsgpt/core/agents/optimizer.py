import json
from typing import Dict, Any
from .base import BaseAIAgent


class PerformanceOptimizer(BaseAIAgent):
    """AI agent for real-time performance optimization."""

    def __init__(self, api_key: str, settings: Dict[str, Any], cost_tracker: Dict[str, Any] | None = None):
        super().__init__(api_key, settings, "PerformanceOptimizer", cost_tracker)

    async def optimize_workflow(self, current_metrics: Dict[str, Any], target_performance: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = """You are a performance optimization expert. Analyze metrics and recommend optimizations. Respond in JSON format."""
        prompt = f"""
Current performance: {json.dumps(current_metrics, indent=2)}
Target performance: {json.dumps(target_performance, indent=2)}

Optimize workflow:
{{
    "optimization_strategy": "description",
    "parameter_adjustments": {{
        "concurrency_level": number,
        "timeout_adjustments": number,
        "rate_limit_changes": number
    }},
    "workflow_modifications": ["modification_descriptions"],
    "expected_improvement": "percentage_or_time_savings"
}}
"""
        return await self._query_ai(prompt, system_prompt)
