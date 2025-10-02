import asyncio
import pytest

from brsgpt.core.agents.optimizer import PerformanceOptimizer


@pytest.mark.asyncio
async def test_performance_optimizer_returns_dict(monkeypatch):
    async def fake_query_ai(self, prompt, system_prompt=None):
        # Minimal valid JSON-like response stub
        return {
            "optimization_strategy": "reduce timeouts and increase concurrency",
            "parameter_adjustments": {
                "concurrency_level": 16,
                "timeout_adjustments": -2,
                "rate_limit_changes": 2.0
            },
            "workflow_modifications": ["cache dns results"],
            "expected_improvement": "15%"
        }

    monkeypatch.setattr(PerformanceOptimizer, "_query_ai", fake_query_ai, raising=True)
    agent = PerformanceOptimizer("sk-test", {"model": "gpt-4o-mini", "max_tokens": 500, "temperature": 0.1})

    current_metrics = {"elapsed_seconds": 1.2, "queries_made": 3}
    target_performance = {"goal": "minimize_duration_without_accuracy_loss"}

    result = await agent.optimize_workflow(current_metrics, target_performance)
    assert isinstance(result, dict)
    assert "optimization_strategy" in result
    assert "parameter_adjustments" in result
