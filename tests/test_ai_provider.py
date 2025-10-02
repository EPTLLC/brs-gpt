import asyncio

import pytest

from brsgpt.core.agents.base import BaseAIAgent
from brsgpt.core.ai import BaseAIProvider


class DummyProvider(BaseAIProvider):
    def __init__(self):
        self.called = False

    async def chat_completion(self, request_params):
        self.called = True
        class Response:
            usage = type("Usage", (), {"prompt_tokens": 10, "completion_tokens": 15, "total_tokens": 25})
            choices = [type("Choice", (), {"message": type("Msg", (), {"content": '{"ok": true}'})})]
        return Response()


class DummyAgent(BaseAIAgent):
    async def run(self):
        return await self._query_ai("{}", None)


@pytest.mark.asyncio
async def test_agent_uses_injected_provider(monkeypatch):
    provider = DummyProvider()

    agent = DummyAgent(
        api_key="sk-test",
        settings={"model": "gpt-4o-mini"},
        agent_name="Dummy",
        cost_tracker={"total_tokens": 0, "total_cost": 0.0, "queries_made": 0},
        provider=provider,
    )

    result = await agent.run()
    assert provider.called
    assert result == {"ok": True}
