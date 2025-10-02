import pytest

from brsgpt.core.simple_ai_analyzer import SimpleAIAnalyzer
from brsgpt.core.ai import BaseAIProvider


class DummyProvider(BaseAIProvider):
    def __init__(self):
        self.called = False

    async def chat_completion(self, request_params):
        self.called = True

        class Response:
            usage = type("Usage", (), {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
            choices = [type("Choice", (), {"message": type("Msg", (), {"content": '{"result": "ok"}'})})]

        return Response()


@pytest.mark.asyncio
async def test_simple_ai_analyzer_uses_injected_provider(monkeypatch, tmp_path):
    provider = DummyProvider()

    analyzer = SimpleAIAnalyzer(
        api_key="sk-test",
        model="gpt-4o-mini",
        provider=provider,
    )

    # Avoid file IO and rich output in the unit test
    monkeypatch.setattr(analyzer, "_log", lambda *args, **kwargs: None)

    result = await analyzer._query_ai("{}", "Test Task")

    assert provider.called
    assert result == {"result": "ok"}
