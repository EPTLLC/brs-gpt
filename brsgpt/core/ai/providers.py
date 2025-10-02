"""AI provider abstractions for BRS-GPT."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

try:
    from openai import AsyncOpenAI
except Exception:  # pragma: no cover - openai optional in some envs
    AsyncOpenAI = None  # type: ignore


class BaseAIProvider(ABC):
    """Abstract provider interface for chat-based AI models."""

    @abstractmethod
    async def chat_completion(self, request_params: Dict[str, Any]) -> Any:
        """Execute a chat completion request and return the raw provider response."""


class OpenAIProvider(BaseAIProvider):
    """Async OpenAI provider wrapper."""

    def __init__(self, api_key: str, **client_kwargs: Any) -> None:
        if AsyncOpenAI is None:
            raise RuntimeError("openai package is required for OpenAIProvider")
        self._client = AsyncOpenAI(api_key=api_key, **client_kwargs)

    async def chat_completion(self, request_params: Dict[str, Any]) -> Any:
        return await self._client.chat.completions.create(**request_params)


_PROVIDER_REGISTRY = {
    "openai": OpenAIProvider,
}


def create_provider(name: str, api_key: str, **provider_kwargs: Any) -> BaseAIProvider:
    """Factory to create configured AI providers."""
    key = (name or "openai").lower()
    if key not in _PROVIDER_REGISTRY:
        raise ValueError(f"Unsupported AI provider: {name}")
    provider_cls = _PROVIDER_REGISTRY[key]
    return provider_cls(api_key=api_key, **provider_kwargs)
