import json
import time
from typing import Any, Dict, Optional

from ..ai import create_provider, BaseAIProvider


class BaseAIAgent:
    """Base class for all AI agents with cost tracking and JSON responses."""

    def __init__(
        self,
        api_key: str,
        settings: Dict[str, Any],
        agent_name: str,
        cost_tracker: Optional[Dict[str, Any]] = None,
        provider: Optional[BaseAIProvider] = None,
    ) -> None:
        self.api_key = api_key
        self.settings = settings
        self.agent_name = agent_name
        provider_kwargs: Dict[str, Any] = {}
        if settings.get('base_url'):
            provider_kwargs['base_url'] = settings['base_url']
        self.provider = provider or create_provider(
            settings.get('provider', 'openai'),
            api_key,
            **provider_kwargs,
        )
        self.model = settings.get('model', 'gpt-4o')
        self.max_tokens = settings.get('max_tokens', 4000)
        self.temperature = settings.get('temperature', 0.1)
        self.cost_tracker = cost_tracker or {'total_tokens': 0, 'total_cost': 0.0, 'queries_made': 0}

    async def _query_ai(self, prompt: str, system_prompt: str | None = None) -> Dict[str, Any]:
        from rich.console import Console
        console = Console()
        try:
            task_description = prompt.split('\n')[0][:60] + "..." if len(prompt) > 60 else prompt.split('\n')[0]
            console.print(f"[dim cyan]AI {self.agent_name}:[/dim cyan] {task_description}")

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            pricing = {
                'gpt-5': {'input': 1.25, 'output': 10.00},
                'gpt-5-mini': {'input': 0.25, 'output': 2.00},
                'gpt-5-nano': {'input': 0.05, 'output': 0.40},
                'gpt-4o': {'input': 2.50, 'output': 10.00},
                'gpt-4o-mini': {'input': 0.15, 'output': 0.60},
                'gpt-4.1': {'input': 2.00, 'output': 8.00},
                'gpt-4.1-mini': {'input': 0.40, 'output': 1.60},
                'gpt-4': {'input': 2.00, 'output': 8.00},
            }

            start_time = time.time()
            
            # Prepare request parameters
            request_params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "response_format": {"type": "json_object"}
            }
            
            # Only add temperature for models that support it
            if not ("preview" in self.model or "search" in self.model):
                request_params["temperature"] = self.temperature
                
            response = await self.provider.chat_completion(request_params)
            query_time = time.time() - start_time

            usage = response.usage
            model_pricing = pricing.get(self.model, pricing['gpt-4'])
            input_cost = (usage.prompt_tokens / 1000000) * model_pricing['input']
            output_cost = (usage.completion_tokens / 1000000) * model_pricing['output']
            actual_cost = input_cost + output_cost

            self.cost_tracker['total_tokens'] += usage.total_tokens
            self.cost_tracker['total_cost'] += actual_cost
            self.cost_tracker['queries_made'] += 1
            try:
                (self.cost_tracker.setdefault('query_times', [])).append(query_time)
            except Exception:
                pass

            console.print(f"[dim green]  ✓ Response: {query_time:.1f}s, In: {usage.prompt_tokens}, Out: {usage.completion_tokens}, Cost: ${actual_cost:.4f}[/dim green]")

            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            console.print(f"[dim red]  ✗ AI Error: {str(e)}[/dim red]")
            return {"error": str(e), "agent": self.agent_name}
