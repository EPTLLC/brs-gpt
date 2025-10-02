from typing import List, Dict
from rich.console import Console

MODEL_CATALOG: List[Dict] = [
    {"id": "gpt-5", "title": "GPT-5", "desc": "Latest model with advanced reasoning capabilities", "recommended": False, "cost": "Std: $1.25/$10 | Flex: $0.625/$5"},
    {"id": "gpt-5-mini", "title": "GPT-5 Mini", "desc": "Efficient GPT-5 variant for cost optimization", "recommended": False, "cost": "Std: $0.25/$2 | Flex: $0.125/$1"},
    {"id": "gpt-5-nano", "title": "GPT-5 Nano", "desc": "Ultra-efficient model for high-volume analysis", "recommended": True, "cost": "Std: $0.05/$0.40 | Flex: $0.025/$0.20"},
    {"id": "gpt-4.1", "title": "GPT-4.1", "desc": "Advanced reasoning quality", "recommended": False, "cost": "Std: $2/$8"},
    {"id": "gpt-4.1-mini", "title": "GPT-4.1 Mini", "desc": "Lightweight reasoning model", "recommended": False, "cost": "Std: $0.40/$1.60"},
    {"id": "gpt-4o", "title": "GPT-4o", "desc": "Balanced speed/quality for most use cases", "recommended": False, "cost": "Std: $2.50/$10"},
    {"id": "gpt-4o-mini", "title": "GPT-4o Mini", "desc": "Budget-friendly option for cost-sensitive analysis", "recommended": False, "cost": "Std: $0.15/$0.60"},
    {"id": "gpt-4o-mini-search-preview", "title": "GPT-4o Mini Search (Preview)", "desc": "Optimized for search/contextual retrieval; great cost/perf", "recommended": True, "cost": "Std: $0.15/$0.60"},
    {"id": "o1", "title": "o1", "desc": "Reasoning model for complex analysis", "recommended": False, "cost": "Std: $15/$60"},
    {"id": "o1-mini", "title": "o1-mini", "desc": "Reasoning model with cost optimization", "recommended": False, "cost": "Std: $1.10/$4.40"},
    {"id": "o3", "title": "o3", "desc": "Advanced reasoning for complex security analysis", "recommended": False, "cost": "Std: $2/$8 | Flex: $1/$4"},
    {"id": "o3-mini", "title": "o3-mini", "desc": "Compact reasoning model", "recommended": False, "cost": "Std: $1.10/$4.40"},
]


def print_model_catalog(console: Console) -> None:
    console.print("[bold]Available OpenAI models:[/bold]")
    for idx, m in enumerate(MODEL_CATALOG, start=1):
        rec = " [green](recommended)[/green]" if m.get("recommended") else ""
        console.print(f"  [cyan]{idx}[/cyan]. [bold]{m['title']}[/bold]{rec}")
        console.print(f"     ID: [magenta]{m['id']}[/magenta]")
        console.print(f"     {m['desc']}")
        console.print(f"     Cost: [yellow]{m.get('cost', 'Unknown')}[/yellow]")
