from typing import Optional
from rich.text import Text
from rich.panel import Panel
from rich.console import Console

from ..utils.config_manager import ConfigManager
from .. import __version__, __company__, __telegram__


def print_banner(profile: Optional[str] = None) -> None:
    console = Console()
    cfg = ConfigManager()

    # Apply profile if provided
    temp_settings = cfg.get_settings().copy()
    if profile:
        try:
            profiles = cfg.get_profiles()
            if profile in profiles:
                temp_settings.update(profiles[profile])
        except Exception:
            pass

    active_profile = profile or temp_settings.get('active_profile', 'balanced')

    banner_text = Text()
    banner_text.append("BRS-GPT", style="bold red")
    banner_text.append(" v" + __version__, style="bold white")
    banner_text.append(" - AI-Controlled Security Analysis", style="white")

    info_text = Text()
    info_text.append(f"Company: {__company__}\n", style="dim white")
    info_text.append(f"Dev: Brabus\n", style="dim white")
    info_text.append(f"Contact: {__telegram__}\n", style="dim white")
    info_text.append(f"Profile: {active_profile}", style="dim white")
    info_text.append(f"\nAI Model: {temp_settings.get('ai', {}).get('model', 'gpt-4o-mini-search-preview')}", style="dim white")

    console.print(Panel(
        banner_text + "\n\n" + info_text,
        border_style="red",
        padding=(1, 2)
    ))


def cli_epilog() -> str:
        return f"""
Examples:
    brs-gpt setup                    Configure OpenAI API key
    brs-gpt start example.com        Analyze target domain
    brs-gpt start example.com -o report.html  Save custom report
    brs-gpt smart example.com        Run AI Orchestrator (multi-agent)
    brs-gpt version                  Show version information

Company: {__company__}
Contact: {__telegram__}
"""
