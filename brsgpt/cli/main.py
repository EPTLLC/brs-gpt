# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
BRS-GPT Main CLI Interface

Implements the "One Command Philosophy":
- brs-gpt setup    (configure OpenAI API key)
- brs-gpt start    (run analysis on target)
- brs-gpt version  (show version info)

Zero configuration, maximum intelligence.
"""

import sys
import argparse
import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console

from ..core.simple_ai_analyzer import SimpleAIAnalyzer
from ..core.intelligent_orchestrator import IntelligentOrchestrator
from ..core.live_mode_agent import LiveModeAgent
from ..core.pentest_as_code import PentestAsCodeExecutor
from ..utils.config_manager import ConfigManager
from .. import __company__, __telegram__, __version__
from .model_catalog import MODEL_CATALOG, print_model_catalog
from .banner import print_banner, cli_epilog


console = Console()


def _select_model_interactive(config_manager: ConfigManager) -> str:
    """Prompt user to select an OpenAI model and persist in config."""
    print_model_catalog(console)
    recommended_idx = next((i for i, m in enumerate(MODEL_CATALOG, start=1) if m.get("recommended")), 1)

    # Non-interactive environments (e.g., CI) must fall back automatically.
    if not sys.stdin.isatty():
        selected = MODEL_CATALOG[recommended_idx - 1]
        config_manager.update_settings({"ai": {"model": selected["id"]}})
        console.print(
            "[yellow]Non-interactive environment detected. Using recommended model:[/yellow] "
            f"{selected['title']} ([magenta]{selected['id']}[/magenta])"
        )
        return selected["id"]

    choice = input(f"Model number [{recommended_idx}]: ").strip()
    if not choice:
        choice_int = recommended_idx
    else:
        try:
            choice_int = int(choice)
        except ValueError:
            choice_int = recommended_idx
    if not (1 <= choice_int <= len(MODEL_CATALOG)):
        choice_int = recommended_idx
    selected = MODEL_CATALOG[choice_int - 1]
    # Persist selection
    config_manager.update_settings({"ai": {"model": selected["id"]}})
    console.print(f"[bold green]Model saved:[/bold green] {selected['title']} ([magenta]{selected['id']}[/magenta])")
    return selected["id"]

    


def setup_command() -> bool:
    """Setup OpenAI API key configuration."""
    console.print("[bold yellow]BRS-GPT Setup[/bold yellow]")
    console.print("Please enter your OpenAI API key:")
    
    api_key = input("OpenAI API Key: ").strip()
    
    if not api_key.startswith('sk-'):
        console.print("[bold red]Error:[/bold red] Invalid OpenAI API key format")
        return False
    
    config_manager = ConfigManager()
    if config_manager.save_api_key(api_key):
        # Ask user to pick OpenAI model right away
        console.print("[bold green]Success:[/bold green] API key saved")
        console.print("")
        try:
            _select_model_interactive(config_manager)
        except Exception:
            # Non-fatal; keep going
            pass
        console.print("You can now run: brs-gpt start <target>")
        return True
    else:
        console.print("[bold red]Error:[/bold red] Failed to save configuration")
        return False


async def start_command(target: str, output: Optional[str] = None, model_override: Optional[str] = None,
                        profile: Optional[str] = None) -> bool:
    """Start analysis on target."""
    console.print(f"[bold cyan]Starting analysis of:[/bold cyan] {target}")

    config_manager = ConfigManager()

    # Apply profile first
    if profile:
        try:
            config_manager.apply_profile(profile)
        except Exception:
            pass

    # AI-First approach: API key is required
    api_key = config_manager.get_api_key()
    if not api_key:
        console.print("[bold red]Error:[/bold red] OpenAI API key is required for AI-controlled analysis")
        console.print("Set your API key in .env file or run: brs-gpt setup")
        return False
    
    console.print("[green]AI-controlled analysis enabled[/green]")

    # Handle model configuration
    settings = config_manager.get_settings()
    current_model = settings.get('ai', {}).get('model')

    # Determine model to use (respect override, otherwise ensure a concrete choice)
    if model_override:
        config_manager.update_settings({'ai': {'model': model_override}})
        selected_model = model_override
        console.print(f"[bold]Model:[/bold] {selected_model}")
    else:
        if not current_model or current_model == 'gpt-4':  # Default needs selection
            console.print("[yellow]Select OpenAI model:[/yellow]")
            try:
                selected_model = _select_model_interactive(config_manager)
            except Exception:
                # Fall back to a sensible default if selection fails
                selected_model = current_model or 'gpt-4o'
        else:
            selected_model = current_model
        # Re-read settings in case they were updated during selection
        settings = config_manager.get_settings()
        selected_model = settings.get('ai', {}).get('model', selected_model)
    
    try:
        # Initialize simple AI analyzer with the resolved model
        analyzer = SimpleAIAnalyzer(api_key, selected_model)
        log_file = await analyzer.analyze_domain(target)
        
        console.print(f"[bold green]Analysis complete:[/bold green] {log_file}")
        console.print(f"[yellow]Total cost:[/yellow] ${analyzer.total_cost:.4f}")
        console.print(f"[yellow]AI queries:[/yellow] {analyzer.total_queries}")
        return True
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return False


async def smart_command(target: str, output: Optional[str] = None, model_override: Optional[str] = None,
                        profile: Optional[str] = None) -> bool:
    """Run AI Orchestrator for advanced, fully AI-controlled analysis."""
    console.print(f"[bold cyan]Starting AI Orchestrator on:[/bold cyan] {target}")

    config_manager = ConfigManager()

    # Apply profile first
    if profile:
        try:
            config_manager.apply_profile(profile)
        except Exception:
            pass

    # API key required
    api_key = config_manager.get_api_key()
    if not api_key:
        console.print("[bold red]Error:[/bold red] OpenAI API key is required for AI-controlled analysis")
        console.print("Set your API key in .env file or run: brs-gpt setup")
        return False

    console.print("[green]AI-controlled orchestrator enabled[/green]")

    # Handle model configuration (same logic as start)
    settings = config_manager.get_settings()
    current_model = settings.get('ai', {}).get('model')

    if model_override:
        config_manager.update_settings({'ai': {'model': model_override}})
        selected_model = model_override
        console.print(f"[bold]Model:[/bold] {selected_model}")
    else:
        if not current_model or current_model == 'gpt-4':
            console.print("[yellow]Select OpenAI model:[/yellow]")
            try:
                selected_model = _select_model_interactive(config_manager)
            except Exception:
                selected_model = current_model or 'gpt-4o'
        else:
            selected_model = current_model
        settings = config_manager.get_settings()
        selected_model = settings.get('ai', {}).get('model', selected_model)

    try:
        # Run orchestrator
        orchestrator = IntelligentOrchestrator(api_key)
        report_path = await orchestrator.ai_analyze_target(target, output)
        console.print(f"[bold green]AI Orchestrator report:[/bold green] {report_path}")
        # If cost tracking available, print summary
        cost = orchestrator.ai_state.get('cost_tracking', {})
        if cost:
            console.print(f"[yellow]AI queries:[/yellow] {cost.get('queries_made', 0)} | "
                          f"[yellow]Tokens:[/yellow] {cost.get('total_tokens', 0)} | "
                          f"[yellow]Cost:[/yellow] ${cost.get('total_cost', 0.0):.4f}")
        return True
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        return False


def version_command() -> None:
    """Show version information."""
    console.print(f"BRS-GPT version {__version__}")
    console.print(f"Company: {__company__}")
    console.print(f"Contact: {__telegram__}")


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="brs-gpt",
        description="AI-Powered Cybersecurity Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=cli_epilog()
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    subparsers.add_parser('setup', help='Configure OpenAI API key')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start analysis on target')
    start_parser.add_argument('target', help='Target domain or URL to analyze')
    start_parser.add_argument('-o', '--output', help='Output file path (optional)')
    start_parser.add_argument('--model', help='Override OpenAI model for this run (e.g., gpt-4o)')
    start_parser.add_argument(
        '--profile', choices=['lightning', 'fast', 'balanced', 'deep'],
        help='Scan profile: lightning (ultra-fast, 3-5min), fast (quick), balanced (default), deep (thorough)'
    )
    
    # Smart command (AI Orchestrator)
    smart_parser = subparsers.add_parser('smart', help='Run advanced AI Orchestrator on target')
    # Live-mode command
    live_parser = subparsers.add_subparsers if False else subparsers.add_parser('live', help='Run continuous lightweight monitoring')
    live_parser.add_argument('target', help='Target domain or URL to monitor')
    live_parser.add_argument('--cycles', type=int, default=3, help='Number of monitoring cycles (default: 3)')
    live_parser.add_argument('--interval', type=int, default=60, help='Seconds between cycles (default: 60)')
    live_parser.add_argument('--model', help='Override OpenAI model (e.g., gpt-4o-mini)')
    live_parser.add_argument('--profile', choices=['lightning', 'fast', 'balanced', 'deep'], help='Scan profile during live mode')

    # Pentest-as-Code command
    pac_parser = subparsers.add_parser('pac', help='Execute Pentest-as-Code scenario (YAML/JSON)')
    pac_parser.add_argument('scenario', help='Path to scenario file (YAML/JSON)')
    smart_parser.add_argument('target', help='Target domain or URL to analyze')
    smart_parser.add_argument('-o', '--output', help='Output file path (optional)')
    smart_parser.add_argument('--model', help='Override OpenAI model for this run (e.g., gpt-4o)')
    smart_parser.add_argument(
        '--profile', choices=['lightning', 'fast', 'balanced', 'deep'],
        help='Scan profile: lightning (ultra-fast), fast, balanced (default), deep (thorough)'
    )

    # API server command
    api_parser = subparsers.add_parser('api', help='Start REST API server')
    api_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    api_parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    api_parser.add_argument('--api-key', help='API key for authentication (default: from env API_KEY)')

    # Optional: list models
    models_parser = subparsers.add_parser('models', help='List available OpenAI models')
    
    # Version command
    subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(1)
    
    # Execute commands
    if args.command == 'setup':
        success = setup_command()
        sys.exit(0 if success else 1)
        
    elif args.command == 'start':
        # Show banner with current settings after processing arguments
        print_banner(profile=getattr(args, 'profile', None))

        # Pass phase flags to start_command
        success = asyncio.run(start_command(
            args.target,
            args.output,
            args.model,
            getattr(args, 'profile', None)
        ))
        sys.exit(0 if success else 1)
    
    elif args.command == 'smart':
        # Show banner with current settings
        print_banner(profile=getattr(args, 'profile', None))
        success = asyncio.run(smart_command(
            args.target,
            args.output,
            args.model,
            getattr(args, 'profile', None)
        ))
        sys.exit(0 if success else 1)

    elif args.command == 'live':
        print_banner(profile=getattr(args, 'profile', None))
        cfg = ConfigManager()
        api_key = cfg.get_api_key()
        if not api_key:
            console.print("[bold red]Error:[/bold red] OpenAI API key is required")
            sys.exit(1)
        agent = LiveModeAgent(api_key)
        try:
            logs = asyncio.run(agent.monitor(
                target=args.target,
                cycles=getattr(args, 'cycles', 3),
                interval_seconds=getattr(args, 'interval', 60),
                profile=getattr(args, 'profile', None),
                model_override=getattr(args, 'model', None),
            ))
            console.print(f"[bold green]Live-mode logs:[/bold green] {len(logs)} files")
            sys.exit(0)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            sys.exit(1)

    elif args.command == 'pac':
        cfg = ConfigManager()
        api_key = cfg.get_api_key()
        if not api_key:
            console.print("[bold red]Error:[/bold red] OpenAI API key is required")
            sys.exit(1)
        executor = PentestAsCodeExecutor(api_key)
        try:
            log = asyncio.run(executor.run(args.scenario))
            console.print(f"[bold green]Scenario completed[/bold green]: {log}")
            sys.exit(0)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            sys.exit(1)

    elif args.command == 'api':
        cfg = ConfigManager()
        openai_key = cfg.get_api_key()
        if not openai_key:
            console.print("[bold red]Error:[/bold red] OpenAI API key is required")
            sys.exit(1)
        
        # Get API key from args or environment
        import os
        api_key = args.api_key or os.getenv('API_KEY', 'changeme')
        
        console.print(f"[bold cyan]Starting BRS-GPT API Server[/bold cyan]")
        console.print(f"[yellow]Host:[/yellow] {args.host}")
        console.print(f"[yellow]Port:[/yellow] {args.port}")
        console.print(f"[yellow]API Key:[/yellow] {'*' * len(api_key)}")
        
        try:
            from ..api.server import start_api_server
            start_api_server(
                host=args.host,
                port=args.port,
                api_key=api_key,
                openai_api_key=openai_key
            )
        except ImportError:
            console.print("[bold red]Error:[/bold red] aiohttp is required for API server")
            console.print("Install with: pip install aiohttp")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            sys.exit(1)
        
    elif args.command == 'models':
        print_model_catalog(console)
        sys.exit(0)
        
    elif args.command == 'version':
        version_command()
        sys.exit(0)


if __name__ == '__main__':
    main()
