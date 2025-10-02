# BRS-GPT AI Agent Instructions

## Project Overview

BRS-GPT is an **AI-controlled cybersecurity analysis platform** that automates reconnaissance, vulnerability scanning, and threat assessment using multi-agent AI orchestration with OpenAI models.

## Architecture

### Multi-Agent System
The core architecture uses specialized AI agents in `brsgpt/core/agents/`:
- `MasterDecisionAgent` - Strategic planning and coordination
- `ReconStrategyAgent` - Reconnaissance strategy and execution  
- `VulnerabilityHuntingAgent` - XSS and vulnerability discovery
- `ThreatIntelligenceAgent` - Risk assessment and threat correlation
- `ExploitationAgent` - Attack scenario planning
- `ReportingAgent` - Executive and technical report generation
- `TestPlannerAgent` - Safe HTTP active probing with budgets
- `PerformanceOptimizer` - Real-time resource optimization

### Key Components
- **CLI Entry Point**: `brsgpt/cli/main.py` implements "One Command Philosophy"
- **Orchestrator**: `IntelligentOrchestrator` coordinates multi-agent workflows
- **Simple Analyzer**: `SimpleAIAnalyzer` for basic single-pass analysis
- **Config Manager**: `ConfigManager` handles API keys and profiles

## Development Patterns

### AI Agent Development
When modifying agents in `brsgpt/core/agents/`:
- All agents inherit from `BaseAIAgent` 
- Use OpenAI-only design (no offline LLMs supported)
- Implement cost tracking with `total_cost` and `total_queries`
- Follow async/await patterns for API calls

### CLI Commands Structure
```bash
brs-gpt setup        # Configure API key interactively
brs-gpt start <target> --profile <lightning|fast|balanced|deep>
brs-gpt smart <target>   # Multi-agent orchestrator mode
brs-gpt live <target>    # Continuous monitoring mode
brs-gpt pac <scenario.yaml>  # Pentest-as-Code execution
```

### Configuration Management
- API keys stored in `~/.config/brs-gpt/config.json` with 700 permissions
- Environment variables: `OPENAI_API_KEY`, `OPENAI_MODEL`, `BRS_GPT_CONFIG_DIR`
- Profiles in config define analysis depth: lightning (2-3min), fast (4-6min), balanced (8-12min), deep (15-25min)

### Report Generation
Reports generated in `results/` directory with formats:
- `.txt` - Human-readable AI summaries
- `.json` - Structured findings data
- `.html` - Executive dashboard with "red lamp" risk indicator
- `.sarif` - SARIF format for security tools integration

## Testing & Development

### Running Tests
```bash
pytest tests/                 # Run all tests
pytest tests/test_ai_*.py    # Test AI components
```

### Development Setup
```bash
pip install -e .             # Editable install
echo "OPENAI_API_KEY=sk-xxx" > .env
brs-gpt setup               # Interactive configuration
```

### Code Quality
- Uses `ruff` for linting (config in `pyproject.toml`)
- Line length: 100 characters
- Type hints with `mypy` (Python 3.10+)

## OpenAI Integration

### Model Selection
- Primary analysis: `OPENAI_MODEL` (default: gpt-4o)
- Search/classification: `OPENAI_SEARCH_MODEL` (default: gpt-4o-mini)
- JSON fallback: `OPENAI_FALLBACK_MODEL` (default: gpt-4o-mini)

### Cost Management
Real-time cost tracking displayed during analysis:
```
AI MasterDecision: Analyze target: example.com
→ Tokens: ~385, Cost: ~$0.0115
✓ Response: 3.5s, Tokens: 552, Cost: $0.0166
```

## Security & Ethics

- **Authorized testing only** - tool designed for legitimate security assessment
- No sensitive data stored locally
- Offline threat feeds supported in `~/.config/brs-gpt/feeds/`
- GPLv3 license with commercial licensing available

## Common Workflows

### Adding New AI Agent
1. Create agent class in `brsgpt/core/agents/new_agent.py`
2. Inherit from `BaseAIAgent`
3. Add import to `brsgpt/core/ai_agents.py`
4. Register in `IntelligentOrchestrator` workflow

### Adding CLI Command
1. Add command function in `brsgpt/cli/main.py`
2. Register in argument parser
3. Handle async execution with proper error handling

### Extending Protocol Detection
1. Add detector logic in `brsgpt/recon/tech_detector.py` 
2. Update service mapping in threat intelligence
3. Add corresponding threat feeds if needed

When working with this codebase, prioritize the AI-first philosophy, maintain cost transparency, and ensure all new features integrate with the multi-agent orchestration system.