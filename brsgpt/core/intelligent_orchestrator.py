# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:10:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
Intelligent Orchestrator

AI-controlled cybersecurity analysis engine:
- AI makes all operational decisions
- Dynamic tool selection based on target analysis
- Real-time strategy adaptation
- Intelligent resource optimization
- Multi-agent coordination
"""

import asyncio
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.panel import Panel

from .ai_agents import (
    MasterDecisionAgent,
    ReconStrategyAgent, 
    VulnerabilityHuntingAgent,
    ThreatIntelligenceAgent,
    ExploitationAgent,
    ReportingAgent,
    PerformanceOptimizer,
    TestPlannerAgent
)
from .openai_analyzer import OpenAIAnalyzer
from .report_generator import ReportGenerator
from ..version import VERSION
from ..utils.http_client import HttpClient
from ..utils.config_manager import ConfigManager


console = Console()


class IntelligentOrchestrator:
    """
    AI-controlled cybersecurity analysis orchestrator.
    
    AI decision points:
    - Target analysis and strategy formulation
    - Tool selection and parameter optimization
    - Vulnerability prioritization and correlation
    - Real-time strategy adaptation
    - Performance optimization
    """
    
    def __init__(self, openai_api_key: str):
        """
        Initialize the AI-First orchestrator.
        
        Args:
            openai_api_key: OpenAI API key (REQUIRED - no fallbacks!)
        """
        if not openai_api_key or not openai_api_key.startswith('sk-'):
            raise ValueError("OpenAI API key is required for AI-controlled analysis.")
        
        self.api_key = openai_api_key
        self.config_manager = ConfigManager()
        self.settings = self.config_manager.get_settings()
        
        # Initialize core components
        # Use conservative defaults for orchestrator global HTTP client
        self.http_client = HttpClient(
            rate_limit=min(12.0, float(self.settings.get('xss', {}).get('rate_limit', 12.0))),
            timeout=min(5, int(self.settings.get('xss', {}).get('request_timeout', 5)))
        )
        self.report_generator = ReportGenerator(self.settings['output'])
        
        # Initialize AI agent system with shared cost tracking
        cost_tracker = {'total_tokens': 0, 'total_cost': 0.0, 'queries_made': 0, 'query_times': []}
        
        self.master_ai = MasterDecisionAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.recon_ai = ReconStrategyAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.vuln_ai = VulnerabilityHuntingAgent(openai_api_key, self.settings['ai'], cost_tracker) 
        self.threat_ai = ThreatIntelligenceAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.exploit_ai = ExploitationAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.report_ai = ReportingAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.optimizer_ai = PerformanceOptimizer(openai_api_key, self.settings['ai'], cost_tracker)
        self.test_planner_ai = TestPlannerAgent(openai_api_key, self.settings['ai'], cost_tracker)
        # New AI capabilities
        from .ai_agents import CorrelationAgent, ComplianceMapperAgent
        self.correlation_ai = CorrelationAgent(openai_api_key, self.settings['ai'], cost_tracker)
        self.compliance_ai = ComplianceMapperAgent(openai_api_key, self.settings['ai'], cost_tracker)
        
        # AI state management
        self.ai_state = {
            'target': None,
            'master_strategy': {},
            'active_agents': [],
            'real_time_decisions': [],
            'performance_metrics': {},
            'adaptation_history': [],
            'cost_tracking': cost_tracker
        }
    
    async def ai_analyze_target(self, target: str, output_file: Optional[str] = None) -> str:
        """
        AI-controlled target analysis.
        
        Process:
        1. Master AI analyzes target and creates strategy
        2. Specialized agents execute their domains
        3. Real-time adaptation based on findings
        4. Intelligent report generation
        
        Returns:
            Path to generated report
        """
        start_time = time.time()
        self.ai_state['target'] = target
        
        console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
        console.print("[yellow]AI-controlled analysis starting...[/yellow]\n")
        
        # Setup AI workspace
        ai_workspace = await self._setup_ai_workspace(target, output_file)
        
        # Create AI progress tracking
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=20),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            TimeElapsedColumn(),
            TextColumn("[dim cyan]{task.fields[status]}"),
            refresh_per_second=3
        )
        
        main_task = progress.add_task("AI Analysis", status="Initializing", total=100)
        
        with Live(progress, refresh_per_second=3) as live:
            try:
                # PHASE 1: Strategic Analysis
                progress.update(main_task, status="Creating analysis strategy", completed=10)
                master_strategy = await self.master_ai.analyze_target_and_create_strategy(target)
                self.ai_state['master_strategy'] = master_strategy
                
                console.print(f"[dim]Strategy: {master_strategy.get('target_classification', 'web_app')} analysis approach[/dim]")
                progress.update(main_task, status="Strategy complete", completed=20)
                
                # PHASE 2: Reconnaissance
                progress.update(main_task, status="Executing reconnaissance", completed=25)
                recon_results = await self.recon_ai.execute_intelligent_recon(target, master_strategy)
                console.print(f"[dim]Found: {len(recon_results.get('subdomains', []))} subdomains, {len(recon_results.get('open_ports', []))} open ports[/dim]")
                progress.update(main_task, status="Reconnaissance complete", completed=45)
                
                # PHASE 3: AI Test Planning & Execution (bounded)
                progress.update(main_task, status="Planning active tests", completed=48)
                test_plan = {}
                test_results = {"steps": [], "errors": []}
                try:
                    test_plan = await asyncio.wait_for(
                        self.test_planner_ai.plan_tests(target, recon_results, master_strategy),
                        timeout=30.0
                    )
                    # Execute plan safely with strict budgets
                    budget = (test_plan.get('budget') or {})
                    max_iterations = int(budget.get('max_iterations', 1))
                    max_http_requests = int(budget.get('max_http_requests', 8))
                    time_limit_seconds = int(budget.get('time_limit_seconds', 60))

                    # Local HTTP client with safe defaults
                    http_client = self.http_client

                    async def execute_step(step: Dict[str, Any]) -> Dict[str, Any]:
                        action = step.get('action')
                        url = step.get('url')
                        headers = step.get('headers') or {}
                        data = step.get('data') or None
                        result: Dict[str, Any] = {"action": action, "url": url, "ok": False, "status": None}
                        if not (action and url and http_client.is_valid_url(url)):
                            result["error"] = "invalid_step"
                            return result
                        try:
                            if action == 'http_get':
                                resp = await asyncio.wait_for(http_client.get(url, headers=headers), timeout=10.0)
                            elif action == 'http_post':
                                resp = await asyncio.wait_for(http_client.post(url, data=data, headers=headers), timeout=10.0)
                            elif action == 'graphql_introspection':
                                gql_body = step.get('body') or {"query": "{ __schema { types { name } } }"}
                                # Ensure JSON content-type
                                json_headers = headers.copy()
                                json_headers['Content-Type'] = 'application/json'
                                resp = await asyncio.wait_for(http_client.post(url, data=gql_body, headers=json_headers), timeout=12.0)
                            else:
                                result["error"] = "unsupported_action"
                                return result
                            if resp is None:
                                result["error"] = "no_response"
                                return result
                            body = await resp.text()
                            result.update({
                                "ok": True,
                                "status": getattr(resp, 'status', None),
                                "headers": dict(getattr(resp, 'headers', {})),
                                "body_snippet": body[:1024]
                            })
                            return result
                        except Exception as e:
                            result["error"] = str(e)
                            return result

                    # Enforce global limits
                    overall_deadline = time.time() + time_limit_seconds
                    requests_made = 0
                    for iteration in (test_plan.get('iterations') or [])[:max_iterations]:
                        if time.time() >= overall_deadline or requests_made >= max_http_requests:
                            break
                        steps = (iteration or {}).get('steps') or []
                        for step in steps:
                            if time.time() >= overall_deadline or requests_made >= max_http_requests:
                                break
                            res = await execute_step(step)
                            test_results["steps"].append({"step": step, "result": res})
                            requests_made += 1
                except Exception:
                    test_plan = {"error": "planner_timeout_or_error"}

                # PHASE 3.1: Vulnerability Discovery (bounded)
                progress.update(main_task, status="Hunting vulnerabilities", completed=50)
                try:
                    import asyncio
                    # Hard budget for vuln hunting (seconds)
                    vuln_results = await asyncio.wait_for(
                        self.vuln_ai.hunt_vulnerabilities(target, recon_results, master_strategy),
                        timeout=90.0
                    )
                except Exception:
                    vuln_results = {'vulnerabilities': [], 'timeout': True}
                console.print(f"[dim]Vulnerabilities: {len(vuln_results.get('vulnerabilities', []))} potential issues found[/dim]")
                
                # PHASE 3.2: Analyze active test results with AI (bounded)
                analysis_of_tests = {}
                try:
                    analysis_of_tests = await asyncio.wait_for(
                        self.test_planner_ai.evaluate_results(target, test_plan, test_results),
                        timeout=20.0
                    )
                except Exception:
                    analysis_of_tests = {"findings": [], "notes": ["analysis_timeout"]}

                # Deterministic Risk Modeling (hybrid approach)
                try:
                    from .risk.risk_model import RiskModeler  # type: ignore
                except Exception:
                    try:
                        from .risk import risk_model  # fallback import style
                        RiskModeler = risk_model.RiskModeler  # type: ignore
                    except Exception:
                        RiskModeler = None  # type: ignore
                deterministic_risk = None
                if RiskModeler:
                    try:
                        risk_modeler = RiskModeler()
                        deterministic_risk = risk_modeler.build_model(
                            {'open_ports_found': recon_results.get('open_ports', [])},
                            {'vulnerabilities_found': vuln_results.get('vulnerabilities', []), 'missing_security_headers': vuln_results.get('missing_security_headers', [])}
                        )
                        console.print(f"[dim]Deterministic risk score: {deterministic_risk.get('risk_score')}/100 posture {deterministic_risk.get('security_posture')}[/dim]")
                    except Exception:
                        deterministic_risk = None
                progress.update(main_task, status="Vulnerability analysis complete", completed=70)

                # PHASE 3.5: Real-time Performance Optimization (non-intrusive)
                try:
                    progress.update(main_task, status="Optimizing performance", completed=72)
                    elapsed = max(0.1, time.time() - start_time)
                    cost_info = self.ai_state['cost_tracking']
                    current_metrics = {
                        'elapsed_seconds': elapsed,
                        'queries_made': cost_info.get('queries_made', 0),
                        'total_tokens': cost_info.get('total_tokens', 0),
                        'avg_query_time': (sum(cost_info.get('query_times', []) or [0.0]) / max(1, len(cost_info.get('query_times', [])))) if cost_info else 0.0,
                        'rate_limit': self.settings['xss'].get('rate_limit', 8.0),
                        'request_timeout': self.settings['xss'].get('request_timeout', 15),
                    }
                    target_performance = {
                        'goal': 'minimize_duration_without_accuracy_loss',
                        'profile': self.settings.get('active_profile', 'balanced'),
                        'max_tokens': self.settings['ai'].get('max_tokens', 4000),
                    }
                    optimization = await self.optimizer_ai.optimize_workflow(current_metrics, target_performance)
                    self.ai_state['performance_metrics'] = {
                        'suggestions': optimization,
                        'snapshot': current_metrics,
                    }
                except Exception:
                    # Non-fatal; continue analysis
                    self.ai_state['performance_metrics'] = {
                        'suggestions': {'note': 'optimization_unavailable'},
                        'snapshot': {},
                    }
                
                # PHASE 4: Threat Intelligence
                progress.update(main_task, status="Correlating threat intelligence", completed=75)
                threat_intel = await self.threat_ai.analyze_threats(recon_results, vuln_results)
                console.print(f"[dim]Risk assessment: {threat_intel.get('threat_assessment', {}).get('overall_risk_score', 'N/A')}/10[/dim]")
                progress.update(main_task, status="Threat analysis complete", completed=85)
                
                # PHASE 5: AI Correlation (cross-domain)
                progress.update(main_task, status="AI correlation across signals", completed=87)
                try:
                    correlation = await asyncio.wait_for(
                        self.correlation_ai.correlate(recon_results, vuln_results, analysis_of_tests, threat_intel, deterministic_risk),
                        timeout=25.0
                    )
                except Exception:
                    correlation = {"insights": [], "notes": ["correlation_timeout"]}

                # PHASE 6: Exploitation Planning
                progress.update(main_task, status="Planning attack scenarios", completed=90)
                exploit_plans = await self.exploit_ai.plan_exploitations(vuln_results, threat_intel)
                console.print(f"[dim]Attack scenarios: {len(exploit_plans.get('attack_scenarios', []))} scenarios identified[/dim]")
                progress.update(main_task, status="Exploitation planning complete", completed=95)
                
                # PHASE 7: Compliance Mapping
                progress.update(main_task, status="Mapping findings to compliance", completed=96)
                try:
                    compliance = await asyncio.wait_for(
                        self.compliance_ai.map_compliance({
                            'threat_intelligence': threat_intel,
                            'vulnerability_intelligence': vuln_results,
                            'risk_model': deterministic_risk
                        }),
                        timeout=20.0
                    )
                except Exception:
                    compliance = {"frameworks": {}, "summary": "unavailable"}

                # PHASE 8: PoC Generation (safe)
                progress.update(main_task, status="Generating PoCs for confirmed findings", completed=97)
                try:
                    confirmed = {
                        'vulnerabilities': vuln_results.get('vulnerabilities', [])[:8],
                        'correlation_insights': correlation.get('insights', [])[:6],
                        'active_tests': (analysis_of_tests.get('findings', []) if isinstance(analysis_of_tests, dict) else [])[:6]
                    }
                    pocs = await asyncio.wait_for(self.exploit_ai.generate_pocs(confirmed), timeout=20.0)
                except Exception:
                    pocs = {"pocs": []}

                # PHASE 9: Report Generation
                progress.update(main_task, status="Generating report", completed=98)
                
                # Compile all AI results
                cost_info = self.ai_state['cost_tracking']
                ai_results = {
                    'target': target,
                    'start_time': datetime.utcnow().isoformat(),
                    'end_time': datetime.utcnow().isoformat(),
                    'master_strategy': master_strategy,
                    'recon_intelligence': recon_results,
                    'active_test_plan': test_plan,
                    'active_test_results': test_results,
                    'active_test_analysis': analysis_of_tests,
                    'correlation': correlation,
                    'compliance': compliance,
                    'vulnerability_intelligence': vuln_results,
                    'threat_intelligence': threat_intel,
                    'exploitation_intelligence': exploit_plans,
                    'poc_generator': pocs,
                    'risk_model': deterministic_risk,
                    'ai_metadata': {
                        'approach': 'Hybrid AI + Deterministic Risk Analysis',
                        'version': f'BRS-GPT v{VERSION}',
                        'agents_used': ['Master', 'Recon', 'Vuln', 'Threat', 'Exploit', 'Report'],
                        'intelligence_level': 'MAXIMUM',
                        'ai_model': self.settings['ai']['model'],
                        'queries_made': cost_info.get('queries_made', 0),
                        'total_tokens': cost_info.get('total_tokens', 0),
                        'total_cost': cost_info.get('total_cost', 0.0),
                    },
                    'performance': {
                        'avg_query_time': (sum(cost_info.get('query_times', []) or [0.0]) / max(1, len(cost_info.get('query_times', [])))) if cost_info else 0.0,
                        'rate_limit': self.settings['xss'].get('rate_limit', 8.0),
                        'request_timeout': self.settings['xss'].get('request_timeout', 15),
                    }
                }
                
                report_path = await self.report_ai.generate_intelligent_report(ai_results, ai_workspace['html_path'])
                progress.update(main_task, status="Analysis complete", completed=100)
                
                # Performance and cost summary
                total_time = time.time() - start_time
                cost_info = self.ai_state['cost_tracking']
                
                console.print(f"\n[bold green]Analysis complete in {total_time:.1f} seconds[/bold green]")
                console.print(f"[bold cyan]Report:[/bold cyan] {report_path}")
                console.print(f"[yellow]AI Usage:[/yellow] {cost_info['queries_made']} queries, {cost_info['total_tokens']} tokens, ${cost_info['total_cost']:.4f}")
                
                return report_path
                
            except Exception as e:
                console.print(f"[bold red]Analysis failed:[/bold red] {str(e)}")
                raise
    
    async def _setup_ai_workspace(self, target: str, output_file: Optional[str]) -> Dict[str, str]:
        """Setup AI workspace for intelligent analysis."""
        target_name = urlparse(target).netloc or target.replace('://', '_').replace('/', '_')
        safe_target = target_name.replace('.', '_').replace(':', '_')
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        base_dir = Path.cwd() / 'results' / safe_target / timestamp
        base_dir.mkdir(parents=True, exist_ok=True)
        
        workspace = {
            'base_dir': str(base_dir),
            'html_path': str(base_dir / 'report.html'),
            'json_path': str(base_dir / 'report.json'),
            'sarif_path': str(base_dir / 'report.sarif'),
            'live_path': str(base_dir / 'live.jsonl'),
        }
        
        # Override HTML path if specified
        if output_file:
            workspace['html_path'] = output_file
        
        console.print(f"[dim]Workspace: {workspace['base_dir']}[/dim]")
        return workspace
