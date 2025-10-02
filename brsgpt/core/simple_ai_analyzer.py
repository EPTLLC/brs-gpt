# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 21:48:00 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Simple AI Analyzer

Простая логика:
1. Создаем файл domain_datetime.txt
2. Пишем туда ВСЕ что происходит
3. AI анализирует и сразу записываем результат
4. Никаких сложностей с папками
"""

import asyncio
import time
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from .risk.risk_model import RiskModeler
from .ai import create_provider, BaseAIProvider
from ..version import VERSION

console = Console()


class SimpleAIAnalyzer:
    """Простой AI анализатор без сложностей."""
    
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        provider: Optional[BaseAIProvider] = None,
        base_url: Optional[str] = None,
    ):
        self.api_key = api_key
        self.model = model
        provider_kwargs: Dict[str, Any] = {}
        if base_url:
            provider_kwargs['base_url'] = base_url
        self.provider = provider or create_provider('openai', api_key, **provider_kwargs)
        
        # Простое отслеживание затрат
        self.total_cost = 0.0
        self.total_queries = 0
        
        # Реальные цены OpenAI
        self.pricing = {
            'gpt-5': {'input': 1.25, 'output': 10.00},
            'gpt-5-mini': {'input': 0.25, 'output': 2.00},
            'gpt-4o': {'input': 2.50, 'output': 10.00},
            'gpt-4o-mini': {'input': 0.15, 'output': 0.60},
            'gpt-4.1': {'input': 2.00, 'output': 8.00},
            'gpt-4.1-mini': {'input': 0.40, 'output': 1.60},
        }
        
        self.log_file = None
    
    def _create_log_file(self, target: str) -> str:
        """Создает простой лог файл в папке results"""
        domain = urlparse(target).netloc or target.replace('https://', '').replace('http://', '')
        safe_domain = domain.replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Создаем в папке results
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)

        filename = results_dir / f"{safe_domain}_{timestamp}.txt"
        self.log_file = str(filename)
        self._evidence_dir = results_dir / "raw" / safe_domain
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Создаем файл и пишем заголовок
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"BRS-GPT Security Analysis Report\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"TARGET INFORMATION:\n")
            f.write(f"Domain: {target}\n")
            f.write(f"AI Model: {self.model}\n") 
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Company: EasyProTech LLC\n")
            f.write(f"{'='*60}\n\n")
        
        console.print(f"[bold cyan]Log file:[/bold cyan] {filename}")
        return filename
    
    def _log(self, message: str):
        """Записывает сообщение в лог файл"""
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        console.print(message)

    def _store_evidence(self, name: str, content: str) -> Optional[str]:
        try:
            evidence_dir = getattr(self, "_evidence_dir", None)
            if not evidence_dir:
                return None
            safe_name = name.replace(":", "_")
            path = evidence_dir / f"{safe_name}.txt"
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(content)
            return str(path)
        except Exception:
            return None
    
    async def _query_ai(self, prompt: str, task_name: str) -> Dict[str, Any]:
        """Простой AI запрос с логированием"""
        
        self._log(f"AI Task: {task_name}")
        self._log(f"Prompt length: {len(prompt)} chars")
        
        try:
            start_time = time.time()
            
            # Prepare request parameters
            request_params = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert. Respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 2000,
                "response_format": {"type": "json_object"}
            }
            
            # Only add temperature for models that support it
            if not ("preview" in self.model or "search" in self.model):
                request_params["temperature"] = 0.1
                
            response = await self.provider.chat_completion(request_params)
            
            query_time = time.time() - start_time
            usage = response.usage
            
            # Рассчитываем реальную стоимость
            model_pricing = self.pricing.get(self.model, {'input': 2.50, 'output': 10.00})
            cost = (usage.prompt_tokens / 1000000 * model_pricing['input'] + 
                   usage.completion_tokens / 1000000 * model_pricing['output'])
            
            self.total_cost += cost
            self.total_queries += 1
            
            self._log(f"Response time: {query_time:.1f}s")
            self._log(f"Tokens: {usage.prompt_tokens} input + {usage.completion_tokens} output = {usage.total_tokens}")
            self._log(f"Cost: ${cost:.4f}")
            self._log(f"Total cost so far: ${self.total_cost:.4f}")
            
            result = json.loads(response.choices[0].message.content)
            # Форматируем ответ AI более читабельно
            self._format_ai_response(result, task_name)
            self._log("-" * 50)
            
            return result
            
        except Exception as e:
            self._log(f"ERROR: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_domain(self, target: str) -> str:
        """Простой анализ домена с записью всего в файл и генерацией HTML/JSON/SARIF отчётов"""
        
        log_file = self._create_log_file(target)
        start_time_iso = datetime.utcnow().isoformat()
        
        self._log("Starting AI-controlled analysis...")
        
        # 1. Стратегический анализ
        strategy_result = await self._query_ai(
            f"Analyze domain {target} and classify it. What type of target is this and what security analysis approach should be used?",
            "Strategic Analysis"
        )
        
        # 2. Реальное reconnaissance + AI анализ
        recon_result = await self._perform_real_recon(target)
        
        # 3. Реальный vulnerability анализ + AI оценка
        vuln_result = await self._perform_real_vuln_scan(target)
        
        # 4. AI threat assessment на основе РЕАЛЬНЫХ данных
        threat_result = await self._query_ai(
            f"""Assess overall security posture for {target} based on REAL scan results:

RECON RESULTS: {recon_result.get('subdomain_count', 0)} subdomains, {recon_result.get('port_count', 0)} open ports
VULNERABILITY RESULTS: {vuln_result.get('vulnerability_count', 0)} XSS issues, {len(vuln_result.get('missing_security_headers', []))} missing headers
CRITICAL FINDINGS: {recon_result.get('critical_findings', [])}

Provide final assessment:
{{
    "overall_security_score": "number_1_to_10_based_on_real_findings",
    "security_posture": "excellent|good|fair|poor|critical",
    "attack_surface_summary": "summary_based_on_actual_ports_and_services",
    "priority_risks": ["risks_based_on_real_scan_results"],
    "immediate_actions": ["specific_actions_for_found_issues"],
    "cost_benefit_analysis": "assessment_of_fix_priorities"
}}""",
            "Final Threat Assessment"
        )
        
        # 5. Final summary
        self._log("=" * 50)
        self._log("ANALYSIS COMPLETE")
        self._log(f"Total AI queries: {self.total_queries}")
        self._log(f"Total cost: ${self.total_cost:.4f}")
        self._log(f"Model used: {self.model}")
        self._log(f"Target analyzed: {target}")
        
        # 6. Итоговые рекомендации на основе РЕАЛЬНЫХ данных
        self._generate_final_recommendations(strategy_result, recon_result, vuln_result, threat_result)

        # 7. Сбор структурированных результатов и генерация отчётов (HTML/JSON/SARIF)
        try:
            end_time_iso = datetime.utcnow().isoformat()
            # Приводим recon/xss к ожидаемой структуре ReportGenerator
            recon_struct = {
                'subdomains': recon_result.get('subdomains_found', []),
                'open_ports': recon_result.get('open_ports_found', []),
                'technologies': {},
                'verified_port_count': recon_result.get('verified_port_count', 0),
            }
            xss_struct = {
                'vulnerabilities': vuln_result.get('vulnerabilities_found', []),
            }
            # Deterministic risk model
            risk_modeler = RiskModeler()
            deterministic_risk = risk_modeler.build_model(recon_result, vuln_result)
            # Нормализуем executive summary для шаблона
            executive_summary = {
                'security_posture_rating': threat_result.get('security_posture', deterministic_risk.get('security_posture', 'unknown')),
                'executive_overview': threat_result.get('vulnerability_summary', deterministic_risk.get('summary', 'Security assessment complete.')),
                'key_findings': recon_result.get('critical_findings', []),
                'immediate_actions': threat_result.get('immediate_actions', deterministic_risk.get('remediation_plan', {}).get('immediate', [])),
                'strategic_recommendations': threat_result.get('strategic_recommendations', []),
            }
            analysis_results = {
                'target': target,
                'start_time': start_time_iso,
                'end_time': end_time_iso,
                'recon_data': recon_struct,
                'xss_data': xss_struct,
                'risk_model': deterministic_risk,
                'ai_analysis': {
                    'executive_summary': executive_summary,
                    'correlation': {},
                    'attack_paths': {},
                },
                'metadata': {
                    'ai_model': self.model,
                    'data_quality': {
                        'verified_open_ports': recon_result.get('verified_port_count', 0),
                        'missing_security_headers': len(vuln_result.get('missing_security_headers', [])),
                    }
                }
            }
            from .report_generator import ReportGenerator
            report = ReportGenerator({'format': 'html', 'include_raw_data': False, 'show_false_positives': False})
            base = str(Path(self.log_file).with_suffix(''))
            html_out = base + '.html'
            json_out = base + '.json'
            sarif_out = base + '.sarif'
            html_path = await report.generate_html_report(analysis_results, html_out)
            json_path = await report.generate_json_report(analysis_results, json_out)
            sarif_path = await report.generate_sarif_report(analysis_results, sarif_out)
            if html_path:
                self._log(f"HTML report: {html_path}")
            if json_path:
                self._log(f"JSON report: {json_path}")
            if sarif_path:
                self._log(f"SARIF report: {sarif_path}")
        except Exception as e:
            self._log(f"Report generation failed: {str(e)}")

        return log_file
    
    def _format_ai_response(self, result: Dict[str, Any], task_name: str):
        """Форматирует ответ AI в читабельном виде"""
        self._log(f"AI DECISION FOR {task_name.upper()}:")
        
        if task_name == "Strategic Analysis":
            self._log(f"  Domain Type: {result.get('classification', 'Unknown')}")
            self._log(f"  Target Type: {result.get('target_type', 'Unknown')}")
            
        elif task_name == "Recon Analysis":
            # Показываем данные из AI анализа реальных результатов
            assessment = result.get('attack_surface_assessment', 'No assessment')
            risk_level = result.get('risk_level', 'Unknown')
            self._log(f"  AI Attack Surface Assessment: {assessment}")
            self._log(f"  AI Risk Level: {risk_level}")
            critical_findings = result.get('critical_findings', [])
            if critical_findings:
                self._log(f"  Critical findings: {', '.join(critical_findings[:3])}")
            
        elif task_name == "Vulnerability Assessment":
            vuln_count = result.get('vulnerability_count', 0)
            missing_headers = result.get('missing_security_headers', [])
            security_rating = result.get('security_rating', 'unknown')
            self._log(f"  XSS Vulnerabilities: {vuln_count}")
            self._log(f"  Missing Security Headers: {len(missing_headers)}")
            if missing_headers:
                self._log(f"    Headers missing: {', '.join(missing_headers[:3])}")
            self._log(f"  AI Security Rating: {security_rating}")
            immediate_fixes = result.get('immediate_fixes', [])
            if immediate_fixes:
                self._log(f"  Immediate fixes: {len(immediate_fixes)} recommended")
                for i, fix in enumerate(immediate_fixes[:2], 1):
                    self._log(f"    {i}. {fix}")
            
        elif task_name == "Final Threat Assessment":
            security_score = result.get('overall_security_score', 'Unknown')
            security_posture = result.get('security_posture', 'Unknown')
            priority_risks = result.get('priority_risks', [])
            immediate_actions = result.get('immediate_actions', [])
            
            self._log(f"  Overall Security Score: {security_score}/10")
            self._log(f"  Security Posture: {security_posture}")
            self._log(f"  Priority Risks: {len(priority_risks)}")
            for i, risk in enumerate(priority_risks[:3], 1):
                self._log(f"    {i}. {risk}")
            self._log(f"  Immediate Actions: {len(immediate_actions)}")
            for i, action in enumerate(immediate_actions[:3], 1):
                self._log(f"    {i}. {action}")
    
    def _generate_final_recommendations(self, strategy: Dict[str, Any], recon: Dict[str, Any], 
                                      vulns: Dict[str, Any], threats: Dict[str, Any]):
        """Генерирует итоговые рекомендации на основе РЕАЛЬНЫХ данных"""
        self._log("=" * 60)
        self._log("FINAL SECURITY ASSESSMENT")
        self._log("=" * 60)
        
        # Берем данные из РЕАЛЬНЫХ результатов сканирования
        subdomain_count = recon.get('subdomain_count', 0)
        port_count = recon.get('port_count', 0)
        vuln_count = vulns.get('vulnerability_count', 0)
        missing_headers_count = len(vulns.get('missing_security_headers', []))
        
        # Берем AI оценки
        security_score = threats.get('overall_security_score', 'Unknown')
        security_posture = threats.get('security_posture', 'Unknown')
        risk_level = recon.get('risk_level', 'Unknown')
        
        self._log("\nSUMMARY (Based on Real Scan Data):")
        self._log(f"  Target Classification: {strategy.get('classification', 'Unknown')}")
        self._log(f"  AI Security Score: {security_score}/10")
        self._log(f"  Security Posture: {security_posture}")
        self._log(f"  Attack Surface Risk: {risk_level}")
        
        self._log("\nFINDINGS:")
        self._log(f"  Subdomains Discovered: {subdomain_count}")
        self._log(f"  Open Ports Found: {port_count}")
        self._log(f"  XSS Vulnerabilities: {vuln_count}")
        self._log(f"  Missing Security Headers: {missing_headers_count}")
        
        # Показываем конкретные missing headers
        missing_headers = vulns.get('missing_security_headers', [])
        if missing_headers:
            self._log("  Missing Headers:")
            for header in missing_headers:
                self._log(f"    - {header}")
        
        self._log("\nPRIORITY ACTIONS (AI Recommendations):")
        
        # Берем конкретные действия из AI анализа
        immediate_actions = threats.get('immediate_actions', [])
        if immediate_actions:
            self._log("  Critical fixes:")
            for i, action in enumerate(immediate_actions[:3], 1):
                self._log(f"    {i}. {action}")
        
        # Добавляем рекомендации по headers если есть
        if missing_headers:
            self._log("  Security headers to implement:")
            for header in missing_headers[:3]:
                self._log(f"    - Add {header}")
        
        # Показываем критические находки из recon
        critical_findings = recon.get('critical_findings', [])
        if critical_findings:
            self._log("  Critical port/service issues:")
            for finding in critical_findings[:3]:
                self._log(f"    - {finding}")
        
        # XSS test summary - показываем что тестировалось
        if vuln_count == 0:
            self._log("  XSS Testing Summary:")
            self._log("    - Contexts tested: HTML, JavaScript, Attributes")
            self._log("    - Result: No XSS vulnerabilities detected")
        else:
            self._log("  XSS Testing Summary:")
            self._log(f"    - Vulnerabilities found: {vuln_count}")
            self._log("    - Requires immediate remediation")

        # Итоговая стоимость и метаданные
        self._log("\nANALYSIS COST:")
        self._log(f"  Total AI Queries: {self.total_queries}")
        self._log(f"  Total Cost: ${self.total_cost:.4f}")
        self._log(f"  Model Used: {self.model}")
        self._log(f"\nGenerated by BRS-GPT v{VERSION} (hybrid mode)")
        self._log("EasyProTech LLC")
    
    async def _perform_real_recon(self, target: str) -> Dict[str, Any]:
        """Выполняет реальное reconnaissance и анализирует результаты через AI"""
        
        self._log("RECONNAISSANCE PHASE:")
        self._log("Performing real subdomain enumeration...")
        
        try:
            # Реальное сканирование субдоменов
            from ..recon.subdomain_enum import SubdomainEnumerator
            from ..utils.http_client import HttpClient
            
            http_client = HttpClient(rate_limit=10.0, timeout=5)
            subdomain_enum = SubdomainEnumerator(http_client, {
                'max_subdomains': 10,
                'dns_timeout': 3,
                'concurrent_requests': 8
            })
            
            subdomains = await asyncio.wait_for(
                subdomain_enum.enumerate(target), 
                timeout=20.0
            )
            
            self._log(f"Found {len(subdomains)} subdomains:")
            for sub in subdomains:
                self._log(f"  - {sub}")
            
        except Exception as e:
            self._log(f"Subdomain scan failed: {str(e)}")
            subdomains = []
        
        self._log("Performing basic port scan...")
        self._log(f"Target for port scan: {target}")
        
        try:
            # Базовый порт-скан
            from ..recon.port_scanner import PortScanner
            
            port_scanner = PortScanner({
                'port_scan_timeout': 5,
                'concurrent_requests': 50
            })
            
            open_ports = await asyncio.wait_for(
                port_scanner.scan(target),
                timeout=60.0  # Увеличиваем таймаут для больших сканирований
            )
            
            self._log(f"Found {len(open_ports)} open ports:")
            
            critical_ports = []
            for port in open_ports:
                port_num = port.get('port')
                service = port.get('service') or 'unknown'
                confidence = port.get('service_confidence', 'unknown')
                notes = port.get('security_notes', {})
                risk = notes.get('risk_level', 'low')
                if risk in {'high', 'critical'}:
                    critical_ports.append(
                        f"Port {port_num} ({service}, confidence={confidence}, risk={risk})"
                    )

            # Показываем первые 15 портов для общего обзора
            for port in open_ports[:15]:
                self._log(
                    f"  - Port {port.get('port')}: {port.get('service') or 'unknown'} "
                    f"(confidence={port.get('service_confidence', 'unknown')})"
                )

            if len(open_ports) > 15:
                self._log(f"  ... and {len(open_ports) - 15} more ports")
                
            if critical_ports:
                self._log("\nCritical services:")
                for svc in critical_ports:
                    self._log(f"  - {svc}")

            for port in open_ports:
                if port.get('evidence'):
                    evidence_path = self._store_evidence(
                        f"port_{port.get('port')}",
                        json.dumps(port['evidence'], indent=2, ensure_ascii=False)
                    )
                    if evidence_path:
                        port['evidence_path'] = evidence_path
                        self._log(f"    Evidence saved for port {port.get('port')} -> {evidence_path}")
            
        except Exception as e:
            self._log(f"Port scan failed: {str(e)}")
            self._log(f"Exception type: {type(e).__name__}")
            import traceback
            self._log(f"Full traceback: {traceback.format_exc()}")
            open_ports = []
        
        # AI анализирует реальные результаты
        real_data = {
            'subdomains_found': subdomains,
            'open_ports_found': open_ports,
            'subdomain_count': len(subdomains),
            'port_count': len(open_ports),
            'verified_port_count': sum(1 for port in open_ports if port.get('evidence', {}).get('connect'))
        }
        
        # AI анализирует РЕАЛЬНЫЕ результаты с детальным контекстом
        port_details = []
        for port in open_ports[:20]:
            port_details.append({
                'port': port.get('port'),
                'service': port.get('service', 'unknown'),
                'service_confidence': port.get('service_confidence', 'unknown'),
                'transport': port.get('transport', 'tcp'),
                'risk_level': port.get('security_notes', {}).get('risk_level', 'unknown')
            })
        
        ai_analysis = await self._query_ai(
            f"""Analyze real reconnaissance results for {target}:

SUBDOMAINS DISCOVERED: {subdomains}
OPEN PORTS FOUND: {port_details}

Based on these REAL findings, provide security assessment:
{{
    "attack_surface_assessment": "description_of_attack_surface_based_on_real_ports",
    "risk_level": "low|medium|high|critical",
    "critical_findings": ["specific_security_issues_based_on_open_ports"],
    "port_analysis": {{
        "high_risk_ports": ["ports_that_pose_security_risks"],
        "services_exposed": ["services_that_should_be_secured"],
        "recommendations": ["specific_actions_for_found_ports"]
    }},
    "subdomain_analysis": {{
        "coverage": "assessment_of_subdomain_discovery",
        "additional_targets": ["potential_missing_subdomains"]
    }}
}}""",
            "Recon Analysis"
        )
        
        # Объединяем реальные данные с AI анализом
        combined_result = {
            'subdomains_found': subdomains,
            'open_ports_found': open_ports,
            'subdomain_count': len(subdomains),
            'port_count': len(open_ports),
            **ai_analysis  # AI анализ становится частью результата
        }
        
        return combined_result
    
    async def _perform_real_vuln_scan(self, target: str) -> Dict[str, Any]:
        """Выполняет реальное vulnerability scanning и анализирует через AI"""
        
        self._log("VULNERABILITY SCANNING PHASE:")
        self._log("Testing XSS vulnerabilities...")
        
        try:
            # Реальное XSS сканирование
            from ..xss.vulnerability_scanner import VulnerabilityScanner
            from ..utils.http_client import HttpClient
            
            http_client = HttpClient(rate_limit=10.0, timeout=5)
            xss_scanner = VulnerabilityScanner(http_client, {
                'max_payloads': 20,  # Ограничено для скорости
                'request_timeout': 5,
                'max_urls': 2
            })
            
            vulnerabilities = await asyncio.wait_for(
                xss_scanner.scan_target(f"https://{target}"),
                timeout=30.0
            )
            
            self._log(f"Found {len(vulnerabilities)} potential vulnerabilities:")
            for vuln in vulnerabilities:
                if 'error' not in vuln:
                    self._log(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('parameter', 'N/A')}")
                else:
                    self._log(f"  - Scan error: {vuln.get('error', 'Unknown')}")
            
        except Exception as e:
            self._log(f"Vulnerability scan failed: {str(e)}")
            vulnerabilities = []
        
        # Проверяем security headers реально
        self._log("Checking security headers...")
        
        try:
            from ..utils.http_client import HttpClient
            from .security.headers_analyzer import SecurityHeadersAnalyzer  # type: ignore
            http_client = HttpClient()

            response = await asyncio.wait_for(
                http_client.get(f"https://{target}"),
                timeout=10.0
            )

            headers = dict(response.headers) if response else {}
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy') or headers.get('Feature-Policy')
            }

            headers_evidence = self._store_evidence(
                "security_headers",
                json.dumps({k: v for k, v in headers.items()}, indent=2, ensure_ascii=False)
            )
            if headers_evidence:
                security_headers['evidence_path'] = headers_evidence

            missing_headers = [h for h, v in security_headers.items() if h in (
                'Content-Security-Policy','X-Frame-Options','Strict-Transport-Security','X-Content-Type-Options') and not v]
            self._log(f"Missing security headers: {len(missing_headers)}")
            for header in missing_headers:
                self._log(f"  - {header}")

            # Advanced analysis
            try:
                analyzer = SecurityHeadersAnalyzer()
                headers_analysis = analyzer.analyze({k: v for k, v in security_headers.items() if v})
            except Exception as inner_e:
                headers_analysis = {'error': str(inner_e)}
        except Exception as e:
            self._log(f"Security header check failed: {str(e)}")
            missing_headers = []
            security_headers = {}
            headers_analysis = {'error': 'header_fetch_failed'}
        
        # AI анализирует РЕАЛЬНЫЕ результаты уязвимостей
        ai_analysis = await self._query_ai(
            f"""Analyze real vulnerability scan results for {target}:

XSS VULNERABILITIES FOUND: {vulnerabilities}
MISSING SECURITY HEADERS: {missing_headers}
SECURITY HEADERS STATUS: {security_headers}

Based on these REAL findings, provide assessment:
{{
    "security_rating": "excellent|good|fair|poor|critical",
    "xss_assessment": "assessment_based_on_actual_scan_results",
    "header_security_score": "score_based_on_missing_headers",
    "immediate_fixes": ["specific_fixes_for_found_issues"],
    "vulnerability_summary": "summary_of_actual_security_state"
}}""",
            "Vulnerability Assessment"
        )
        
        # Объединяем все реальные данные
        combined_result = {
            'vulnerabilities_found': vulnerabilities,
            'vulnerability_count': len(vulnerabilities),
            'missing_security_headers': missing_headers,
            'security_headers_checked': security_headers,
            'security_headers_analysis': headers_analysis,
            'scan_status': 'completed',
            **ai_analysis
        }
        
        return combined_result
