# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Report Generator

Professional cybersecurity report generation with multiple formats:
- Interactive HTML reports with executive dashboard
- Machine-readable JSON reports for automation
- SARIF-compliant reports for CI/CD integration
- Executive PDF summaries for leadership
- Detailed technical appendices for security teams

Generates enterprise-grade reports with visual analytics and actionable insights.
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import base64
from jinja2 import Template
from ..version import VERSION
from .reporting import (
    HTML_TEMPLATE,
    prepare_html_template_data,
    calculate_scan_duration,
    calculate_payload_success_rate,
    generate_sarif_rules,
    convert_to_sarif_result,
)


class ReportGenerator:
    """Professional cybersecurity report generator with multiple output formats."""
    
    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize report generator.
        
        Args:
            settings: Output settings and preferences
        """
        self.settings = settings
        self.output_format = settings.get('format', 'html')
        self.include_raw_data = settings.get('include_raw_data', False)
        self.show_false_positives = settings.get('show_false_positives', False)
        
        # HTML report template moved to reporting submodule
        self.html_template = HTML_TEMPLATE
    
    async def generate_html_report(self, analysis_results: Dict[str, Any], 
                                 output_file: str) -> Optional[str]:
        """
        Generate comprehensive HTML report.
        
        Args:
            analysis_results: Complete analysis results
            output_file: Output file path
            
        Returns:
            Path to generated report
        """
        try:
            # Extract data for template and enrich with deterministic risk model if available
            template_data = self._prepare_html_template_data(analysis_results)
            risk = analysis_results.get('risk_model') or {}
            if risk:
                template_data['det_risk_score'] = risk.get('risk_score') or risk.get('aggregate_score')
                template_data['det_security_posture'] = risk.get('security_posture')
                template_data['det_summary'] = risk.get('summary')
                template_data['det_immediate_actions'] = (risk.get('remediation_plan') or {}).get('immediate', [])
                template_data['risk_model_remediation_short'] = (risk.get('remediation_plan') or {}).get('short_term', [])
                template_data['risk_model_remediation_long'] = (risk.get('remediation_plan') or {}).get('long_term', [])
            template = Template(self.html_template)
            html_content = template.render(**template_data)
            
            # Write to file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return str(output_path.absolute())
            
        except Exception as e:
            return None
    
    def _prepare_html_template_data(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template rendering."""
        try:
            return prepare_html_template_data(analysis_results)
        except Exception as e:
            # Return minimal template data if preparation fails
            return {
                'target_domain': analysis_results.get('target', 'Unknown'),
                'scan_date': 'Unknown',
                'ai_model': 'disabled',
                'ai_enabled': False,
                'ai_rationale': '',
                'executive_summary': {'security_posture_rating': 'Unknown', 'executive_overview': 'Report generation error'},
                'overall_risk_score': 5,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'subdomains_found': 0,
                'open_ports': 0,
                'critical_findings': [],
                'xss_vulnerabilities': [],
                'attack_scenarios': [],
                'immediate_actions': [],
                'strategic_recommendations': [],
                'include_technical_details': False,
                'recon_summary': {},
                'xss_summary': {'contexts_affected': [], 'waf_bypasses_found': 0},
                'dnssec_status_badge': 'badge-medium',
                'payload_success_rate': 0,
                'report_timestamp': 'Unknown',
            }
    
    async def generate_json_report(self, analysis_results: Dict[str, Any], 
                                 output_file: str) -> Optional[str]:
        """
        Generate machine-readable JSON report.
        
        Args:
            analysis_results: Complete analysis results
            output_file: Output file path
            
        Returns:
            Path to generated report
        """
        try:
            # Prepare JSON report structure
            json_report = {
                'report_metadata': {
                    'generator': f'BRS-GPT v{VERSION}',
                    'company': 'EasyProTech LLC',
                    'contact': 'https://t.me/easyprotech',
                    'report_timestamp': datetime.utcnow().isoformat(),
                    'report_type': 'cybersecurity_assessment',
                    'target': analysis_results.get('target'),
                    'scan_duration': self._calculate_scan_duration(analysis_results)
                },
                'executive_summary': analysis_results.get('ai_analysis', {}).get('executive_summary', {}),
                'risk_assessment': analysis_results.get('ai_analysis', {}).get('risk_assessment', {}),
                'reconnaissance_results': analysis_results.get('recon_data', {}),
                'vulnerability_results': analysis_results.get('xss_data', {}),
                'security_headers': analysis_results.get('xss_data', {}).get('security_headers_analysis', {}),
                'attack_path_analysis': analysis_results.get('ai_analysis', {}).get('attack_paths', {}),
                'correlation_analysis': analysis_results.get('ai_analysis', {}).get('correlation', {}),
                'technical_metadata': {
                    'scan_start_time': analysis_results.get('start_time'),
                    'scan_end_time': analysis_results.get('end_time'),
                    'scanner_version': f'BRS-GPT v{VERSION}',
                    'methodology': 'AI + deterministic risk modeling'
                }
            }

            # Append deterministic risk model section if present
            if analysis_results.get('risk_model'):
                json_report['deterministic_risk_model'] = analysis_results['risk_model']

            if self.include_raw_data:
                json_report['raw_data'] = analysis_results

            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, default=str)
            return str(output_path.absolute())

        except Exception:
            return None
    
    async def generate_sarif_report(self, analysis_results: Dict[str, Any], 
                                  output_file: str) -> Optional[str]:
        """
        Generate SARIF-compliant report for CI/CD integration.
        
        Args:
            analysis_results: Complete analysis results
            output_file: Output file path
            
        Returns:
            Path to generated report
        """
        try:
            vulnerabilities = analysis_results.get('xss_data', {}).get('vulnerabilities', [])
            risk_model = analysis_results.get('risk_model') or {}
            components = risk_model.get('components', {}) if isinstance(risk_model, dict) else {}
            missing_headers = components.get('missing_headers', []) if isinstance(components, dict) else []
            high_risk_ports = components.get('high_risk_ports', []) if isinstance(components, dict) else []
            
            # Create SARIF structure
            sarif_report = {
                "version": "2.1.0",
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "BRS-GPT",
                                "version": "1.0.0",
                                "informationUri": "https://www.easypro.tech",
                                "organization": "EasyProTech LLC",
                                "rules": self._generate_sarif_rules()
                            }
                        },
                        "results": [],
                        "properties": {
                            "scanStartTime": analysis_results.get('start_time'),
                            "scanEndTime": analysis_results.get('end_time'),
                            "targetUrl": analysis_results.get('target')
                        }
                    }
                ]
            }
            
            # Convert vulnerabilities to SARIF results
            for vuln in vulnerabilities:
                if vuln.get('type') == 'xss_vulnerability':
                    sarif_report["runs"][0]["results"].append(self._convert_to_sarif_result(vuln))

            # Add missing security headers as SARIF results
            for header in missing_headers:
                sarif_report["runs"][0]["results"].append(self._convert_to_sarif_result({
                    'type': 'missing_security_header',
                    'header': header,
                    'sarif_rule_id': 'HDR001',
                    'sarif_level': 'warning',
                    'description': f'Missing recommended security header {header}',
                    'timestamp': datetime.utcnow().isoformat(),
                }))

            # Add risky service exposure results
            for port in high_risk_ports:
                sarif_report["runs"][0]["results"].append(self._convert_to_sarif_result({
                    'type': 'risky_service_exposure',
                    'port': port,
                    'sarif_rule_id': 'PORT001',
                    'sarif_level': 'note',
                    'description': f'Potentially risky service port {port} exposed',
                    'timestamp': datetime.utcnow().isoformat(),
                }))
            
            # Write SARIF file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_report, f, indent=2)
            
            return str(output_path.absolute())
            
        except Exception as e:
            return None
    
    
    def _generate_sarif_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rules for XSS vulnerabilities."""
        return generate_sarif_rules()
    
    def _convert_to_sarif_result(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Convert vulnerability to SARIF result format."""
        return convert_to_sarif_result(vulnerability)
    
    def _calculate_scan_duration(self, analysis_results: Dict[str, Any]) -> str:
        """Calculate scan duration in human-readable format."""
        return calculate_scan_duration(analysis_results)
    
    def _calculate_payload_success_rate(self, xss_data: Dict[str, Any]) -> int:
        """Calculate payload success rate percentage."""
        return calculate_payload_success_rate(xss_data)

