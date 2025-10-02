# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
OpenAI Analyzer

AI-powered cybersecurity analysis and correlation engine:
- Intelligent correlation of reconnaissance and XSS data
- Risk assessment with business impact analysis
- Attack path discovery and exploitation chains
- Executive summary generation for management
- Security recommendations with prioritization
- Threat intelligence synthesis

Leverages GPT-4 for advanced cybersecurity analysis and insights.
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from openai import AsyncOpenAI
from .openai_prompts import (
    CORRELATION_PROMPT,
    RISK_ASSESSMENT_PROMPT,
    ATTACK_PATH_PROMPT,
    EXECUTIVE_SUMMARY_PROMPT,
)


class OpenAIAnalyzer:
    """AI-powered cybersecurity analysis and correlation engine."""
    
    def __init__(self, api_key: str, settings: Dict[str, Any]):
        """Initialize OpenAI analyzer with client, settings, and prompt templates."""
        self.api_key = api_key
        self.settings = settings

        # Configure OpenAI client
        self.client = AsyncOpenAI(api_key=api_key)

        # Analysis parameters (provided via config/env)
        self.model = settings.get('model')
        self.search_model = settings.get('search_model')
        self.fallback_model = settings.get('fallback_model')
        self.max_tokens = settings.get('max_tokens', 4000)
        self.temperature = settings.get('temperature', 0.1)

        # Analysis prompts moved to dedicated module
        self.correlation_prompt = CORRELATION_PROMPT
        self.risk_assessment_prompt = RISK_ASSESSMENT_PROMPT
        self.attack_path_prompt = ATTACK_PATH_PROMPT
        self.executive_summary_prompt = EXECUTIVE_SUMMARY_PROMPT
    
    async def correlate_data(self, recon_data: Dict[str, Any], 
                           xss_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate reconnaissance and XSS vulnerability data using AI analysis.
        
        Args:
            recon_data: Reconnaissance scan results
            xss_data: XSS vulnerability scan results
            
        Returns:
            Correlated analysis results
        """
        try:
            # Prepare data for analysis
            recon_summary = self._summarize_recon_data(recon_data)
            xss_summary = self._summarize_xss_data(xss_data)
            
            # Create analysis prompt
            prompt = self.correlation_prompt.format(
                recon_data=json.dumps(recon_summary, indent=2),
                xss_data=json.dumps(xss_summary, indent=2)
            )
            
            # Get AI analysis
            response = await self._query_openai(prompt)
            
            # Parse and validate response
            correlation_result = self._parse_json_response(response)
            
            # Add metadata
            correlation_result['analysis_timestamp'] = datetime.utcnow().isoformat()
            from ..version import VERSION
            correlation_result['analyzer_version'] = f'BRS-GPT v{VERSION}'
            correlation_result['model_used'] = self.model
            
            return correlation_result
            
        except Exception as e:
            return {
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }
    
    async def assess_risks(self, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform AI-powered risk assessment based on correlated data.
        
        Args:
            correlation_data: Correlated security data
            
        Returns:
            Risk assessment results
        """
        try:
            # Create risk assessment prompt
            prompt = self.risk_assessment_prompt.format(
                correlation_data=json.dumps(correlation_data, indent=2)
            )
            
            # Get AI analysis
            response = await self._query_openai(prompt)
            
            # Parse response
            risk_assessment = self._parse_json_response(response)
            
            # Add metadata
            risk_assessment['assessment_timestamp'] = datetime.utcnow().isoformat()
            risk_assessment['methodology'] = 'AI-powered risk analysis'
            risk_assessment['confidence_level'] = 'high'
            
            return risk_assessment
            
        except Exception as e:
            return {
                'error': str(e),
                'assessment_timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }
    
    async def discover_attack_paths(self, correlation_data: Dict[str, Any], 
                                  risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Discover potential attack paths using AI analysis.
        
        Args:
            correlation_data: Correlated security data
            risk_assessment: Risk assessment results
            
        Returns:
            Attack path analysis
        """
        try:
            # Combine data for attack path analysis
            assessment_data = {
                'correlation': correlation_data,
                'risks': risk_assessment
            }
            
            # Create attack path prompt
            prompt = self.attack_path_prompt.format(
                assessment_data=json.dumps(assessment_data, indent=2)
            )
            
            # Get AI analysis
            response = await self._query_openai(prompt)
            
            # Parse response
            attack_paths = self._parse_json_response(response)
            
            # Add metadata
            attack_paths['analysis_timestamp'] = datetime.utcnow().isoformat()
            attack_paths['methodology'] = 'AI-powered attack path discovery'
            attack_paths['threat_model'] = 'external attacker with network access'
            
            return attack_paths
            
        except Exception as e:
            return {
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }
    
    async def generate_executive_summary(self, recon_data: Dict[str, Any],
                                       xss_data: Dict[str, Any],
                                       risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary for leadership.
        
        Args:
            recon_data: Reconnaissance results
            xss_data: XSS vulnerability results
            risk_assessment: Risk assessment results
            
        Returns:
            Executive summary
        """
        try:
            # Prepare summaries for executive briefing
            recon_summary = self._create_executive_recon_summary(recon_data)
            vuln_summary = self._create_executive_vuln_summary(xss_data)
            risk_summary = self._create_executive_risk_summary(risk_assessment)
            
            # Create executive summary prompt
            prompt = self.executive_summary_prompt.format(
                recon_summary=json.dumps(recon_summary, indent=2),
                vuln_summary=json.dumps(vuln_summary, indent=2),
                risk_summary=json.dumps(risk_summary, indent=2)
            )
            
            # Get AI analysis
            response = await self._query_openai(prompt)
            
            # Parse response
            executive_summary = self._parse_json_response(response)
            
            # Add metadata
            executive_summary['report_timestamp'] = datetime.utcnow().isoformat()
            executive_summary['report_type'] = 'Executive Security Briefing'
            executive_summary['audience'] = 'C-level executives and board members'
            
            return executive_summary
            
        except Exception as e:
            return {
                'error': str(e),
                'report_timestamp': datetime.utcnow().isoformat(),
                'status': 'failed'
            }

    async def generate_rationale(self, correlated_data: Dict[str, Any]) -> str:
        """
        Produce a concise AI rationale (1-2 sentences) explaining overall risk posture.
        Returns plain text extracted from a short JSON response for reliability.
        """
        try:
            prompt = (
                "You are a security analyst. Given the correlated assessment data, "
                "write a single, business-friendly rationale (1-2 sentences) that explains the current risk posture "
                "and why the findings matter. Respond as JSON: {\"rationale\": \"...\"}.\n\n"
                f"DATA:\n{json.dumps(correlated_data)[:4000]}"
            )
            response = await self._query_openai(prompt)
            parsed = self._parse_json_response(response)
            rationale = parsed.get('rationale')
            if isinstance(rationale, str) and rationale.strip():
                return rationale.strip()
        except Exception:
            pass
        return "AI rationale unavailable."
    
    async def _query_openai(self, prompt: str) -> str:
        """
        Query OpenAI API with retry logic. Tries JSON mode first for robust parsing,
        then falls back to standard mode if the model doesn't support it.
        """
        max_retries = 3
        retry_delay = 1
        use_json_mode = True

        active_model = self.model
        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": active_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a senior cybersecurity analyst with expertise in vulnerability assessment, risk analysis, and threat modeling. Respond ONLY with valid JSON that matches the requested schema."
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": self.max_tokens,
                }
                
                # Only add temperature for models that support it
                if not ("preview" in active_model or "search" in active_model):
                    kwargs["temperature"] = self.temperature
                if use_json_mode:
                    kwargs["response_format"] = {"type": "json_object"}

                response = await self.client.chat.completions.create(**kwargs)
                return (response.choices[0].message.content or "").strip()

            except Exception:
                # First failure on JSON mode: disable and retry; otherwise backoff
                if use_json_mode:
                    use_json_mode = False
                elif attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                else:
                    # Last-chance: try fallback model once
                    if active_model != self.fallback_model:
                        active_model = self.fallback_model
                        use_json_mode = True
                        # continue loop to retry with fallback
                        continue
                    raise
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON response from OpenAI with error handling.
        
        Args:
            response: Raw response from OpenAI
            
        Returns:
            Parsed JSON data
        """
        try:
            # Try to find JSON in response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                return json.loads(json_str)
            else:
                # Fallback: try to parse entire response
                return json.loads(response)
                
        except json.JSONDecodeError:
            # Return structured error if JSON parsing fails
            return {
                'error': 'Failed to parse AI response as JSON',
                'raw_response': response[:500],  # Truncate for safety
                'status': 'parse_error'
            }
    
    def _summarize_recon_data(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize reconnaissance data for AI analysis."""
        return {
            'subdomains_found': len(recon_data.get('subdomains', [])),
            'key_subdomains': recon_data.get('subdomains', [])[:10],
            'dns_security_issues': len([
                issue for issue in recon_data.get('dns_records', {}).get('security_issues', [])
            ]),
            'open_ports': len(recon_data.get('open_ports', [])),
            'critical_services': [
                port for port in recon_data.get('open_ports', [])
                if port.get('security_notes', {}).get('risk_level') == 'critical'
            ],
            'technologies_detected': recon_data.get('technologies', {}),
            'security_headers_missing': [
                header for header, info in recon_data.get('technologies', {}).get('security_headers', {}).items()
                if not info.get('present', False)
            ]
        }
    
    def _summarize_xss_data(self, xss_data: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize XSS vulnerability data for AI analysis."""
        vulnerabilities = xss_data.get('vulnerabilities', [])
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'high_severity_count': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium_severity_count': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low_severity_count': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'contexts_affected': list(set(v.get('context', {}).get('type') for v in vulnerabilities)),
            'waf_bypasses_found': len([v for v in vulnerabilities if v.get('waf_bypass', False)]),
            'critical_vulnerabilities': [
                {
                    'url': v.get('url'),
                    'parameter': v.get('parameter'),
                    'severity': v.get('severity'),
                    'context': v.get('context', {}).get('type')
                }
                for v in vulnerabilities if v.get('severity') == 'high'
            ][:5]
        }
    
    def _create_executive_recon_summary(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive-level reconnaissance summary."""
        return {
            'attack_surface_size': len(recon_data.get('subdomains', [])) + len(recon_data.get('open_ports', [])),
            'critical_exposures': len([
                port for port in recon_data.get('open_ports', [])
                if port.get('security_notes', {}).get('risk_level') in ['critical', 'high']
            ]),
            'technology_risks': len(recon_data.get('technologies', {})),
            'dns_security_score': self._calculate_dns_security_score(recon_data.get('dns_records', {}))
        }
    
    def _create_executive_vuln_summary(self, xss_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive-level vulnerability summary."""
        vulnerabilities = xss_data.get('vulnerabilities', [])
        
        return {
            'total_security_issues': len(vulnerabilities),
            'critical_issues': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'immediate_threats': len([v for v in vulnerabilities if v.get('confidence', 0) > 0.8]),
            'compliance_impact': 'High' if any(v.get('severity') == 'high' for v in vulnerabilities) else 'Medium'
        }
    
    def _create_executive_risk_summary(self, risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive-level risk summary."""
        return {
            'overall_risk_level': risk_assessment.get('overall_risk_score', 0),
            'business_impact_areas': len(risk_assessment.get('business_impact', {})),
            'immediate_actions_required': len(risk_assessment.get('mitigation_timeline', {}).get('immediate', [])),
            'regulatory_concerns': len(risk_assessment.get('compliance_concerns', []))
        }
    
    def _calculate_dns_security_score(self, dns_data: Dict[str, Any]) -> int:
        """Calculate DNS security score (0-100)."""
        score = 100
        
        # Deduct points for security issues
        security_issues = dns_data.get('security_issues', [])
        score -= len(security_issues) * 10
        
        # Deduct points for missing DNSSEC
        if dns_data.get('dnssec_status') == 'disabled':
            score -= 20
        
        # Deduct points for poor mail security
        mail_score = dns_data.get('mail_config', {}).get('security_score', 100)
        if mail_score < 50:
            score -= 15
        
        return max(0, min(100, score))
