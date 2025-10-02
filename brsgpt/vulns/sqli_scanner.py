# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
SQL Injection Scanner

Comprehensive SQL injection detection with:
- Error-based detection
- Boolean-based blind detection
- Time-based blind detection
- Union-based detection
- Database fingerprinting
"""

import asyncio
import re
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime

from ..utils.http_client import HttpClient


class SQLiScanner:
    """SQL Injection vulnerability scanner."""

    def __init__(self, http_client: HttpClient, settings: Dict[str, Any]):
        """
        Initialize SQLi scanner.
        
        Args:
            http_client: HTTP client for requests
            settings: Scanner settings
        """
        self.http_client = http_client
        self.settings = settings
        self.timeout = settings.get('request_timeout', 15)
        self.max_tests_per_param = settings.get('max_sqli_tests', 20)

        # SQL error patterns for different databases
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            
            # PostgreSQL
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            
            # MSSQL
            r"Driver.*?SQL[\-\_\ ]*Server",
            r"OLE DB.*?SQL Server",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Native Client error",
            r"SqlClient\.SqlException",
            
            # Oracle
            r"ORA-[0-9]{4,5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_.*",
            
            # SQLite
            r"SQLite\/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            
            # Generic
            r"syntax error",
            r"unclosed quotation mark",
            r"unexpected end of SQL command",
        ]

        # SQL injection test payloads
        self.test_payloads = {
            'error_based': [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1--", "\" OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
            ],
            'boolean_based': [
                "' AND '1'='1", "' AND '1'='2",
                "' OR '1'='1", "' OR '1'='2",
                " AND 1=1", " AND 1=2",
                " OR 1=1", " OR 1=2",
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
                "'; SELECT SLEEP(5)--",  # MySQL
                "'; SELECT pg_sleep(5)--",  # PostgreSQL
                " AND SLEEP(5)",
                " OR SLEEP(5)",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                " UNION SELECT NULL--",
            ]
        }

    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Scan target for SQL injection vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of discovered SQL injection vulnerabilities
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
        Test a specific parameter for SQL injection.
        
        Args:
            base_url: Base URL
            param_name: Parameter name
            param_value: Original parameter value
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        # Get baseline response
        baseline = await self._get_baseline_response(base_url)
        if not baseline:
            return vulnerabilities

        # Test error-based SQLi
        error_vuln = await self._test_error_based(base_url, param_name, param_value, baseline)
        if error_vuln:
            vulnerabilities.append(error_vuln)

        # Test boolean-based blind SQLi
        boolean_vuln = await self._test_boolean_based(base_url, param_name, param_value, baseline)
        if boolean_vuln:
            vulnerabilities.append(boolean_vuln)

        # Test time-based blind SQLi
        time_vuln = await self._test_time_based(base_url, param_name, param_value)
        if time_vuln:
            vulnerabilities.append(time_vuln)

        # Test union-based SQLi
        union_vuln = await self._test_union_based(base_url, param_name, param_value, baseline)
        if union_vuln:
            vulnerabilities.append(union_vuln)

        return vulnerabilities

    async def _get_baseline_response(self, url: str) -> Optional[Dict[str, Any]]:
        """Get baseline response for comparison."""
        try:
            response = await self.http_client.get(url)
            if not response:
                return None
            
            return {
                'status': response.status,
                'body': await response.text(),
                'length': len(await response.text())
            }
        except Exception:
            return None

    async def _test_error_based(self, base_url: str, param_name: str, 
                                param_value: str, baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for error-based SQL injection."""
        for payload in self.test_payloads['error_based'][:self.max_tests_per_param]:
            try:
                test_url = self._inject_payload(base_url, param_name, payload)
                response = await self.http_client.get(test_url)
                
                if not response:
                    continue

                body = await response.text()
                
                # Check for SQL error patterns
                for pattern in self.error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        return {
                            'type': 'sqli_error_based',
                            'severity': 'critical',
                            'confidence': 0.95,
                            'url': base_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': self._extract_error_evidence(body, pattern),
                            'cwe': 'CWE-89',
                            'owasp': 'A03:2021 - Injection',
                            'impact': 'Allows attacker to manipulate database queries',
                            'timestamp': datetime.utcnow().isoformat(),
                            'detection_method': 'error_based',
                            'remediation': {
                                'summary': 'Use parameterized queries and input validation',
                                'details': [
                                    'Use parameterized queries (prepared statements)',
                                    'Validate and sanitize all user input',
                                    'Implement least privilege database access',
                                    'Use Web Application Firewall (WAF)',
                                    'Enable database activity monitoring'
                                ]
                            }
                        }
            
            except Exception:
                continue

        return None

    async def _test_boolean_based(self, base_url: str, param_name: str,
                                  param_value: str, baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for boolean-based blind SQL injection."""
        try:
            # Test with TRUE condition
            true_payload = "' AND '1'='1"
            true_url = self._inject_payload(base_url, param_name, param_value + true_payload)
            true_response = await self.http_client.get(true_url)
            
            if not true_response:
                return None

            true_body = await true_response.text()
            true_length = len(true_body)

            # Test with FALSE condition
            false_payload = "' AND '1'='2"
            false_url = self._inject_payload(base_url, param_name, param_value + false_payload)
            false_response = await self.http_client.get(false_url)
            
            if not false_response:
                return None

            false_body = await false_response.text()
            false_length = len(false_body)

            # Compare responses
            if abs(true_length - false_length) > 100:  # Significant difference
                return {
                    'type': 'sqli_boolean_blind',
                    'severity': 'high',
                    'confidence': 0.80,
                    'url': base_url,
                    'parameter': param_name,
                    'payload': true_payload,
                    'method': 'GET',
                    'evidence': f'TRUE response: {true_length} bytes, FALSE response: {false_length} bytes',
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection',
                    'impact': 'Allows attacker to extract data through boolean queries',
                    'timestamp': datetime.utcnow().isoformat(),
                    'detection_method': 'boolean_blind',
                    'remediation': {
                        'summary': 'Use parameterized queries and input validation',
                        'details': [
                            'Use parameterized queries (prepared statements)',
                            'Validate and sanitize all user input',
                            'Implement proper error handling',
                            'Avoid revealing application behavior differences'
                        ]
                    }
                }

        except Exception:
            pass

        return None

    async def _test_time_based(self, base_url: str, param_name: str, 
                              param_value: str) -> Optional[Dict[str, Any]]:
        """Test for time-based blind SQL injection."""
        for payload in self.test_payloads['time_based'][:5]:  # Limit time-based tests
            try:
                test_url = self._inject_payload(base_url, param_name, param_value + payload)
                
                start_time = time.time()
                response = await asyncio.wait_for(
                    self.http_client.get(test_url),
                    timeout=self.timeout
                )
                elapsed_time = time.time() - start_time

                if elapsed_time >= 4.5:  # Delay detected (5 seconds in payload)
                    return {
                        'type': 'sqli_time_blind',
                        'severity': 'high',
                        'confidence': 0.85,
                        'url': base_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'GET',
                        'evidence': f'Response delayed by {elapsed_time:.2f} seconds',
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection',
                        'impact': 'Allows attacker to extract data through time delays',
                        'timestamp': datetime.utcnow().isoformat(),
                        'detection_method': 'time_blind',
                        'remediation': {
                            'summary': 'Use parameterized queries and input validation',
                            'details': [
                                'Use parameterized queries (prepared statements)',
                                'Validate and sanitize all user input',
                                'Implement query timeouts',
                                'Monitor for suspicious query patterns'
                            ]
                        }
                    }

            except asyncio.TimeoutError:
                # Possible time-based SQLi (with lower confidence)
                return {
                    'type': 'sqli_time_blind',
                    'severity': 'medium',
                    'confidence': 0.60,
                    'url': base_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': 'GET',
                    'evidence': 'Request timeout (possible time-based SQLi)',
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection',
                    'impact': 'Potential time-based SQL injection',
                    'timestamp': datetime.utcnow().isoformat(),
                    'detection_method': 'time_blind_timeout'
                }
            except Exception:
                continue

        return None

    async def _test_union_based(self, base_url: str, param_name: str,
                               param_value: str, baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for union-based SQL injection."""
        for payload in self.test_payloads['union_based'][:self.max_tests_per_param]:
            try:
                test_url = self._inject_payload(base_url, param_name, param_value + payload)
                response = await self.http_client.get(test_url)
                
                if not response:
                    continue

                body = await response.text()
                
                # Check for successful UNION injection indicators
                if 'NULL' in body or response.status == 200:
                    # Further validation needed
                    validation_payload = payload.replace('NULL', "'test'")
                    validation_url = self._inject_payload(base_url, param_name, param_value + validation_payload)
                    validation_response = await self.http_client.get(validation_url)
                    
                    if validation_response and 'test' in await validation_response.text():
                        return {
                            'type': 'sqli_union_based',
                            'severity': 'critical',
                            'confidence': 0.90,
                            'url': base_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': 'UNION injection successful',
                            'cwe': 'CWE-89',
                            'owasp': 'A03:2021 - Injection',
                            'impact': 'Allows attacker to extract data from database',
                            'timestamp': datetime.utcnow().isoformat(),
                            'detection_method': 'union_based',
                            'remediation': {
                                'summary': 'Use parameterized queries and input validation',
                                'details': [
                                    'Use parameterized queries (prepared statements)',
                                    'Validate and sanitize all user input',
                                    'Implement proper database access controls',
                                    'Minimize database error messages'
                                ]
                            }
                        }

            except Exception:
                continue

        return None

    def _inject_payload(self, base_url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _extract_error_evidence(self, body: str, pattern: str) -> str:
        """Extract SQL error evidence from response."""
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 50)
            return body[start:end]
        return "SQL error detected"


__all__ = ['SQLiScanner']

