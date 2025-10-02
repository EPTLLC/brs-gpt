# BRS-GPT: AI-Enhanced Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for SQLi Scanner."""

import pytest
from brsgpt.vulns.sqli_scanner import SQLiScanner
from brsgpt.utils.http_client import HttpClient


def test_sqli_scanner_initialization():
    """Test SQLi scanner initializes correctly."""
    settings = {'request_timeout': 15, 'max_sqli_tests': 20}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SQLiScanner(client, settings)
    
    assert scanner.timeout == 15
    assert scanner.max_tests_per_param == 20
    assert len(scanner.error_patterns) > 0
    assert 'error_based' in scanner.test_payloads
    assert 'boolean_based' in scanner.test_payloads
    assert 'time_based' in scanner.test_payloads
    assert 'union_based' in scanner.test_payloads


def test_sqli_scanner_has_database_patterns():
    """Test SQLi scanner has patterns for different databases."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SQLiScanner(client, settings)
    
    patterns_text = '|'.join(scanner.error_patterns)
    
    # Check for MySQL patterns
    assert 'MySQL' in patterns_text or 'mysql' in patterns_text
    
    # Check for PostgreSQL patterns
    assert 'PostgreSQL' in patterns_text or 'pg_' in patterns_text
    
    # Check for MSSQL patterns
    assert 'SQL Server' in patterns_text or 'SqlClient' in patterns_text


def test_sqli_payload_injection():
    """Test payload injection into URL."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SQLiScanner(client, settings)
    
    base_url = "http://example.com/page?id=1"
    injected = scanner._inject_payload(base_url, 'id', "1' OR '1'='1")
    
    assert "id=1%27+OR+%271%27%3D%271" in injected or "1' OR '1'='1" in injected
    assert "http://example.com/page" in injected


def test_sqli_extract_evidence():
    """Test evidence extraction from SQL errors."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SQLiScanner(client, settings)
    
    body = "Some text before MySQL syntax error near 'test' at line 1 and text after"
    pattern = r"MySQL syntax"
    
    evidence = scanner._extract_error_evidence(body, pattern)
    
    assert len(evidence) > 0
    assert 'MySQL' in evidence


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

