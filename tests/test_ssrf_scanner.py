# BRS-GPT: AI-Enhanced Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for SSRF Scanner."""

import pytest
from brsgpt.vulns.ssrf_scanner import SSRFScanner
from brsgpt.utils.http_client import HttpClient


def test_ssrf_scanner_initialization():
    """Test SSRF scanner initializes correctly."""
    settings = {'request_timeout': 15, 'max_ssrf_tests': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SSRFScanner(client, settings)
    
    assert scanner.timeout == 15
    assert scanner.max_tests_per_param == 15
    assert 'localhost' in scanner.test_payloads
    assert 'internal_ips' in scanner.test_payloads
    assert 'cloud_metadata' in scanner.test_payloads
    assert 'protocol_smuggling' in scanner.test_payloads
    assert 'bypasses' in scanner.test_payloads


def test_ssrf_scanner_has_cloud_metadata_payloads():
    """Test SSRF scanner has cloud metadata payloads."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SSRFScanner(client, settings)
    
    cloud_payloads = scanner.test_payloads['cloud_metadata']
    
    # AWS metadata
    assert any('169.254.169.254' in p for p in cloud_payloads)
    
    # Check for metadata endpoints
    assert any('meta-data' in p or 'metadata' in p for p in cloud_payloads)


def test_ssrf_severity_assessment():
    """Test SSRF severity assessment logic."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SSRFScanner(client, settings)
    
    # Cloud metadata should be critical
    assert scanner._assess_severity('cloud_metadata', 'ami-id') == 'critical'
    
    # File disclosure should be critical
    assert scanner._assess_severity('protocol_smuggling', 'root:') == 'critical'
    
    # Localhost should be high
    assert scanner._assess_severity('localhost', 'test') == 'high'


def test_ssrf_impact_descriptions():
    """Test SSRF impact descriptions."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SSRFScanner(client, settings)
    
    assert 'cloud metadata' in scanner._get_impact_description('cloud_metadata').lower()
    assert 'internal' in scanner._get_impact_description('internal_ips').lower()
    assert 'localhost' in scanner._get_impact_description('localhost').lower()


def test_ssrf_payload_injection():
    """Test SSRF payload injection into URL."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = SSRFScanner(client, settings)
    
    base_url = "http://example.com/fetch?url=http://normal.com"
    injected = scanner._inject_payload(base_url, 'url', 'http://localhost')
    
    assert "url=http" in injected
    assert "example.com/fetch" in injected


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

