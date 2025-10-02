# BRS-GPT: AI-Enhanced Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for XXE Scanner."""

import pytest
from brsgpt.vulns.xxe_scanner import XXEScanner
from brsgpt.utils.http_client import HttpClient


def test_xxe_scanner_initialization():
    """Test XXE scanner initializes correctly."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = XXEScanner(client, settings)
    
    assert scanner.timeout == 15
    assert len(scanner.test_payloads) > 0
    assert len(scanner.xxe_indicators) > 0
    assert 'basic_file_disclosure' in scanner.test_payloads
    assert 'billion_laughs' in scanner.test_payloads


def test_xxe_scanner_has_payloads():
    """Test XXE scanner has required payload types."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = XXEScanner(client, settings)
    
    expected_payloads = [
        'basic_file_disclosure',
        'windows_file_disclosure',
        'ssrf_via_xxe',
        'parameter_entity',
        'billion_laughs',
        'simple_xxe'
    ]
    
    for payload_type in expected_payloads:
        assert payload_type in scanner.test_payloads
        assert '<?xml' in scanner.test_payloads[payload_type]
        assert 'DOCTYPE' in scanner.test_payloads[payload_type]


def test_xxe_severity_assessment():
    """Test XXE severity assessment."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = XXEScanner(client, settings)
    
    # File disclosure should be critical
    assert scanner._assess_severity('basic_file_disclosure', 'root:') == 'critical'
    
    # SSRF via XXE should be critical
    assert scanner._assess_severity('ssrf_via_xxe', 'ami-id') == 'critical'
    
    # Billion laughs should be high
    assert scanner._assess_severity('billion_laughs', 'test') == 'high'


def test_xxe_impact_descriptions():
    """Test XXE impact descriptions."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = XXEScanner(client, settings)
    
    assert 'file' in scanner._get_impact_description('basic_file_disclosure').lower()
    assert 'windows' in scanner._get_impact_description('windows_file_disclosure').lower()
    assert 'ssrf' in scanner._get_impact_description('ssrf_via_xxe').lower()
    assert 'denial of service' in scanner._get_impact_description('billion_laughs').lower()


def test_xxe_extract_evidence():
    """Test XXE evidence extraction."""
    settings = {'request_timeout': 15}
    client = HttpClient(rate_limit=10.0, timeout=15)
    scanner = XXEScanner(client, settings)
    
    body = "Some response with root:x:0:0:root:/root:/bin/bash in the middle"
    pattern = r'root:.*:/bin/'
    
    evidence = scanner._extract_evidence(body, pattern)
    
    assert len(evidence) > 0
    assert 'root:' in evidence


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

