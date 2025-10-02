from __future__ import annotations

from typing import Any, Dict, List


def sarif_severity_mapping(severity: str) -> str:
    mapping = {
        'low': 'note',
        'medium': 'warning',
        'high': 'error',
        'critical': 'error',
    }
    return mapping.get(severity, 'warning')


def remediation_guidance(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    context_type = vulnerability.get('context', {}).get('type', 'html')
    remediation = {
        'summary': 'Implement proper input validation and output encoding',
        'details': []
    }
    if context_type == 'html':
        remediation['details'].extend([
            'HTML encode all user input before output',
            'Use Content Security Policy (CSP) headers',
            'Validate input against whitelist of allowed characters',
        ])
    elif context_type == 'javascript':
        remediation['details'].extend([
            'JavaScript encode user input in script contexts',
            'Avoid dynamic script generation with user input',
            'Use safe DOM manipulation methods',
        ])
    elif context_type == 'css':
        remediation['details'].extend([
            'CSS encode user input in style contexts',
            'Avoid CSS expressions and dynamic styles',
            'Validate CSS properties against whitelist',
        ])
    elif context_type == 'uri':
        remediation['details'].extend([
            'URL encode user input in URI contexts',
            'Validate URLs against whitelist of allowed schemes',
            'Use relative URLs when possible',
        ])
    return remediation
