from __future__ import annotations

from typing import Any, Dict, List


def generate_sarif_rules() -> List[Dict[str, Any]]:
    return [
        {
            "id": "XSS001",
            "name": "CrossSiteScripting",
            "shortDescription": {"text": "Cross-Site Scripting (XSS) vulnerability detected"},
            "fullDescription": {"text": "Cross-Site Scripting vulnerability enabling JavaScript injection."},
            "help": {"text": "Implement output encoding, CSP, and input validation."},
            "properties": {"category": "security", "precision": "high", "tags": ["security", "xss", "injection"]},
        },
        {
            "id": "HDR001",
            "name": "MissingSecurityHeader",
            "shortDescription": {"text": "Missing critical security HTTP header"},
            "fullDescription": {"text": "A recommended security HTTP response header is absent, reducing defense-in-depth."},
            "help": {"text": "Add the missing header with secure directives (e.g., CSP, HSTS, X-Frame-Options)."},
            "properties": {"category": "security", "precision": "medium", "tags": ["headers", "hardening", "security"]},
        },
        {
            "id": "PORT001",
            "name": "RiskyServiceExposure",
            "shortDescription": {"text": "Potentially risky service port exposed"},
            "fullDescription": {"text": "An exposed network service port commonly targeted or historically vulnerable."},
            "help": {"text": "Restrict exposure, enforce authentication, or disable unused service."},
            "properties": {"category": "security", "precision": "medium", "tags": ["network", "exposure", "ports"]},
        },
    ]


def convert_to_sarif_result(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    v_type = vulnerability.get('type', 'xss_vulnerability')
    if v_type == 'missing_security_header':
        rule_id = 'HDR001'
        message = f"Missing security header: {vulnerability.get('header')}"
    elif v_type == 'risky_service_exposure':
        rule_id = 'PORT001'
        message = f"Risky service port exposed: {vulnerability.get('port')}"
    else:
        rule_id = vulnerability.get("sarif_rule_id", "XSS001")
        message = f"XSS vulnerability in parameter '{vulnerability.get('parameter')}'"

    return {
        "ruleId": rule_id,
        "level": vulnerability.get("sarif_level", "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": vulnerability.get("url", ""),
                        "description": {"text": vulnerability.get('description', message)},
                    }
                }
            }
        ],
        "properties": {
            "severity": vulnerability.get("severity"),
            "confidence": vulnerability.get("confidence"),
            "context": vulnerability.get("context"),
            "payload": vulnerability.get("payload"),
            "method": vulnerability.get("method"),
            "impact": vulnerability.get("impact"),
            "cwe": vulnerability.get("cwe"),
            "owasp": vulnerability.get("owasp"),
            "scanner": vulnerability.get("scanner"),
            "timestamp": vulnerability.get("timestamp"),
        },
        "fixes": [
            {
                "description": {
                    "text": vulnerability.get("remediation", {}).get("summary", "Apply recommended security hardening")
                }
            }
        ],
    }
