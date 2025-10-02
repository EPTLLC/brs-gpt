from __future__ import annotations

import re
from typing import Any, Dict, List


def is_executable_xss(payload: str, response_body: str, context: Dict[str, Any], xss_indicators: List[str]) -> bool:
    for indicator_pattern in xss_indicators:
        if re.search(indicator_pattern, response_body, re.IGNORECASE):
            return True

    context_type = context.get('type', 'html')

    if context_type == 'html':
        lowered = payload.lower()
        if '<script' in lowered or any(evt in lowered for evt in ['onerror', 'onload', 'onclick', 'onfocus']):
            return True
        return ('"' in payload or "'" in payload) and ('<' in payload or '>' in payload)

    elif context_type == 'javascript':
        js_patterns = ['alert(', 'prompt(', 'confirm(', 'eval(', 'Function(']
        return any(pattern in payload for pattern in js_patterns)

    elif context_type == 'css':
        lowered = payload.lower()
        if 'expression(' in lowered:
            return True
        if 'url(' in lowered or '@import' in lowered:
            return ('javascript:' in lowered) or ('data:' in lowered)
        return False

    elif context_type == 'svg':
        lowered = payload.lower()
        return (
            '<script' in lowered or
            'onload' in lowered or 'onbegin' in lowered or
            ('href' in lowered and ('javascript:' in lowered or 'data:' in lowered))
        )

    elif context_type == 'uri':
        return ('javascript:' in payload.lower()) or ('data:' in payload.lower())

    return False


def calculate_severity(payload_info: Dict[str, Any], context: Dict[str, Any]) -> str:
    base_severity = 'medium'
    dangerous_contexts = ['javascript', 'svg', 'html']
    if context.get('type') in dangerous_contexts:
        base_severity = 'high'
    if payload_info.get('effectiveness_score', 0) > 0.8:
        base_severity = 'high'
    payload = payload_info.get('payload', '')
    if any(dangerous in payload.lower() for dangerous in ['document.', 'window.', 'eval(']):
        base_severity = 'high'
    return base_severity


def calculate_confidence(payload: str, response_body: str, context: Dict[str, Any], xss_indicators: List[str]) -> float:
    confidence = 0.5
    if payload in response_body:
        confidence += 0.3
    if context.get('type') != 'unknown':
        confidence += 0.2
    indicator_count = sum(1 for pattern in xss_indicators if re.search(pattern, response_body, re.IGNORECASE))
    confidence += min(indicator_count * 0.1, 0.3)
    return min(confidence, 1.0)


def assess_impact(context: Dict[str, Any], payload_info: Dict[str, Any]) -> str:
    context_type = context.get('type', 'html')
    high_impact_contexts = ['javascript', 'html']
    if context_type in high_impact_contexts:
        return 'High - Full JavaScript execution possible'
    elif context_type == 'css':
        return 'Medium - CSS-based attacks possible'
    elif context_type == 'uri':
        return 'Medium - URL-based attacks possible'
    else:
        return 'Low - Limited attack vectors'


def extract_evidence(payload: str, response_body: str, xss_indicators: List[str]) -> Dict[str, Any]:
    evidence = {
        'payload_reflected': payload in response_body,
        'reflection_count': response_body.count(payload),
        'xss_indicators': []
    }
    for pattern in xss_indicators:
        matches = re.findall(pattern, response_body, re.IGNORECASE)
        if matches:
            evidence['xss_indicators'].extend(matches)
    return evidence


def deduplicate_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique_vulnerabilities: List[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        key = (
            vuln.get('url', ''),
            vuln.get('parameter', ''),
            vuln.get('context', {}).get('type', ''),
            vuln.get('severity', ''),
        )
        if key not in seen:
            seen.add(key)
            unique_vulnerabilities.append(vuln)
    return unique_vulnerabilities
