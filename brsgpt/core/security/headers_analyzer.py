"""Advanced Security Headers Analyzer for BRS-GPT.

Parses and evaluates HTTP response security headers:
- Content-Security-Policy (basic directive quality score)
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy (report if missing or too permissive)

Outputs structured findings consumable by risk model & reporting.
"""
from __future__ import annotations
from typing import Dict, Any, List
import re

CSP_KEY_DIRECTIVES = [
    'default-src', 'script-src', 'object-src', 'base-uri', 'frame-ancestors'
]

class SecurityHeadersAnalyzer:
    def analyze(self, headers: Dict[str, str]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        score_components: Dict[str, int] = {}
        csp = headers.get('Content-Security-Policy')
        if csp:
            csp_score, csp_findings = self._score_csp(csp)
            score_components['csp'] = csp_score
            findings.extend(csp_findings)
        else:
            findings.append({'type': 'missing_header', 'header': 'Content-Security-Policy', 'impact': 'high', 'recommendation': 'Define a restrictive CSP with script-src nonce/sha256 and disallow unsafe-inline.'})
            score_components['csp'] = 0
        hsts = headers.get('Strict-Transport-Security')
        if hsts:
            if 'max-age=' in hsts and ('includeSubDomains' in hsts or 'includesubdomains' in hsts.lower()):
                score_components['hsts'] = 10
            else:
                score_components['hsts'] = 5
                findings.append({'type': 'weak_header', 'header': 'Strict-Transport-Security', 'detail': hsts, 'recommendation': 'Add includeSubDomains and preload with max-age >= 15552000.'})
        else:
            score_components['hsts'] = 0
            findings.append({'type': 'missing_header', 'header': 'Strict-Transport-Security', 'impact': 'medium', 'recommendation': 'Add HSTS max-age>=15552000; includeSubDomains; preload.'})
        xfo = headers.get('X-Frame-Options')
        if xfo:
            if xfo.upper() in ('DENY', 'SAMEORIGIN'):
                score_components['xfo'] = 8
            else:
                score_components['xfo'] = 3
                findings.append({'type': 'weak_header', 'header': 'X-Frame-Options', 'detail': xfo, 'recommendation': 'Use DENY or SAMEORIGIN.'})
        else:
            score_components['xfo'] = 0
            findings.append({'type': 'missing_header', 'header': 'X-Frame-Options', 'impact': 'low', 'recommendation': 'Add X-Frame-Options: DENY (or SAMEORIGIN if framing required).'})
        xcto = headers.get('X-Content-Type-Options')
        if xcto:
            if xcto.lower() == 'nosniff':
                score_components['xcto'] = 6
            else:
                score_components['xcto'] = 2
                findings.append({'type': 'weak_header', 'header': 'X-Content-Type-Options', 'detail': xcto, 'recommendation': 'Set to nosniff.'})
        else:
            score_components['xcto'] = 0
            findings.append({'type': 'missing_header', 'header': 'X-Content-Type-Options', 'impact': 'low', 'recommendation': 'Add X-Content-Type-Options: nosniff.'})
        refpol = headers.get('Referrer-Policy')
        if refpol:
            if refpol.lower() in ('no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'):
                score_components['referrer'] = 5
            else:
                score_components['referrer'] = 3
        else:
            score_components['referrer'] = 0
            findings.append({'type': 'missing_header', 'header': 'Referrer-Policy', 'impact': 'low', 'recommendation': 'Add strict-origin-when-cross-origin or no-referrer.'})
        perm = headers.get('Permissions-Policy') or headers.get('Feature-Policy')
        if perm:
            overly_permissive = any(': *' in seg or '="*"' in seg for seg in perm.split(','))
            if overly_permissive:
                score_components['permissions'] = 2
                findings.append({'type': 'weak_header', 'header': 'Permissions-Policy', 'detail': perm, 'recommendation': 'Restrict each feature to required origins only; avoid wildcard *.'})
            else:
                score_components['permissions'] = 6
        else:
            score_components['permissions'] = 0
            findings.append({'type': 'missing_header', 'header': 'Permissions-Policy', 'impact': 'low', 'recommendation': 'Add Permissions-Policy limiting powerful features.'})
        total_score = sum(score_components.values())
        max_score = 10 + 10 + 8 + 6 + 5 + 6  # per above weights
        hardening_ratio = round((total_score / max_score) * 100, 1) if max_score else 0.0
        return {
            'score_components': score_components,
            'total_header_score': total_score,
            'header_hardening_percent': hardening_ratio,
            'findings': findings,
        }

    def _score_csp(self, csp: str):
        findings: List[Dict[str, Any]] = []
        directives = {}
        for part in csp.split(';'):
            part = part.strip()
            if not part:
                continue
            if ' ' in part:
                name, val = part.split(' ', 1)
            else:
                name, val = part, ''
            directives[name.lower()] = val
        score = 0
        for key in CSP_KEY_DIRECTIVES:
            if key in directives:
                val = directives[key]
                penalty = 0
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val:
                    penalty += 2
                if '*' in val:
                    penalty += 2
                base = 8 if key == 'default-src' else 6
                comp = max(0, base - penalty)
                score += comp
                if penalty > 0:
                    findings.append({'type': 'weak_csp_directive', 'directive': key, 'value': val, 'penalty': penalty, 'recommendation': 'Remove unsafe-inline/unsafe-eval and wildcards.'})
            else:
                findings.append({'type': 'missing_csp_directive', 'directive': key, 'recommendation': 'Define this directive explicitly.'})
        return score, findings

__all__ = ['SecurityHeadersAnalyzer']
