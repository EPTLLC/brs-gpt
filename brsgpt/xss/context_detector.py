# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Context Detector

Intelligent XSS context detection for precise payload generation:
- HTML context: tag content, attributes, comments
- JavaScript context: script blocks, event handlers, JSON
- CSS context: style blocks, inline styles  
- URI context: URL parameters, fragments
- SVG context: SVG elements and attributes
- XML context: CDATA sections, processing instructions

Context-aware detection reduces false positives and improves exploit reliability.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import unquote
import html


class ContextDetector:
    """Intelligent XSS context detection for precise vulnerability assessment."""
    
    def __init__(self):
        """Initialize context detector with comprehensive detection patterns."""
        
        # HTML context patterns
        self.html_patterns = {
            'tag_content': r'<[^>]*>([^<]*{marker}[^<]*)</',
            'attribute_value': r'<[^>]*\s+[^=]*=["\']([^"\']*{marker}[^"\']*)["\']',
            'attribute_unquoted': r'<[^>]*\s+[^=]*=([^\s>]*{marker}[^\s>]*)',
            'html_comment': r'<!--[^>]*{marker}[^>]*-->',
            'meta_content': r'<meta[^>]*content=["\']([^"\']*{marker}[^"\']*)["\']',
            'title_content': r'<title[^>]*>([^<]*{marker}[^<]*)</title>'
        }
        
        # JavaScript context patterns
        self.js_patterns = {
            'script_block': r'<script[^>]*>([^<]*{marker}[^<]*)</script>',
            'event_handler': r'on\w+=["\']([^"\']*{marker}[^"\']*)["\']',
            'js_string': r'["\']([^"\']*{marker}[^"\']*)["\']',
            'js_variable': r'var\s+\w+\s*=\s*["\']?([^"\';\n]*{marker}[^"\';\n]*)["\']?',
            'json_value': r'"[^"]*":\s*"([^"]*{marker}[^"]*)"',
            'template_literal': r'`([^`]*{marker}[^`]*)`'
        }
        
        # CSS context patterns
        self.css_patterns = {
            'style_block': r'<style[^>]*>([^<]*{marker}[^<]*)</style>',
            'inline_style': r'style=["\']([^"\']*{marker}[^"\']*)["\']',
            'css_property': r'([^:;]*{marker}[^:;]*):',
            'css_value': r':\s*([^;]*{marker}[^;]*);?',
            'css_comment': r'/\*([^*]*{marker}[^*]*)\*/',
            'css_url': r'url\(([^)]*{marker}[^)]*)\)'
        }
        
        # URI context patterns
        self.uri_patterns = {
            'url_parameter': r'[?&]([^=]*{marker}[^=]*)=',
            'url_value': r'[?&][^=]*=([^&]*{marker}[^&]*)',
            'url_fragment': r'#([^?\s]*{marker}[^?\s]*)',
            'href_attribute': r'href=["\']([^"\']*{marker}[^"\']*)["\']',
            'src_attribute': r'src=["\']([^"\']*{marker}[^"\']*)["\']',
            'action_attribute': r'action=["\']([^"\']*{marker}[^"\']*)["\']'
        }
        
        # SVG context patterns
        self.svg_patterns = {
            'svg_content': r'<svg[^>]*>([^<]*{marker}[^<]*)</svg>',
            'svg_attribute': r'<[^>]*\s+[^=]*=["\']([^"\']*{marker}[^"\']*)["\'][^>]*/>?',
            'svg_text': r'<text[^>]*>([^<]*{marker}[^<]*)</text>',
            'svg_script': r'<script[^>]*>([^<]*{marker}[^<]*)</script>',
            'svg_animate': r'<animate[^>]*values=["\']([^"\']*{marker}[^"\']*)["\']'
        }
        
        # XML context patterns
        self.xml_patterns = {
            'xml_content': r'<[^>]*>([^<]*{marker}[^<]*)</',
            'xml_attribute': r'<[^>]*\s+[^=]*=["\']([^"\']*{marker}[^"\']*)["\']',
            'xml_cdata': r'<!\[CDATA\[([^\]]*{marker}[^\]]*)\]\]>',
            'xml_comment': r'<!--([^>]*{marker}[^>]*)-->',
            'xml_pi': r'<\?[^?]*([^?]*{marker}[^?]*)\?>',
            'xml_entity': r'&([^;]*{marker}[^;]*);'
        }
        
        # Context priority (higher number = higher priority)
        self.context_priority = {
            'javascript': 90,
            'svg': 80,
            'css': 70,
            'xml': 60,
            'uri': 50,
            'html': 40
        }
        
        # Dangerous HTML tags that require special attention
        self.dangerous_tags = [
            'script', 'iframe', 'object', 'embed', 'applet', 'form', 'input',
            'textarea', 'select', 'button', 'link', 'style', 'meta', 'base'
        ]
        
        # Event handlers for JavaScript context detection
        self.event_handlers = [
            'onload', 'onclick', 'onmouseover', 'onmouseout', 'onfocus', 'onblur',
            'onchange', 'onsubmit', 'onerror', 'onabort', 'onresize', 'onscroll',
            'onkeypress', 'onkeydown', 'onkeyup', 'ondblclick', 'onmousedown',
            'onmouseup', 'onmousemove', 'oncontextmenu', 'ondrag', 'ondrop'
        ]
    
    def detect_contexts(self, response_body: str, injection_point: str, 
                       test_marker: str = "BRSGPT_XSS_TEST") -> List[Dict[str, Any]]:
        """
        Detect all contexts where the injection point appears.
        
        Args:
            response_body: HTTP response body
            injection_point: The parameter/location being tested
            test_marker: Unique marker used for detection
            
        Returns:
            List of detected contexts with details
        """
        contexts = []
        
        # Replace injection point with test marker for analysis
        marked_body = response_body.replace(injection_point, test_marker)
        
        # Detect each context type
        html_contexts = self._detect_html_context(marked_body, test_marker)
        js_contexts = self._detect_javascript_context(marked_body, test_marker)
        css_contexts = self._detect_css_context(marked_body, test_marker)
        uri_contexts = self._detect_uri_context(marked_body, test_marker)
        svg_contexts = self._detect_svg_context(marked_body, test_marker)
        xml_contexts = self._detect_xml_context(marked_body, test_marker)
        
        # Combine all contexts
        all_contexts = (html_contexts + js_contexts + css_contexts + 
                       uri_contexts + svg_contexts + xml_contexts)
        
        # Remove duplicates and sort by priority
        unique_contexts = self._deduplicate_contexts(all_contexts)
        sorted_contexts = sorted(unique_contexts, 
                               key=lambda x: self.context_priority.get(x['type'], 0), 
                               reverse=True)
        
        return sorted_contexts
    
    def _detect_html_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect HTML contexts."""
        contexts = []
        
        for context_name, pattern in self.html_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                context = {
                    'type': 'html',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_encoding': self._requires_html_encoding(context_name),
                    'dangerous_location': self._is_dangerous_html_location(match.group(0))
                }
                contexts.append(context)
        
        return contexts
    
    def _detect_javascript_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect JavaScript contexts."""
        contexts = []
        
        for context_name, pattern in self.js_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                context = {
                    'type': 'javascript',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_js_encoding': True,
                    'execution_context': self._determine_js_execution_context(match.group(0))
                }
                contexts.append(context)
        
        return contexts
    
    def _detect_css_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect CSS contexts."""
        contexts = []
        
        for context_name, pattern in self.css_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                context = {
                    'type': 'css',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_css_encoding': True,
                    'allows_expressions': self._allows_css_expressions(match.group(0))
                }
                contexts.append(context)
        
        return contexts
    
    def _detect_uri_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect URI contexts."""
        contexts = []
        
        for context_name, pattern in self.uri_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE)
            
            for match in matches:
                context = {
                    'type': 'uri',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_url_encoding': True,
                    'scheme': self._extract_uri_scheme(match.group(0))
                }
                contexts.append(context)
        
        return contexts
    
    def _detect_svg_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect SVG contexts."""
        contexts = []
        
        for context_name, pattern in self.svg_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                context = {
                    'type': 'svg',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_xml_encoding': True,
                    'allows_script': 'script' in match.group(0).lower()
                }
                contexts.append(context)
        
        return contexts
    
    def _detect_xml_context(self, body: str, marker: str) -> List[Dict[str, Any]]:
        """Detect XML contexts."""
        contexts = []
        
        for context_name, pattern in self.xml_patterns.items():
            pattern_with_marker = pattern.format(marker=re.escape(marker))
            matches = re.finditer(pattern_with_marker, body, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                context = {
                    'type': 'xml',
                    'subtype': context_name,
                    'position': match.start(),
                    'matched_content': match.group(0),
                    'injection_context': match.group(1) if match.groups() else match.group(0),
                    'requires_xml_encoding': True,
                    'cdata_section': 'CDATA' in match.group(0)
                }
                contexts.append(context)
        
        return contexts
    
    def _requires_html_encoding(self, context_name: str) -> bool:
        """Determine if HTML context requires encoding."""
        encoding_required = {
            'tag_content': True,
            'attribute_value': True,
            'attribute_unquoted': True,
            'html_comment': False,
            'meta_content': True,
            'title_content': True
        }
        return encoding_required.get(context_name, True)
    
    def _is_dangerous_html_location(self, matched_content: str) -> bool:
        """Check if HTML location is dangerous."""
        for tag in self.dangerous_tags:
            if f'<{tag}' in matched_content.lower():
                return True
        return False
    
    def _determine_js_execution_context(self, matched_content: str) -> str:
        """Determine JavaScript execution context."""
        content_lower = matched_content.lower()
        
        if '<script' in content_lower:
            return 'script_block'
        elif any(handler in content_lower for handler in self.event_handlers):
            return 'event_handler'
        elif 'javascript:' in content_lower:
            return 'javascript_url'
        elif '"' in matched_content or "'" in matched_content:
            return 'string_literal'
        else:
            return 'direct_execution'
    
    def _allows_css_expressions(self, matched_content: str) -> bool:
        """Check if CSS context allows expressions."""
        # IE-specific CSS expressions
        return 'expression(' in matched_content.lower()
    
    def _extract_uri_scheme(self, matched_content: str) -> Optional[str]:
        """Extract URI scheme from matched content."""
        scheme_match = re.search(r'^([a-zA-Z][a-zA-Z0-9+.-]*):/', matched_content)
        return scheme_match.group(1) if scheme_match else None
    
    def _deduplicate_contexts(self, contexts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate contexts."""
        seen = set()
        unique_contexts = []
        
        for context in contexts:
            # Create a unique key based on type, subtype, and position
            key = (context['type'], context['subtype'], context['position'])
            
            if key not in seen:
                seen.add(key)
                unique_contexts.append(context)
        
        return unique_contexts
    
    def analyze_breaking_characters(self, context: Dict[str, Any]) -> List[str]:
        """
        Analyze which characters can break out of the current context.
        
        Args:
            context: Context information
            
        Returns:
            List of characters that can break the context
        """
        breaking_chars = []
        
        context_type = context['type']
        subtype = context['subtype']
        
        if context_type == 'html':
            if subtype == 'tag_content':
                breaking_chars = ['<', '>', '&']
            elif subtype in ['attribute_value']:
                breaking_chars = ['"', "'", '<', '>', '&']
            elif subtype == 'attribute_unquoted':
                breaking_chars = [' ', '\t', '\n', '\r', '>', '<', '&']
            elif subtype == 'html_comment':
                breaking_chars = ['-->', '<']
        
        elif context_type == 'javascript':
            if subtype in ['js_string', 'template_literal']:
                breaking_chars = ['"', "'", '`', '\\', '\n', '\r']
            elif subtype == 'script_block':
                breaking_chars = ['</script>', ';', '\n']
            elif subtype == 'event_handler':
                breaking_chars = ['"', "'", ';', ')', '&']
        
        elif context_type == 'css':
            if subtype in ['style_block', 'inline_style']:
                breaking_chars = [';', '}', '/*', '*/', '"', "'"]
            elif subtype == 'css_value':
                breaking_chars = [';', '}', '"', "'", ')', '\\']
        
        elif context_type == 'uri':
            breaking_chars = ['&', '?', '#', ' ', '%', '+', '=']
        
        elif context_type == 'svg':
            breaking_chars = ['<', '>', '"', "'", '&']
        
        elif context_type == 'xml':
            breaking_chars = ['<', '>', '"', "'", '&', ']]>']
        
        return breaking_chars
    
    def get_context_specific_filters(self, context: Dict[str, Any]) -> List[str]:
        """
        Get context-specific filters that might block payloads.
        
        Args:
            context: Context information
            
        Returns:
            List of potential filters for this context
        """
        filters = []
        
        context_type = context['type']
        subtype = context['subtype']
        
        # Common filters across all contexts
        common_filters = ['<script', 'javascript:', 'onerror', 'onload', 'alert(', 'eval(']
        filters.extend(common_filters)
        
        if context_type == 'html':
            html_filters = ['<iframe', '<object', '<embed', '<form', '<input', 'src=', 'href=']
            filters.extend(html_filters)
        
        elif context_type == 'javascript':
            js_filters = ['document.', 'window.', 'location.', 'cookie', 'localStorage']
            filters.extend(js_filters)
        
        elif context_type == 'css':
            css_filters = ['expression(', 'url(', '@import', 'behavior:']
            filters.extend(css_filters)
        
        elif context_type == 'uri':
            uri_filters = ['javascript:', 'data:', 'vbscript:', 'file:']
            filters.extend(uri_filters)
        
        return filters

