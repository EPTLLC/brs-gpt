# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-15 00:00:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
Technology Detector

Comprehensive web technology stack identification:
- Server software and version detection
- Web frameworks and CMS identification
- JavaScript libraries and frameworks
- Database technology inference
- CDN and hosting provider detection
- Security technology identification

Built-in technology detection without external API dependencies.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, urljoin
import json

from ..utils.http_client import HttpClient


class TechnologyDetector:
    """Comprehensive web technology stack detector."""
    
    def __init__(self, http_client: HttpClient, settings: Dict[str, Any]):
        """
        Initialize technology detector.
        
        Args:
            http_client: HTTP client for web requests
            settings: Reconnaissance settings
        """
        self.http_client = http_client
        self.settings = settings
        
        # Technology detection signatures
        self.technology_signatures = {
            'servers': {
                'nginx': {
                    'headers': [r'nginx'],
                    'body': [],
                    'category': 'Web Server'
                },
                'apache': {
                    'headers': [r'Apache'],
                    'body': [],
                    'category': 'Web Server'
                },
                'iis': {
                    'headers': [r'Microsoft-IIS'],
                    'body': [],
                    'category': 'Web Server'
                },
                'cloudflare': {
                    'headers': [r'cloudflare'],
                    'body': [],
                    'category': 'CDN'
                },
                'aws': {
                    'headers': [r'AmazonS3', r'CloudFront'],
                    'body': [],
                    'category': 'Cloud Provider'
                }
            },
            'frameworks': {
                'react': {
                    'headers': [],
                    'body': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                    'category': 'JavaScript Framework'
                },
                'vue': {
                    'headers': [],
                    'body': [r'vue\.js', r'__vue__'],
                    'category': 'JavaScript Framework'
                },
                'angular': {
                    'headers': [],
                    'body': [r'angular', r'ng-version'],
                    'category': 'JavaScript Framework'
                },
                'jquery': {
                    'headers': [],
                    'body': [r'jquery', r'\$\.fn\.jquery'],
                    'category': 'JavaScript Library'
                },
                'bootstrap': {
                    'headers': [],
                    'body': [r'bootstrap', r'btn-primary'],
                    'category': 'CSS Framework'
                },
                'django': {
                    'headers': [],
                    'body': [r'csrfmiddlewaretoken', r'django'],
                    'category': 'Web Framework'
                },
                'rails': {
                    'headers': [],
                    'body': [r'rails', r'authenticity_token'],
                    'category': 'Web Framework'
                },
                'laravel': {
                    'headers': [],
                    'body': [r'laravel_session', r'_token'],
                    'category': 'Web Framework'
                },
                'wordpress': {
                    'headers': [],
                    'body': [r'wp-content', r'wp-includes', r'WordPress'],
                    'category': 'CMS'
                },
                'drupal': {
                    'headers': [],
                    'body': [r'drupal', r'sites/default'],
                    'category': 'CMS'
                },
                'joomla': {
                    'headers': [],
                    'body': [r'joomla', r'option=com_'],
                    'category': 'CMS'
                }
            },
            'security': {
                'waf': {
                    'headers': [r'X-WAF', r'X-Sucuri', r'X-Security'],
                    'body': [],
                    'category': 'Security'
                },
                'cloudflare_security': {
                    'headers': [r'CF-RAY', r'__cfduid'],
                    'body': [],
                    'category': 'Security'
                },
                'incapsula': {
                    'headers': [r'X-Iinfo', r'incap_ses'],
                    'body': [],
                    'category': 'Security'
                }
            },
            'analytics': {
                'google_analytics': {
                    'headers': [],
                    'body': [r'google-analytics\.com', r'gtag\('],
                    'category': 'Analytics'
                },
                'google_tag_manager': {
                    'headers': [],
                    'body': [r'googletagmanager\.com'],
                    'category': 'Analytics'
                },
                'facebook_pixel': {
                    'headers': [],
                    'body': [r'fbevents\.js', r'facebook\.com/tr'],
                    'category': 'Analytics'
                }
            }
        }
        
        # Common technology-specific paths to check
        self.tech_paths = {
            'wordpress': [
                '/wp-admin/',
                '/wp-content/',
                '/wp-includes/',
                '/wp-json/wp/v2/',
                '/xmlrpc.php',
                '/wp-login.php'
            ],
            'drupal': [
                '/user/login',
                '/admin/',
                '/sites/default/',
                '/modules/',
                '/themes/'
            ],
            'joomla': [
                '/administrator/',
                '/components/',
                '/modules/',
                '/templates/'
            ],
            'phpmyadmin': [
                '/phpmyadmin/',
                '/pma/',
                '/phpMyAdmin/',
                '/mysql/'
            ],
            'admin_panels': [
                '/admin/',
                '/administrator/',
                '/admin.php',
                '/login/',
                '/dashboard/',
                '/panel/',
                '/control/',
                '/manage/'
            ]
        }
    
    async def detect(self, target_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive technology detection.
        
        Args:
            target_url: Target URL to analyze
            
        Returns:
            Dictionary containing detected technologies
        """
        detection_results = {
            'url': target_url,
            'technologies': {},
            'security_headers': {},
            'cookies': {},
            'forms': [],
            'admin_panels': [],
            'interesting_paths': [],
            'cms_detection': {},
            'javascript_libraries': [],
            'server_info': {},
            'web_checks': {
                'graphql': {},
                'cors': {},
                'api_keys': [],
                'websockets': [],
                'grpc': {},
                'jwt': {},
                'oidc': {}
            },
            'auth': {},
            'service_endpoints': {}
        }
        
        try:
            # Primary page analysis
            primary_analysis = await self._analyze_primary_page(target_url)
            detection_results.update(primary_analysis)
            
            # Path-based detection
            path_analysis = await self._analyze_tech_paths(target_url)
            detection_results['interesting_paths'] = path_analysis
            
            # Admin panel detection
            admin_panels = await self._detect_admin_panels(target_url)
            detection_results['admin_panels'] = admin_panels
            
            # CMS-specific detection
            cms_analysis = await self._deep_cms_detection(target_url, detection_results['technologies'])
            detection_results['cms_detection'] = cms_analysis
            
            # JavaScript library detection
            js_libs = await self._detect_javascript_libraries(target_url)
            detection_results['javascript_libraries'] = js_libs

            # Web checks: GraphQL, CORS, API keys, WebSockets, gRPC
            detection_results['web_checks']['graphql'] = await self._detect_graphql(target_url)
            detection_results['web_checks']['cors'] = self._check_cors_misconfig(detection_results.get('security_headers', {}))
            detection_results['web_checks']['api_keys'] = await self._scan_api_keys(target_url)
            detection_results['web_checks']['websockets'] = self._detect_websockets_links(primary_analysis.get('server_info', {}), await self._safe_get_body(target_url))
            # gRPC: headers + proactive Accept probe
            grpc_headers = self._detect_grpc_from_headers(primary_analysis.get('server_info', {}))
            grpc_probe = await self._detect_grpc_probe(target_url)
            detection_results['web_checks']['grpc'] = { **grpc_headers, **grpc_probe }
            detection_results['web_checks']['oauth'] = await self._detect_oauth_endpoints(target_url)
            # Auth/JWT/OIDC checks
            detection_results['web_checks']['jwt'] = (primary_analysis.get('auth') or {}).get('jwt', {})
            detection_results['web_checks']['oidc'] = await self._detect_oidc(target_url)

            # Management/DevOps endpoints
            detection_results['service_endpoints'] = await self._detect_management_endpoints(target_url)
            
        except Exception as e:
            detection_results['error'] = str(e)
        
        return detection_results
    
    async def _analyze_primary_page(self, url: str) -> Dict[str, Any]:
        """
        Analyze the primary page for technology indicators.
        
        Args:
            url: Target URL
            
        Returns:
            Primary analysis results
        """
        results = {
            'technologies': {},
            'security_headers': {},
            'cookies': {},
            'forms': [],
            'server_info': {},
            'auth': {}
        }
        
        try:
            response = await self.http_client.get(url)
            if not response:
                return results
            
            # Analyze headers
            headers = dict(response.headers)
            results['server_info'] = self._extract_server_info(headers)
            results['security_headers'] = self._analyze_security_headers(headers)
            
            # Analyze cookies
            if 'Set-Cookie' in headers:
                results['cookies'] = self._analyze_cookies(headers['Set-Cookie'])
            
            # Analyze response body
            body = await response.text()
            
            # Technology detection from headers and body
            results['technologies'] = self._detect_technologies(headers, body)
            
            # Form analysis
            results['forms'] = self._analyze_forms(body)

            # JWT detection (headers + cookies)
            results['auth']['jwt'] = self._detect_jwt(headers, headers.get('Set-Cookie', ''))
            
        except Exception:
            pass
        
        return results

    async def _safe_get_body(self, url: str) -> str:
        try:
            resp = await self.http_client.get(url)
            if resp and resp.status == 200:
                return await resp.text()
        except Exception:
            pass
        return ""
    
    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Extract server information from headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Server information
        """
        server_info = {}
        
        # Server header
        if 'Server' in headers:
            server_info['server'] = headers['Server']
        
        # X-Powered-By header
        if 'X-Powered-By' in headers:
            server_info['powered_by'] = headers['X-Powered-By']
        
        # X-Generator header
        if 'X-Generator' in headers:
            server_info['generator'] = headers['X-Generator']
        
        # Via header (proxy information)
        if 'Via' in headers:
            server_info['via'] = headers['Via']
        
        return server_info
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze security-related headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Security headers analysis
        """
        security_headers = {}
        security_header_list = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy'
        ]
        
        for header in security_header_list:
            if header in headers:
                security_headers[header] = {
                    'present': True,
                    'value': headers[header]
                }
            else:
                security_headers[header] = {
                    'present': False,
                    'security_risk': 'Missing security header'
                }
        
        return security_headers
    
    def _analyze_cookies(self, cookie_header: str) -> Dict[str, Any]:
        """
        Analyze cookie security attributes.
        
        Args:
            cookie_header: Set-Cookie header value
            
        Returns:
            Cookie analysis
        """
        cookie_analysis = {
            'total_cookies': 0,
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'samesite_cookies': 0,
            'security_issues': []
        }
        
        cookies = cookie_header.split(',')
        cookie_analysis['total_cookies'] = len(cookies)
        
        for cookie in cookies:
            cookie = cookie.strip().lower()
            
            if 'secure' in cookie:
                cookie_analysis['secure_cookies'] += 1
            else:
                cookie_analysis['security_issues'].append('Cookie without Secure flag')
            
            if 'httponly' in cookie:
                cookie_analysis['httponly_cookies'] += 1
            else:
                cookie_analysis['security_issues'].append('Cookie without HttpOnly flag')
            
            if 'samesite' in cookie:
                cookie_analysis['samesite_cookies'] += 1
            else:
                cookie_analysis['security_issues'].append('Cookie without SameSite attribute')
        
        return cookie_analysis

    def _detect_jwt(self, headers: Dict[str, str], cookie_header: str) -> Dict[str, Any]:
        """Detect and lightly analyze JWTs (header.alg, kid) from headers/cookies."""
        findings: Dict[str, Any] = {
            'present': False,
            'locations': [],
            'issues': [],
            'samples': []
        }
        try:
            import base64, json as _json
            def decode_b64url(segment: str) -> Dict[str, Any]:
                try:
                    pad = '=' * (-len(segment) % 4)
                    data = base64.urlsafe_b64decode(segment + pad)
                    return _json.loads(data.decode('utf-8', errors='ignore'))
                except Exception:
                    return {}

            tokens: List[str] = []
            h_lower = {k.lower(): v for k, v in (headers or {}).items()}
            auth = h_lower.get('authorization', '')
            if 'bearer ' in auth.lower() and '.' in auth:
                findings['present'] = True
                findings['locations'].append('Authorization header')
                try:
                    tokens.append(auth.split()[-1])
                except Exception:
                    pass
            # Search for JWT-like tokens in cookies
            if cookie_header:
                for piece in cookie_header.split(';'):
                    token = piece.strip()
                    if token.count('.') >= 2 and len(token) > 20:
                        findings['present'] = True
                        findings['locations'].append('Cookie')
                        tokens.append(token)

            # Decode up to 3 tokens to evaluate header.alg
            for t in tokens[:3]:
                try:
                    header_seg = t.split('.')[0]
                    header_obj = decode_b64url(header_seg)
                    alg = (header_obj.get('alg') or '').upper()
                    kid = header_obj.get('kid')
                    sample = {'alg': alg, 'kid': kid}
                    # Weak algorithm checks
                    weak = []
                    if alg == 'NONE':
                        weak.append('alg:none (no signature)')
                    if alg in ('HS256', 'HS384', 'HS512'):
                        weak.append('HMAC-based JWT (ensure strong shared secret)')
                    if weak:
                        sample['weak'] = weak
                        findings['issues'].extend(weak)
                    findings['samples'].append(sample)
                except Exception:
                    continue

            # If no HSTS and JWT present, warn
            if 'Strict-Transport-Security' not in headers and findings['present']:
                findings['issues'].append('JWT without HSTS (transport hardening missing)')
        except Exception:
            pass
        return findings

    async def _detect_oidc(self, base_url: str) -> Dict[str, Any]:
        """Detect OIDC discovery endpoint availability (/.well-known/openid-configuration)."""
        result: Dict[str, Any] = { 'discovery_found': False, 'endpoint': None, 'issues': [] }
        try:
            from urllib.parse import urljoin
            url = urljoin(base_url, '/.well-known/openid-configuration')
            resp = await self.http_client.get(url)
            if resp and resp.status in (200, 401):
                # 200 indicates readable discovery; 401 indicates protected but present
                result['discovery_found'] = True
                result['endpoint'] = url
                if resp.status == 200:
                    result['issues'].append('OIDC discovery openly readable')
        except Exception:
            pass
        return result

    async def _detect_oauth_endpoints(self, base_url: str) -> Dict[str, Any]:
        """Probe common OAuth2 endpoints (authorize, token) under /oauth and /.well-known."""
        found: Dict[str, Any] = { 'authorize': None, 'token': None, 'well_known': None }
        try:
            candidates = [
                '/oauth/authorize',
                '/oauth/token',
                '/oauth2/authorize',
                '/oauth2/token',
                '/.well-known/oauth-authorization-server',
            ]
            for path in candidates:
                try:
                    url = urljoin(base_url, path)
                    resp = await self.http_client.get(url)
                    if not resp:
                        continue
                    text = ''
                    try:
                        text = await resp.text()
                    except Exception:
                        text = ''
                    if 'authorize' in path and resp.status in (200, 302, 401):
                        found['authorize'] = {'endpoint': url, 'status': resp.status}
                    if 'token' in path and resp.status in (200, 401, 405):
                        found['token'] = {'endpoint': url, 'status': resp.status}
                    if 'well-known' in path and resp.status in (200, 401):
                        found['well_known'] = {'endpoint': url, 'status': resp.status}
                except Exception:
                    continue
        except Exception:
            pass
        return found
    
    def _detect_technologies(self, headers: Dict[str, str], body: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect technologies from headers and body content.
        
        Args:
            headers: HTTP response headers
            body: Response body content
            
        Returns:
            Detected technologies by category
        """
        detected_technologies = {}
        
        # Convert headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()
        
        for category, technologies in self.technology_signatures.items():
            detected_technologies[category] = []
            
            for tech_name, signatures in technologies.items():
                detected = False
                confidence = 0
                evidence = []
                
                # Check header signatures
                for header_pattern in signatures['headers']:
                    for header_name, header_value in headers_lower.items():
                        if re.search(header_pattern.lower(), header_value):
                            detected = True
                            confidence += 30
                            evidence.append(f'Header: {header_name}')
                
                # Check body signatures
                for body_pattern in signatures['body']:
                    if re.search(body_pattern.lower(), body_lower):
                        detected = True
                        confidence += 20
                        evidence.append(f'Body content: {body_pattern}')
                
                if detected:
                    detected_technologies[category].append({
                        'name': tech_name,
                        'category': signatures['category'],
                        'confidence': min(confidence, 100),
                        'evidence': evidence
                    })
        
        return detected_technologies
    
    def _analyze_forms(self, body: str) -> List[Dict[str, Any]]:
        """
        Analyze HTML forms for security issues.
        
        Args:
            body: Response body content
            
        Returns:
            List of form analysis results
        """
        forms = []
        
        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, body, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            form_analysis = {
                'method': 'GET',
                'action': '',
                'has_csrf_token': False,
                'input_fields': [],
                'security_issues': []
            }
            
            # Extract form attributes
            method_match = re.search(r'method=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
            if method_match:
                form_analysis['method'] = method_match.group(1).upper()
            
            action_match = re.search(r'action=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
            if action_match:
                form_analysis['action'] = action_match.group(1)
            
            # Check for CSRF token
            csrf_patterns = [
                r'csrf[_-]?token',
                r'authenticity[_-]?token',
                r'_token',
                r'csrfmiddlewaretoken'
            ]
            
            for pattern in csrf_patterns:
                if re.search(pattern, form_html, re.IGNORECASE):
                    form_analysis['has_csrf_token'] = True
                    break
            
            # Extract input fields
            input_pattern = r'<input[^>]*>'
            input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
            
            for input_match in input_matches:
                input_html = input_match.group(0)
                input_info = {
                    'type': 'text',
                    'name': '',
                    'required': False
                }
                
                type_match = re.search(r'type=["\']?([^"\'>\s]+)', input_html, re.IGNORECASE)
                if type_match:
                    input_info['type'] = type_match.group(1).lower()
                
                name_match = re.search(r'name=["\']?([^"\'>\s]+)', input_html, re.IGNORECASE)
                if name_match:
                    input_info['name'] = name_match.group(1)
                
                if 'required' in input_html.lower():
                    input_info['required'] = True
                
                form_analysis['input_fields'].append(input_info)
            
            # Security analysis
            if form_analysis['method'] == 'POST' and not form_analysis['has_csrf_token']:
                form_analysis['security_issues'].append('POST form without CSRF protection')
            
            if any(field['type'] == 'password' for field in form_analysis['input_fields']):
                if form_analysis['action'].startswith('http://'):
                    form_analysis['security_issues'].append('Password form over HTTP')
            
            forms.append(form_analysis)
        
        return forms

    async def _detect_management_endpoints(self, base_url: str) -> Dict[str, Any]:
        """Detect common DevOps/Cloud services via HTTP endpoints.

        Non-intrusive, GET-only probes with short timeouts.
        """
        found: Dict[str, Any] = {}
        checks = [
            ('gitlab', '/-/health'),
            ('gitlab_signup', '/users/sign_up'),
            ('jenkins', '/api/json'),
            ('jenkins_crumb', '/crumbIssuer/api/json'),
            ('sonarqube_health', '/api/system/health'),
            ('sonarqube_version', '/api/server/version'),
            ('vault', '/v1/sys/health'),
            ('consul', '/v1/status/leader'),
            ('minio', '/minio/health/live'),
            ('s3_list', '/?list-type=2'),
            ('terraform_state', '/terraform.tfstate'),
            ('harbor', '/api/v2.0/systeminfo'),
            ('docker_registry', '/v2/'),
        ]
        for name, path in checks:
            try:
                url = urljoin(base_url, path)
                resp = await self.http_client.get(url)
                if not resp:
                    continue
                text = ''
                try:
                    text = await resp.text()
                except Exception:
                    text = ''
                if name == 'gitlab' and resp.status == 200 and ('ok' in text.lower() or 'healthy' in text.lower()):
                    found['gitlab'] = {'endpoint': url, 'status': 'healthy'}
                elif name == 'gitlab_signup' and resp.status == 200 and ('Sign up' in text or 'Register' in text):
                    found.setdefault('gitlab', {})['signup'] = {'endpoint': url, 'open_signup': True}
                elif name == 'jenkins' and (resp.headers.get('X-Jenkins') or 'jenkins' in text.lower()):
                    found['jenkins'] = {'endpoint': url, 'x_jenkins': resp.headers.get('X-Jenkins')}
                elif name == 'jenkins_crumb' and resp.status in (200, 403) and ('crumb' in text.lower() or 'Jenkins-Crumb' in resp.headers):
                    found.setdefault('jenkins', {})['crumb'] = {'endpoint': url, 'present': True}
                elif name.startswith('sonarqube') and (resp.status == 200 and ('SONARQUBE' in text.upper() or 'health' in text.lower() or text.strip().startswith('"') )):
                    entry = {'endpoint': url, 'status_code': resp.status}
                    if name.endswith('version'):
                        try:
                            entry['version'] = text.strip().strip('"')
                        except Exception:
                            pass
                    found.setdefault('sonarqube', {})[name.split('_')[-1]] = entry
                elif name == 'vault' and ('initialized' in text or 'sealed' in text or resp.status in (200, 429, 501, 503)):
                    v = {'endpoint': url, 'status_code': resp.status}
                    try:
                        import json as _json
                        data = _json.loads(text)
                        if isinstance(data, dict):
                            v['sealed'] = data.get('sealed')
                            v['initialized'] = data.get('initialized')
                    except Exception:
                        pass
                    found['vault'] = v
                elif name == 'consul' and (resp.status == 200 and text.strip().startswith('"')):
                    found['consul'] = {'endpoint': url, 'leader': text.strip().strip('"')}
                elif name == 'minio' and (resp.status == 200 and 'ok' in text.lower()):
                    found['minio'] = {'endpoint': url, 'status': 'ok'}
                elif name == 's3_list' and ('ListBucketResult' in text or '<Error>' in text):
                    found['s3_like'] = {'endpoint': url, 'hint': 'ListBucketResult/Error XML detected'}
                elif name == 'terraform_state' and (resp.status == 200 and 'outputs' in text and 'resources' in text):
                    found['terraform_state'] = {'endpoint': url, 'risk': 'Potential secrets in tfstate'}
                elif name == 'harbor' and (resp.status in (200, 401) and ('harbor' in text.lower() or 'registry_url' in text.lower())):
                    found['harbor'] = {'endpoint': url, 'status_code': resp.status}
                elif name == 'docker_registry' and resp.status in (200, 401):
                    found['docker_registry'] = {'endpoint': url, 'status_code': resp.status}
                # RabbitMQ Management: /api/overview JSON (if probed elsewhere)
                elif 'rabbitmq' in text.lower() and 'management' in text.lower():
                    try:
                        import json as _json
                        data = _json.loads(text)
                        if isinstance(data, dict):
                            ov = {
                                'endpoint': url,
                                'cluster_name': data.get('cluster_name'),
                                'management_version': data.get('management_version'),
                                'rabbitmq_version': data.get('rabbitmq_version'),
                            }
                            found['rabbitmq'] = ov
                    except Exception:
                        pass
            except Exception:
                continue
        return found

    async def _detect_graphql(self, base_url: str) -> Dict[str, Any]:
        """Attempt GraphQL introspection on common endpoints.

        Non-intrusive POST to /graphql and /api/graphql with standard query.
        """
        result: Dict[str, Any] = { 'introspection_enabled': False, 'endpoint': None, 'types_count': None, 'has_mutations': None, 'type_names_sample': [] }
        try:
            endpoints = ['/graphql', '/api/graphql']
            for ep in endpoints:
                gql_endpoint = urljoin(base_url, ep)
                payload = {
                    'query': 'query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }'
                }
                headers = { 'Content-Type': 'application/json' }
                resp = await self.http_client.post(gql_endpoint, json=payload, headers=headers)
                if resp and resp.status == 200:
                    text = await resp.text()
                    if '__schema' in text:
                        result['introspection_enabled'] = True
                        result['endpoint'] = gql_endpoint
                        # Lightweight stats
                        try:
                            import json as _json
                            data = _json.loads(text)
                            types = data.get('data', {}).get('__schema', {}).get('types', [])
                            result['types_count'] = len(types) if isinstance(types, list) else None
                            result['has_mutations'] = bool(data.get('data', {}).get('__schema', {}).get('mutationType'))
                            # sample first few type names
                            try:
                                names = []
                                for t in types:
                                    n = t.get('name') if isinstance(t, dict) else None
                                    if n and not n.startswith('__'):
                                        names.append(n)
                                    if len(names) >= 8:
                                        break
                                result['type_names_sample'] = names
                            except Exception:
                                pass
                        except Exception:
                            pass
                        break
        except Exception:
            pass
        return result

    def _check_cors_misconfig(self, security_headers: Dict[str, Any]) -> Dict[str, Any]:
        """Detect common CORS misconfigurations from headers only (lightweight)."""
        cors = {
            'allow_origin': None,
            'allow_credentials': None,
            'misconfig': False,
            'issues': []
        }
        try:
            h = {k.lower(): v.get('value') if isinstance(v, dict) else v for k, v in security_headers.items()}
            aco = h.get('access-control-allow-origin')
            acc = h.get('access-control-allow-credentials')
            acm = h.get('access-control-allow-methods')
            ach = h.get('access-control-allow-headers')
            if aco:
                cors['allow_origin'] = aco
            if acc:
                cors['allow_credentials'] = acc
            if aco == '*':
                cors['misconfig'] = True
                cors['issues'].append('Access-Control-Allow-Origin is wildcard *')
            if aco and acc and acc.lower() == 'true' and aco == '*':
                cors['misconfig'] = True
                cors['issues'].append('Wildcard ACAO with credentials=true')
            # Overly permissive methods/headers (heuristic)
            if acm and ('*' in acm or 'PUT' in acm or 'DELETE' in acm):
                cors['issues'].append('Permissive methods allowed in CORS')
            if ach and ('*' in ach or 'authorization' in ach.lower()):
                cors['issues'].append('Permissive headers allowed in CORS')
        except Exception:
            pass
        return cors

    async def _scan_api_keys(self, base_url: str) -> List[Dict[str, Any]]:
        """Scan HTML and a few linked JS files for common API key patterns."""
        findings: List[Dict[str, Any]] = []
        try:
            resp = await self.http_client.get(base_url)
            if not resp or resp.status != 200:
                return findings
            html = await resp.text()
            findings.extend(self._match_api_keys(html, base_url))
            # Find JS links
            js_links = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.IGNORECASE)
            for link in js_links[:5]:
                try:
                    js_url = urljoin(base_url, link)
                    js_resp = await self.http_client.get(js_url)
                    if js_resp and js_resp.status == 200:
                        js_body = await js_resp.text()
                        findings.extend(self._match_api_keys(js_body, js_url))
                except Exception:
                    continue
        except Exception:
            pass
        # Deduplicate
        unique = []
        seen = set()
        for f in findings:
            key = (f.get('type'), f.get('value'))
            if key not in seen:
                seen.add(key); unique.append(f)
        return unique

    def _match_api_keys(self, text: str, source: str) -> List[Dict[str, Any]]:
        patterns = [
            ('AWS Access Key', r'AKIA[0-9A-Z]{16}'),
            ('Google API Key', r'AIzaSy[0-9A-Za-z\-_]{35}'),
            ('Slack Token', r'xox[abpr]-[0-9A-Za-z\-]{10,48}'),
            ('GitHub Token', r'ghp_[0-9A-Za-z]{36}'),
            ('OpenAI Key', r'sk-[A-Za-z0-9]{32,}'),
        ]
        findings: List[Dict[str, Any]] = []
        for name, pat in patterns:
            for m in re.finditer(pat, text):
                findings.append({'type': name, 'value': m.group(0), 'source': source})
        return findings

    def _detect_websockets_links(self, server_info: Dict[str, Any], body: str) -> List[str]:
        links: List[str] = []
        try:
            for m in re.finditer(r'ws[s]?://[^"\'\s]+', body or ''):
                links.append(m.group(0))
        except Exception:
            pass
        return links

    def _detect_grpc_from_headers(self, server_info: Dict[str, Any]) -> Dict[str, Any]:
        # Heuristic: look for application/grpc or grpc-related hints in server info
        suspected = False
        hints = []
        for key, value in (server_info or {}).items():
            try:
                val = str(value).lower()
                if 'grpc' in val:
                    suspected = True
                    hints.append(f'{key}: {value}')
            except Exception:
                continue
        return { 'suspected': suspected, 'hints': hints[:3] }

    async def _detect_grpc_probe(self, base_url: str) -> Dict[str, Any]:
        """Send a lightweight GET with gRPC content types to see if server hints at gRPC."""
        try:
            headers = { 'Accept': 'application/grpc, */*' }
            resp = await self.http_client.get(base_url, headers=headers)
            if resp and ('application/grpc' in (resp.headers.get('content-type','').lower())):
                return { 'probe_suspected': True }
        except Exception:
            pass
        return { 'probe_suspected': False }
    
    async def _analyze_tech_paths(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Analyze technology-specific paths.
        
        Args:
            base_url: Base URL to test
            
        Returns:
            List of interesting paths found
        """
        interesting_paths = []
        
        # Test technology-specific paths
        for tech_name, paths in self.tech_paths.items():
            for path in paths:
                try:
                    test_url = urljoin(base_url, path)
                    response = await self.http_client.get(test_url)
                    
                    if response and response.status < 400:
                        interesting_paths.append({
                            'path': path,
                            'status_code': response.status,
                            'technology': tech_name,
                            'url': test_url,
                            'accessible': True
                        })
                        
                except Exception:
                    continue
        
        return interesting_paths
    
    async def _detect_admin_panels(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Detect accessible admin panels.
        
        Args:
            base_url: Base URL to test
            
        Returns:
            List of detected admin panels
        """
        admin_panels = []
        
        for path in self.tech_paths['admin_panels']:
            try:
                test_url = urljoin(base_url, path)
                response = await self.http_client.get(test_url)
                
                if response and response.status < 400:
                    body = await response.text()
                    
                    # Check for admin panel indicators
                    admin_indicators = [
                        'login', 'username', 'password', 'admin', 'dashboard',
                        'control panel', 'management', 'administration'
                    ]
                    
                    indicator_count = sum(1 for indicator in admin_indicators 
                                        if indicator in body.lower())
                    
                    if indicator_count >= 2:
                        admin_panels.append({
                            'path': path,
                            'url': test_url,
                            'status_code': response.status,
                            'confidence': min(indicator_count * 25, 100),
                            'title': self._extract_title(body)
                        })
                        
            except Exception:
                continue
        
        return admin_panels
    
    async def _deep_cms_detection(self, base_url: str, detected_technologies: Dict[str, List]) -> Dict[str, Any]:
        """
        Perform deep CMS detection and version identification.
        
        Args:
            base_url: Base URL
            detected_technologies: Already detected technologies
            
        Returns:
            Detailed CMS information
        """
        cms_info = {}
        
        # Check if any CMS was detected
        cms_detected = None
        for category, techs in detected_technologies.items():
            for tech in techs:
                if tech['category'] == 'CMS':
                    cms_detected = tech['name']
                    break
        
        if cms_detected == 'wordpress':
            cms_info = await self._detect_wordpress_details(base_url)
        elif cms_detected == 'drupal':
            cms_info = await self._detect_drupal_details(base_url)
        elif cms_detected == 'joomla':
            cms_info = await self._detect_joomla_details(base_url)
        
        return cms_info
    
    async def _detect_wordpress_details(self, base_url: str) -> Dict[str, Any]:
        """
        Detect detailed WordPress information.
        
        Args:
            base_url: WordPress site URL
            
        Returns:
            WordPress details
        """
        wp_info = {
            'cms': 'WordPress',
            'version': None,
            'theme': None,
            'plugins': [],
            'security_issues': []
        }
        
        try:
            # Check readme.html for version
            readme_url = urljoin(base_url, '/readme.html')
            response = await self.http_client.get(readme_url)
            if response and response.status == 200:
                body = await response.text()
                version_match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', body)
                if version_match:
                    wp_info['version'] = version_match.group(1)
            
            # Check wp-json API for version
            api_url = urljoin(base_url, '/wp-json/wp/v2/')
            response = await self.http_client.get(api_url)
            if response and response.status == 200:
                wp_info['security_issues'].append('WordPress REST API exposed')
            
            # Check for xmlrpc.php
            xmlrpc_url = urljoin(base_url, '/xmlrpc.php')
            response = await self.http_client.get(xmlrpc_url)
            if response and response.status == 200:
                wp_info['security_issues'].append('XML-RPC endpoint accessible')
            
        except Exception:
            pass
        
        return wp_info
    
    async def _detect_drupal_details(self, base_url: str) -> Dict[str, Any]:
        """
        Detect detailed Drupal information.
        
        Args:
            base_url: Drupal site URL
            
        Returns:
            Drupal details
        """
        drupal_info = {
            'cms': 'Drupal',
            'version': None,
            'security_issues': []
        }
        
        try:
            # Check CHANGELOG.txt for version
            changelog_url = urljoin(base_url, '/CHANGELOG.txt')
            response = await self.http_client.get(changelog_url)
            if response and response.status == 200:
                body = await response.text()
                version_match = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', body)
                if version_match:
                    drupal_info['version'] = version_match.group(1)
                drupal_info['security_issues'].append('CHANGELOG.txt accessible')
            
        except Exception:
            pass
        
        return drupal_info
    
    async def _detect_joomla_details(self, base_url: str) -> Dict[str, Any]:
        """
        Detect detailed Joomla information.
        
        Args:
            base_url: Joomla site URL
            
        Returns:
            Joomla details
        """
        joomla_info = {
            'cms': 'Joomla',
            'version': None,
            'security_issues': []
        }
        
        try:
            # Check for version in meta tags
            response = await self.http_client.get(base_url)
            if response and response.status == 200:
                body = await response.text()
                version_match = re.search(r'generator.*?joomla.*?(\d+\.\d+(?:\.\d+)?)', body, re.IGNORECASE)
                if version_match:
                    joomla_info['version'] = version_match.group(1)
            
        except Exception:
            pass
        
        return joomla_info
    
    async def _detect_javascript_libraries(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Detect JavaScript libraries and frameworks.
        
        Args:
            base_url: Base URL to analyze
            
        Returns:
            List of detected JavaScript libraries
        """
        js_libraries = []
        
        try:
            response = await self.http_client.get(base_url)
            if not response or response.status != 200:
                return js_libraries
            
            body = await response.text()
            
            # Common JavaScript library patterns
            js_patterns = {
                'jQuery': [r'jquery[.-](\d+\.\d+(?:\.\d+)?)', r'\$\.fn\.jquery'],
                'React': [r'react[.-](\d+\.\d+(?:\.\d+)?)', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'Vue.js': [r'vue[.-](\d+\.\d+(?:\.\d+)?)', r'Vue\.version'],
                'Angular': [r'angular[.-](\d+\.\d+(?:\.\d+)?)', r'ng-version'],
                'Bootstrap': [r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)', r'Bootstrap v'],
                'Lodash': [r'lodash[.-](\d+\.\d+(?:\.\d+)?)', r'_.VERSION'],
                'Moment.js': [r'moment[.-](\d+\.\d+(?:\.\d+)?)', r'moment\.version'],
                'D3.js': [r'd3[.-](\d+\.\d+(?:\.\d+)?)', r'd3\.version']
            }
            
            for lib_name, patterns in js_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, body, re.IGNORECASE)
                    for match in matches:
                        version = None
                        if match.groups():
                            version = match.group(1)
                        
                        js_libraries.append({
                            'name': lib_name,
                            'version': version,
                            'pattern_matched': pattern
                        })
                        break  # Only add once per library
        
        except Exception:
            pass
        
        return js_libraries
    
    def _extract_title(self, html: str) -> Optional[str]:
        """
        Extract page title from HTML.
        
        Args:
            html: HTML content
            
        Returns:
            Page title or None
        """
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return None

