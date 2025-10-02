# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
Subdomain Enumerator

Built-in subdomain enumeration using multiple techniques:
- Dictionary-based brute force with common subdomain lists
- DNS zone transfer attempts
- Certificate transparency log queries
- Search engine dorking (when possible)
- Reverse DNS lookups
- Integration with Amass and Subfinder (if available)

No external API dependencies - fully autonomous operation.
"""

import asyncio
import socket
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse
import ssl
import json

import dns.resolver
import dns.zone
import dns.query
from dns.exception import DNSException
from rich.console import Console

from ..utils.http_client import HttpClient

console = Console()

# Optional integrations
try:
    from .amass_integration import AmassIntegration
except ImportError:
    AmassIntegration = None  # type: ignore

try:
    from .subfinder_integration import SubfinderIntegration
except ImportError:
    SubfinderIntegration = None  # type: ignore


class SubdomainEnumerator:
    """Autonomous subdomain enumeration without API dependencies."""
    
    def __init__(self, http_client: HttpClient, settings: Dict[str, Any]):
        """
        Initialize subdomain enumerator.
        
        Args:
            http_client: HTTP client for web requests
            settings: Reconnaissance settings
        """
        self.http_client = http_client
        self.settings = settings
        self.max_subdomains = settings.get('max_subdomains', 1000)
        self.dns_timeout = settings.get('dns_timeout', 5)
        self.concurrent_requests = settings.get('concurrent_requests', 32)
        
        # Initialize optional integrations
        self.amass = AmassIntegration(settings) if AmassIntegration else None
        self.subfinder = SubfinderIntegration(settings) if SubfinderIntegration else None
        
        # Common subdomain wordlist (built-in)
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mail2', 'www2', 'test',
            'ns', 'news', 'dev', 'admin', 'web', 'blog', 'forum', 'shop', 'api', 'cdn',
            'mobile', 'app', 'secure', 'vpn', 'ssl', 'support', 'help', 'docs', 'wiki',
            'staging', 'beta', 'demo', 'preview', 'old', 'new', 'backup', 'server',
            'database', 'db', 'mysql', 'postgres', 'redis', 'elastic', 'search', 'log',
            'monitor', 'stats', 'analytics', 'metrics', 'grafana', 'kibana', 'jenkins',
            'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'code', 'build',
            'ci', 'cd', 'deploy', 'release', 'prod', 'production', 'live', 'www1',
            'assets', 'static', 'media', 'images', 'img', 'css', 'js', 'files',
            'download', 'downloads', 'upload', 'uploads', 'share', 'public', 'private',
            'internal', 'intranet', 'extranet', 'portal', 'dashboard', 'panel', 'control',
            'management', 'manager', 'console', 'terminal', 'shell', 'ssh', 'sftp',
            'exchange', 'owa', 'outlook', 'office', 'sharepoint', 'teams', 'skype',
            'conference', 'meet', 'zoom', 'webex', 'gotomeeting', 'video', 'voice',
            'crm', 'erp', 'hr', 'finance', 'accounting', 'billing', 'invoice', 'payment',
            'shop', 'store', 'cart', 'checkout', 'order', 'orders', 'customer', 'client',
            'partner', 'vendor', 'supplier', 'reseller', 'affiliate', 'referral',
            'marketing', 'campaign', 'newsletter', 'email', 'subscribe', 'unsubscribe',
            'social', 'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'tiktok',
            'community', 'forum', 'discussion', 'chat', 'message', 'comment', 'review',
            'feedback', 'survey', 'poll', 'vote', 'rating', 'testimonial', 'case-study'
        ]
        
        # Additional technical subdomains
        self.technical_subdomains = [
            'kubernetes', 'k8s', 'docker', 'container', 'registry', 'harbor', 'nexus',
            'sonar', 'quality', 'security', 'vault', 'secret', 'config', 'env',
            'prometheus', 'alert', 'notification', 'webhook', 'callback', 'trigger',
            'queue', 'worker', 'job', 'task', 'scheduler', 'cron', 'batch', 'process',
            'lambda', 'function', 'serverless', 'edge', 'proxy', 'gateway', 'lb',
            'balancer', 'cluster', 'node', 'master', 'slave', 'primary', 'secondary',
            'replica', 'mirror', 'cache', 'memcache', 'varnish', 'nginx', 'apache',
            'tomcat', 'jboss', 'wildfly', 'websphere', 'weblogic', 'iis', 'lighttpd'
        ]
    
    async def enumerate(self, domain: str) -> List[str]:
        """
        Perform comprehensive subdomain enumeration.

        Args:
            domain: Target domain

        Returns:
            List of discovered subdomains
        """
        discovered_subdomains: Set[str] = set()

        try:
            # Lightning mode optimization: ultra-fast scanning
            if self.max_subdomains <= 50:  # Lightning mode detected
                return await self._lightning_enumerate(domain)
            
            # Try advanced tools first (if available)
            if self.subfinder and self.subfinder.subfinder_available:
                console.print("[dim cyan]Using Subfinder for enumeration...[/dim cyan]")
                subfinder_results = await self.subfinder.enumerate_subdomains(domain)
                for result in subfinder_results:
                    if result.get('name'):
                        discovered_subdomains.add(result['name'])
            
            if self.amass and self.amass.amass_available:
                console.print("[dim cyan]Using Amass for enumeration...[/dim cyan]")
                amass_results = await self.amass.enumerate_subdomains(domain, passive_only=True)
                for result in amass_results:
                    if result.get('name'):
                        discovered_subdomains.add(result['name'])
            
            # Full enumeration for other modes
            # Method 1: Dictionary-based brute force
            dict_subdomains = await self._dictionary_bruteforce(domain)
            discovered_subdomains.update(dict_subdomains)

            # Method 2: DNS zone transfer attempt
            zone_subdomains = await self._zone_transfer_attempt(domain)
            discovered_subdomains.update(zone_subdomains)

            # Method 3: Certificate transparency logs
            ct_subdomains = await self._certificate_transparency(domain)
            discovered_subdomains.update(ct_subdomains)

            # Method 4: Reverse DNS lookups
            reverse_subdomains = await self._reverse_dns_lookup(domain)
            discovered_subdomains.update(reverse_subdomains)

            # Method 5: Common variations
            variation_subdomains = await self._generate_variations(domain, list(discovered_subdomains))
            discovered_subdomains.update(variation_subdomains)

        except Exception as e:
            # Continue with partial results
            pass

        # Validate and filter results
        valid_subdomains = await self._validate_subdomains(list(discovered_subdomains))

        # Limit results to prevent overwhelming
        return valid_subdomains[:self.max_subdomains]
    
    async def _lightning_enumerate(self, domain: str) -> List[str]:
        """
        Ultra-fast subdomain enumeration for lightning mode.
        Only tests the most common subdomains.
        """
        discovered: Set[str] = set()
        
        # Only test the most common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog']
        
        # Test with short timeout
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        
        async def check_subdomain(subdomain: str) -> Optional[str]:
            async with semaphore:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    # Quick DNS resolution test
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2  # Very short timeout
                    resolver.lifetime = 2
                    
                    await asyncio.wait_for(
                        asyncio.to_thread(resolver.resolve, full_domain, 'A'),
                        timeout=3.0
                    )
                    return full_domain
                except:
                    return None
        
        # Test all common subdomains concurrently
        tasks = [check_subdomain(sub) for sub in common_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect valid results
        for result in results:
            if isinstance(result, str):
                discovered.add(result)
        
        # Always add www if domain resolves (common case)
        try:
            www_domain = f"www.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            await asyncio.wait_for(
                asyncio.to_thread(resolver.resolve, www_domain, 'A'),
                timeout=3.0
            )
            discovered.add(www_domain)
        except:
            pass
        
        return sorted(list(discovered))
    
    async def _dictionary_bruteforce(self, domain: str) -> List[str]:
        """
        Perform dictionary-based subdomain brute force.
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains
        """
        discovered = []
        wordlist = self.common_subdomains + self.technical_subdomains
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.concurrent_requests)
        
        async def check_subdomain(subdomain: str) -> Optional[str]:
            async with semaphore:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    
                    # DNS resolution check
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = self.dns_timeout
                    resolver.lifetime = self.dns_timeout
                    
                    await asyncio.get_event_loop().run_in_executor(
                        None, resolver.resolve, full_domain, 'A'
                    )
                    return full_domain
                    
                except DNSException:
                    return None
                except Exception:
                    return None
        
        # Execute concurrent DNS lookups
        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        for result in results:
            if isinstance(result, str):
                discovered.append(result)
        
        return discovered
    
    async def _zone_transfer_attempt(self, domain: str) -> List[str]:
        """
        Attempt DNS zone transfer.
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered subdomains from zone transfer
        """
        discovered = []
        
        try:
            # Get name servers for the domain
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.dns_timeout
            
            ns_records = await asyncio.get_event_loop().run_in_executor(
                None, resolver.resolve, domain, 'NS'
            )
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = await asyncio.get_event_loop().run_in_executor(
                        None, dns.zone.from_xfr, dns.query.xfr(str(ns), domain)
                    )
                    
                    # Extract subdomains from zone
                    for name, node in zone.nodes.items():
                        if name != dns.name.empty:
                            subdomain = f"{name}.{domain}"
                            discovered.append(subdomain)
                            
                except Exception:
                    # Zone transfer not allowed (expected)
                    continue
                    
        except Exception:
            # No NS records or other DNS error
            pass
        
        return discovered
    
    async def _certificate_transparency(self, domain: str) -> List[str]:
        """
        Query certificate transparency logs.
        
        Args:
            domain: Target domain
            
        Returns:
            List of subdomains from CT logs
        """
        discovered = []
        
        try:
            # Query crt.sh (certificate transparency database)
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            response = await self.http_client.get(ct_url)
            if response and response.status == 200:
                ct_data = await response.json()
                
                for cert in ct_data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name.endswith(f".{domain}") and '*' not in name:
                                discovered.append(name)
                                
        except Exception:
            # CT query failed, continue with other methods
            pass
        
        return list(set(discovered))
    
    async def _reverse_dns_lookup(self, domain: str) -> List[str]:
        """
        Perform reverse DNS lookups on common IP ranges.
        
        Args:
            domain: Target domain
            
        Returns:
            List of subdomains from reverse DNS
        """
        discovered = []
        
        try:
            # Get IP address of main domain
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.dns_timeout
            
            a_records = await asyncio.get_event_loop().run_in_executor(
                None, resolver.resolve, domain, 'A'
            )
            
            for record in a_records:
                ip = str(record)
                ip_parts = ip.split('.')
                
                # Check nearby IPs in the same subnet
                base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                
                for i in range(max(0, int(ip_parts[3]) - 5), 
                             min(256, int(ip_parts[3]) + 5)):
                    try:
                        test_ip = f"{base_ip}.{i}"
                        hostname = await asyncio.get_event_loop().run_in_executor(
                            None, socket.gethostbyaddr, test_ip
                        )
                        
                        if hostname[0].endswith(f".{domain}"):
                            discovered.append(hostname[0])
                            
                    except socket.herror:
                        continue
                    except Exception:
                        continue
                        
        except Exception:
            # Reverse DNS failed
            pass
        
        return discovered
    
    async def _generate_variations(self, domain: str, existing_subdomains: List[str]) -> List[str]:
        """
        Generate subdomain variations based on discovered subdomains.
        
        Args:
            domain: Target domain
            existing_subdomains: Already discovered subdomains
            
        Returns:
            List of subdomain variations
        """
        variations = []
        prefixes = ['dev-', 'test-', 'staging-', 'prod-', 'beta-', 'alpha-', 'old-', 'new-']
        suffixes = ['-dev', '-test', '-staging', '-prod', '-beta', '-alpha', '-old', '-new']
        numbers = ['1', '2', '3', '01', '02', '03']
        
        for subdomain in existing_subdomains[:20]:  # Limit to prevent explosion
            base_name = subdomain.split('.')[0]
            
            # Add prefixes
            for prefix in prefixes:
                variations.append(f"{prefix}{base_name}.{domain}")
            
            # Add suffixes
            for suffix in suffixes:
                variations.append(f"{base_name}{suffix}.{domain}")
            
            # Add numbers
            for number in numbers:
                variations.append(f"{base_name}{number}.{domain}")
        
        return variations
    
    async def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """
        Validate discovered subdomains by checking DNS resolution and HTTP response.
        
        Args:
            subdomains: List of potential subdomains
            
        Returns:
            List of validated subdomains
        """
        valid_subdomains = []
        semaphore = asyncio.Semaphore(self.concurrent_requests)
        
        async def validate_subdomain(subdomain: str) -> Optional[str]:
            async with semaphore:
                try:
                    # DNS validation
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = self.dns_timeout
                    
                    await asyncio.get_event_loop().run_in_executor(
                        None, resolver.resolve, subdomain, 'A'
                    )
                    
                    # HTTP validation (optional - check if web server responds)
                    https_url = f"https://{subdomain}"
                    http_url = f"http://{subdomain}"
                    
                    # Try HTTPS first, then HTTP
                    for url in [https_url, http_url]:
                        response = await self.http_client.get(url)
                        if response and response.status < 500:
                            return subdomain
                    
                    # Even if HTTP fails, subdomain exists if DNS resolves
                    return subdomain
                    
                except Exception:
                    return None
        
        # Validate all subdomains concurrently
        tasks = [validate_subdomain(sub) for sub in set(subdomains)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful validations
        for result in results:
            if isinstance(result, str):
                valid_subdomains.append(result)
        
        return sorted(list(set(valid_subdomains)))

