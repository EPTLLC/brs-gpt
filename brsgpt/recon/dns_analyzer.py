# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
DNS Analyzer

Comprehensive DNS record analysis and security assessment:
- A, AAAA, CNAME, MX, NS, TXT, SOA record enumeration
- DNS security extensions (DNSSEC) validation
- DNS misconfiguration detection
- Subdomain takeover vulnerability assessment
- DNS cache poisoning indicators
- Mail server configuration analysis

Autonomous operation without external API dependencies.
"""

import asyncio
import socket
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re

import dns.resolver
import dns.reversename
import dns.query
import dns.message
from dns.exception import DNSException


class DNSAnalyzer:
    """Comprehensive DNS analysis and security assessment."""
    
    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize DNS analyzer.
        
        Args:
            settings: Reconnaissance settings
        """
        self.settings = settings
        self.dns_timeout = settings.get('dns_timeout', 5)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.dns_timeout
        self.resolver.lifetime = self.dns_timeout
        
        # Common record types to query
        self.record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV']
        
        # Indicators for subdomain takeover vulnerabilities
        self.takeover_indicators = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            'wordpress.com': 'WordPress.com',
            'ghost.io': 'Ghost',
            'bitbucket.io': 'Bitbucket',
            'surge.sh': 'Surge.sh',
            'netlify.com': 'Netlify',
            'vercel.app': 'Vercel',
            'firebase.com': 'Firebase',
            'cloudfront.net': 'CloudFront',
            'azurewebsites.net': 'Azure',
            'amazonaws.com': 'AWS',
            'googleusercontent.com': 'Google',
        }
    
    async def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive DNS analysis.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary containing DNS analysis results
        """
        analysis_results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'records': {},
            'security_issues': [],
            'mail_config': {},
            'nameservers': [],
            'dnssec_status': 'unknown',
            'subdomain_takeover_risks': [],
            'dns_misconfigurations': []
        }
        
        try:
            # Gather all DNS records
            analysis_results['records'] = await self._gather_dns_records(domain)
            
            # Analyze nameservers
            analysis_results['nameservers'] = await self._analyze_nameservers(domain)
            
            # Check DNSSEC status
            analysis_results['dnssec_status'] = await self._check_dnssec(domain)
            
            # Analyze mail configuration
            analysis_results['mail_config'] = await self._analyze_mail_config(domain, analysis_results['records'])

            # Analyze CAA records (certificate issuance policy)
            analysis_results['caa_records'] = await self._analyze_caa_records(domain)
            
            # Check for subdomain takeover vulnerabilities
            analysis_results['subdomain_takeover_risks'] = await self._check_subdomain_takeover(analysis_results['records'])
            
            # Detect DNS misconfigurations
            analysis_results['dns_misconfigurations'] = await self._detect_misconfigurations(domain, analysis_results['records'])

            # Check zone transfer exposure (AXFR)
            try:
                axfr_ns = await self._check_zone_transfer(domain, analysis_results.get('nameservers', []))
                if axfr_ns:
                    analysis_results['dns_misconfigurations'].append({
                        'type': 'zone_transfer_allowed',
                        'nameservers': axfr_ns,
                        'severity': 'high',
                        'description': 'DNS zone transfer (AXFR) is allowed on some nameservers'
                    })
            except Exception:
                pass
            
            # Identify security issues
            analysis_results['security_issues'] = await self._identify_security_issues(analysis_results)
            
        except Exception as e:
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    async def _gather_dns_records(self, domain: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Gather all DNS records for the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary of DNS records by type
        """
        records = {}
        
        for record_type in self.record_types:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self._query_dns_record, domain, record_type
                )
                
                if result:
                    records[record_type] = result
                    
            except Exception:
                # Record type not found or error occurred
                continue
        
        return records
    
    def _query_dns_record(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """
        Query specific DNS record type.
        
        Args:
            domain: Target domain
            record_type: DNS record type
            
        Returns:
            List of DNS records
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            records = []
            
            for answer in answers:
                record_data = {
                    'type': record_type,
                    'value': str(answer),
                    'ttl': answers.ttl
                }
                
                # Add specific fields based on record type
                if record_type == 'MX':
                    record_data['priority'] = answer.preference
                    record_data['exchange'] = str(answer.exchange)
                elif record_type == 'SOA':
                    record_data['mname'] = str(answer.mname)
                    record_data['rname'] = str(answer.rname)
                    record_data['serial'] = answer.serial
                    record_data['refresh'] = answer.refresh
                    record_data['retry'] = answer.retry
                    record_data['expire'] = answer.expire
                    record_data['minimum'] = answer.minimum
                elif record_type == 'SRV':
                    record_data['priority'] = answer.priority
                    record_data['weight'] = answer.weight
                    record_data['port'] = answer.port
                    record_data['target'] = str(answer.target)
                
                records.append(record_data)
            
            return records
            
        except DNSException:
            return []
    
    async def _analyze_nameservers(self, domain: str) -> List[Dict[str, Any]]:
        """
        Analyze nameserver configuration.
        
        Args:
            domain: Target domain
            
        Returns:
            List of nameserver information
        """
        nameservers = []
        
        try:
            ns_records = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, domain, 'NS'
            )
            
            for ns in ns_records:
                ns_info = {
                    'nameserver': str(ns),
                    'ip_addresses': [],
                    'location': 'unknown',
                    'provider': 'unknown'
                }
                
                # Resolve nameserver IP addresses
                try:
                    a_records = await asyncio.get_event_loop().run_in_executor(
                        None, self.resolver.resolve, str(ns), 'A'
                    )
                    ns_info['ip_addresses'] = [str(ip) for ip in a_records]
                except DNSException:
                    pass
                
                # Identify nameserver provider
                ns_info['provider'] = self._identify_ns_provider(str(ns))
                
                nameservers.append(ns_info)
                
        except DNSException:
            pass
        
        return nameservers
    
    def _identify_ns_provider(self, nameserver: str) -> str:
        """
        Identify nameserver provider based on hostname.
        
        Args:
            nameserver: Nameserver hostname
            
        Returns:
            Provider name
        """
        providers = {
            'cloudflare.com': 'Cloudflare',
            'googledomains.com': 'Google Domains',
            'awsdns': 'Amazon Route 53',
            'azure-dns': 'Microsoft Azure DNS',
            'nsone.net': 'NS1',
            'dnsimple.com': 'DNSimple',
            'dns.google': 'Google Public DNS',
            'quad9.net': 'Quad9',
            'opendns.com': 'OpenDNS',
        }
        
        for pattern, provider in providers.items():
            if pattern in nameserver.lower():
                return provider
        
        return 'Unknown'
    
    async def _check_dnssec(self, domain: str) -> str:
        """
        Check DNSSEC validation status.
        
        Args:
            domain: Target domain
            
        Returns:
            DNSSEC status
        """
        try:
            # Child zone must have DNSKEY; parent zone must publish DS for full enablement
            dnskey_records = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, domain, 'DNSKEY'
            )

            if dnskey_records:
                try:
                    # DS owner name is the child domain in the parent zone
                    ds_records = await asyncio.get_event_loop().run_in_executor(
                        None, self.resolver.resolve, domain, 'DS'
                    )
                    if ds_records:
                        return 'enabled'
                except DNSException:
                    # No DS found: likely only DNSKEY configured
                    return 'partially_enabled'

        except DNSException:
            # No DNSKEY: treated as disabled
            return 'disabled'

        return 'disabled'
    
    async def _analyze_mail_config(self, domain: str, records: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Analyze mail server configuration.
        
        Args:
            domain: Target domain
            records: DNS records
            
        Returns:
            Mail configuration analysis
        """
        mail_config = {
            'mx_records': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_records': [],
            'security_score': 0,
            'vulnerabilities': []
        }
        
        # Analyze MX records
        if 'MX' in records:
            mail_config['mx_records'] = records['MX']
            mail_config['security_score'] += 20
        
        # Check for SPF record
        if 'TXT' in records:
            for txt_record in records['TXT']:
                txt_value = txt_record['value'].lower()
                
                if txt_value.startswith('v=spf1'):
                    mail_config['spf_record'] = txt_record['value']
                    mail_config['security_score'] += 25
                    
                    # Check SPF configuration quality
                    if 'all' not in txt_value:
                        mail_config['vulnerabilities'].append('SPF record missing all mechanism')
                    elif '~all' in txt_value:
                        mail_config['security_score'] += 10
                    elif '-all' in txt_value:
                        mail_config['security_score'] += 15
        
        # Check for DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, dmarc_domain, 'TXT'
            )
            
            for record in dmarc_records:
                if str(record).startswith('v=DMARC1'):
                    mail_config['dmarc_record'] = str(record)
                    mail_config['security_score'] += 30
                    
                    # Analyze DMARC policy
                    rec_lower = str(record).lower()
                    if 'p=reject' in rec_lower:
                        mail_config['security_score'] += 15
                    elif 'p=quarantine' in rec_lower:
                        mail_config['security_score'] += 10
                    elif 'p=none' in rec_lower:
                        mail_config['vulnerabilities'].append('DMARC policy set to none')
                    
        except DNSException:
            mail_config['vulnerabilities'].append('DMARC record not found')
        
        # Check for common DKIM selectors
        dkim_selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim']
        for selector in dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_records = await asyncio.get_event_loop().run_in_executor(
                    None, self.resolver.resolve, dkim_domain, 'TXT'
                )
                
                for record in dkim_records:
                    if 'k=rsa' in str(record) or 'p=' in str(record):
                        mail_config['dkim_records'].append({
                            'selector': selector,
                            'record': str(record)
                        })
                        mail_config['security_score'] += 15
                        break
                        
            except DNSException:
                continue
        
        return mail_config

    async def _analyze_caa_records(self, domain: str) -> List[Dict[str, Any]]:
        """Analyze CAA records (Certificate Authority Authorization)."""
        caa_list: List[Dict[str, Any]] = []
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, domain, 'CAA'
            )
            for ans in answers:
                try:
                    caa_list.append({
                        'flags': getattr(ans, 'flags', None),
                        'tag': getattr(ans, 'tag', str(ans).split(' ')[1] if ' ' in str(ans) else 'issue'),
                        'value': getattr(ans, 'value', str(ans))
                    })
                except Exception:
                    caa_list.append({'raw': str(ans)})
        except DNSException:
            pass
        return caa_list
    
    async def _check_subdomain_takeover(self, records: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Check for potential subdomain takeover vulnerabilities.
        
        Args:
            records: DNS records
            
        Returns:
            List of potential takeover risks
        """
        risks = []
        
        # Check CNAME records for takeover indicators
        if 'CNAME' in records:
            for cname_record in records['CNAME']:
                cname_value = cname_record['value'].lower()
                
                for indicator, service in self.takeover_indicators.items():
                    if indicator in cname_value:
                        risks.append({
                            'type': 'subdomain_takeover',
                            'service': service,
                            'cname': cname_value,
                            'risk_level': 'high',
                            'description': f'CNAME points to {service} which may be unclaimed'
                        })
        
        # Check A records pointing to cloud services
        if 'A' in records:
            for a_record in records['A']:
                ip = a_record['value']
                
                # Check for common cloud service IP ranges
                cloud_ranges = {
                    '13.': 'AWS',
                    '52.': 'AWS',
                    '54.': 'AWS',
                    '20.': 'Azure',
                    '40.': 'Azure',
                    '104.': 'Azure',
                    '35.': 'Google Cloud',
                    '34.': 'Google Cloud',
                }
                
                for prefix, provider in cloud_ranges.items():
                    if ip.startswith(prefix):
                        risks.append({
                            'type': 'cloud_service_ip',
                            'provider': provider,
                            'ip': ip,
                            'risk_level': 'medium',
                            'description': f'IP address belongs to {provider} - verify resource is still active'
                        })
                        break
        
        return risks
    
    async def _detect_misconfigurations(self, domain: str, records: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Detect DNS misconfigurations.
        
        Args:
            domain: Target domain
            records: DNS records
            
        Returns:
            List of detected misconfigurations
        """
        misconfigurations = []
        
        # Check for wildcard DNS
        try:
            random_subdomain = f"nonexistent-{datetime.now().microsecond}.{domain}"
            wildcard_result = await asyncio.get_event_loop().run_in_executor(
                None, self.resolver.resolve, random_subdomain, 'A'
            )
            
            if wildcard_result:
                misconfigurations.append({
                    'type': 'wildcard_dns',
                    'severity': 'medium',
                    'description': 'Wildcard DNS record detected - may aid in reconnaissance'
                })
                
        except DNSException:
            # No wildcard DNS (expected)
            pass
        
        # Check for excessive TTL values
        for record_type, record_list in records.items():
            for record in record_list:
                if record.get('ttl', 0) > 86400:  # More than 24 hours
                    misconfigurations.append({
                        'type': 'high_ttl',
                        'record_type': record_type,
                        'ttl': record['ttl'],
                        'severity': 'low',
                        'description': f'High TTL value ({record["ttl"]}s) may slow DNS updates'
                    })
        
        # Check for missing reverse DNS
        if 'A' in records:
            for a_record in records['A']:
                try:
                    reverse_name = dns.reversename.from_address(a_record['value'])
                    ptr_result = await asyncio.get_event_loop().run_in_executor(
                        None, self.resolver.resolve, reverse_name, 'PTR'
                    )
                    
                except DNSException:
                    misconfigurations.append({
                        'type': 'missing_reverse_dns',
                        'ip': a_record['value'],
                        'severity': 'low',
                        'description': f'No reverse DNS (PTR) record for IP {a_record["value"]}'
                    })
        
        return misconfigurations
    
    async def _identify_security_issues(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify overall DNS security issues.
        
        Args:
            analysis_results: Complete DNS analysis results
            
        Returns:
            List of security issues
        """
        security_issues = []
        
        # DNSSEC not enabled
        if analysis_results['dnssec_status'] == 'disabled':
            security_issues.append({
                'type': 'dnssec_disabled',
                'severity': 'medium',
                'description': 'DNSSEC is not enabled - domain vulnerable to DNS spoofing'
            })
        
        # Poor mail security configuration
        mail_score = analysis_results['mail_config']['security_score']
        if mail_score < 50:
            security_issues.append({
                'type': 'poor_mail_security',
                'severity': 'high',
                'score': mail_score,
                'description': 'Mail security configuration is inadequate (SPF/DMARC/DKIM)'
            })

        # DMARC policy none
        dmarc = analysis_results['mail_config'].get('dmarc_record')
        if dmarc and 'p=none' in str(dmarc).lower():
            security_issues.append({
                'type': 'dmarc_policy_none',
                'severity': 'medium',
                'description': 'DMARC policy is set to none; recommended quarantine or reject'
            })

        # SPF overly permissive (+all)
        spf = analysis_results['mail_config'].get('spf_record')
        if spf and '+all' in str(spf).lower():
            security_issues.append({
                'type': 'spf_permissive_all',
                'severity': 'high',
                'description': 'SPF record contains +all (overly permissive)'
            })

        # Missing CAA
        if not analysis_results.get('caa_records'):
            security_issues.append({
                'type': 'missing_caa',
                'severity': 'low',
                'description': 'No CAA records present; consider restricting certificate issuance'
            })

        # Subdomain takeover risks
        if analysis_results['subdomain_takeover_risks']:
            security_issues.append({
                'type': 'subdomain_takeover_risk',
                'severity': 'high',
                'count': len(analysis_results['subdomain_takeover_risks']),
                'description': 'Potential subdomain takeover vulnerabilities detected'
            })

        return security_issues

    async def _check_zone_transfer(self, domain: str, nameservers: List[Dict[str, Any]]) -> List[str]:
        """Attempt AXFR against nameservers to detect zone transfer exposure."""
        vulnerable_ns: List[str] = []
        for ns in nameservers:
            ns_host = ns.get('nameserver') or ''
            try:
                zone = await asyncio.get_event_loop().run_in_executor(
                    None, dns.zone.from_xfr, dns.query.xfr(str(ns_host).rstrip('.'), domain)
                )
                if zone:
                    vulnerable_ns.append(str(ns_host))
            except Exception:
                continue
        return vulnerable_ns

