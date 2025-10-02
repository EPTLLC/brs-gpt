from __future__ import annotations

# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-15 00:00:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

from datetime import datetime
from typing import Any, Dict, List


def prepare_html_template_data(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    target = analysis_results.get('target', 'Unknown')
    recon_data = analysis_results.get('recon_data', {})
    xss_data = analysis_results.get('xss_data', {})
    ai_analysis = analysis_results.get('ai_analysis', {})

    vulnerabilities = xss_data.get('vulnerabilities', [])

    total_vulnerabilities = len(vulnerabilities)
    critical_vulnerabilities = len([v for v in vulnerabilities if v.get('severity') == 'high'])
    subdomains_found = len(recon_data.get('subdomains', []))
    open_ports = len(recon_data.get('open_ports', []))

    executive_summary = ai_analysis.get('final_synthesis', {})
    live_analysis = ai_analysis.get('live_analysis', {})
    ai_rationale = ai_analysis.get('rationale', '')

    if not executive_summary:
        executive_summary = {
            'security_posture_rating': 'Fair' if total_vulnerabilities > 0 else 'Good',
            'executive_overview': f'Security analysis completed for {target}. Found {total_vulnerabilities} potential issues.',
        }

    overall_risk_score = min(10, max(1, 5 + (critical_vulnerabilities * 2) + (total_vulnerabilities // 5)))

    # Normalize DNS data: support both 'dns_records' (legacy) and 'dns_analysis' (current)
    dns_data = recon_data.get('dns_records') or recon_data.get('dns_analysis', {})

    # Optional cost/performance metrics
    cost_metrics = analysis_results.get('cost_metrics', {}) or {}
    perf_metrics = analysis_results.get('performance_metrics', {}) or {}

    # Compute red-lamp style indicator (very simple heuristic)
    risk_level = 'low'
    if overall_risk_score >= 8 or open_ports >= 20:
        risk_level = 'critical'
    elif overall_risk_score >= 6 or open_ports >= 10:
        risk_level = 'high'
    elif overall_risk_score >= 4 or open_ports >= 5:
        risk_level = 'medium'

    # Threat intel (from deterministic risk model components)
    risk_model = analysis_results.get('risk_model') or {}
    risk_components = risk_model.get('components', {}) if isinstance(risk_model, dict) else {}
    threat_intel = risk_components.get('threat_intel', {}) if isinstance(risk_components, dict) else {}
    threat_feeds = risk_components.get('threat_feeds', {}) if isinstance(risk_components, dict) else {}

    # Derive basic attack paths (visual chain) from available findings
    attack_paths: List[Dict[str, Any]] = []
    try:
        # Example chain: API key -> S3-like bucket -> Critical
        ai_web_checks = (recon_data.get('technologies') or {})
        # If we had API keys (from tech detector), or S3-like endpoints, synthesize a simple chain
        s3_like = []
        try:
            s3_like = analysis_results.get('recon_data', {}).get('service_endpoints', {}).get('s3_like', [])  # type: ignore
        except Exception:
            s3_like = []
        if threat_intel.get('default_creds'):
            attack_paths.append({
                'title': 'Default credentials exposure',
                'steps': [
                    'Service with known default credentials detected',
                    'Brute-force or login with defaults',
                    'Privilege escalation and lateral movement'
                ]
            })
        if s3_like:
            attack_paths.append({
                'title': 'API key leak to S3-like bucket compromise',
                'steps': [
                    'API key or public endpoint discovered',
                    'ListBucketResult indicates accessible bucket',
                    'Exfiltrate sensitive data'
                ]
            })
    except Exception:
        attack_paths = []

    # Merge CVEs from local KB and offline feeds (dedup)
    kb_cves = threat_intel.get('cves', []) if isinstance(threat_intel, dict) else []
    feed_cves = threat_feeds.get('cves', []) if isinstance(threat_feeds, dict) else []
    merged_cves = []
    try:
        seen = set()
        for c in (kb_cves or []) + (feed_cves or []):
            if c not in seen:
                seen.add(c); merged_cves.append(c)
    except Exception:
        merged_cves = kb_cves or []

    exploit_refs = threat_feeds.get('exploits', []) if isinstance(threat_feeds, dict) else []

    # DevOps/Infra exposure summary + PoC hints
    devops_exposure: List[Dict[str, Any]] = []
    try:
        by_service = threat_intel.get('by_service', {}) if isinstance(threat_intel, dict) else {}
        exposure_map = {
            'docker_api': 'If :2375 open without TLS, remote container control (GET /info).',
            'kubernetes_api': 'Check /version and /api; RBAC misconfig may allow read.',
            'jenkins': 'Try /api/json and crumb; default creds admin:admin are common.',
            'gitlab': 'Check /-/health and sign-up policy; assess visibility.',
            'sonarqube': 'Hit /api/system/health and /api/server/version; default creds.',
            'grafana': 'Test anonymous access; default admin:admin.',
            'prometheus': 'Open /metrics can leak internal targets.',
            'vault': 'GET /v1/sys/health; verify sealed/initialized; never expose.',
            'consul': 'Open leader/kv endpoints leak topology and secrets.',
            'minio': 'GET /minio/health/live; default minioadmin creds; list buckets.',
            'etcd': 'Open /version; exposed etcd reveals cluster secrets.',
            'docker_registry': 'GET /v2/; may enumerate repositories without auth.',
            'harbor': 'Harbor API/UI; default creds admin:Harbor12345.',
            'rabbitmq': 'Management API often on 15672; default guest:guest.',
            'kafka': 'Broker 9092 often unauthenticated; metadata reveals topics.',
            'smb': 'Check for SMBv1 and guest access; enumerate shares.',
            'ldap': 'Anonymous bind may list users; restrict access.',
            'ldaps': 'Validate TLS and access controls.',
            'winrm': 'Ensure auth and HTTPS; 5985 exposes WS-Man.',
            'rdp': 'Require NLA; brute-force exposure risk.',
            'nfs': 'Exported shares to 0.0.0.0/0 leak data.',
            'iscsi': 'Targets may be listable without auth.',
        }
        # Produce a basic criticality order (network mgmt > secrets > build > metrics)
        priority_order = {
            'vault': 1, 'consul': 2, 'docker_api': 3, 'kubernetes_api': 4, 'jenkins': 5,
            'gitlab': 6, 'sonarqube': 7, 'prometheus': 8, 'grafana': 9, 'docker_registry': 10,
            'harbor': 11, 'rabbitmq': 12, 'kafka': 13, 'etcd': 14, 'minio': 15,
            'smb': 16, 'ldap': 17, 'ldaps': 18, 'winrm': 19, 'rdp': 20, 'nfs': 21, 'iscsi': 22
        }
        for svc, meta in (by_service or {}).items():
            hint = exposure_map.get(svc)
            if hint:
                ports = meta.get('ports') or []
                devops_exposure.append({'service': svc, 'ports': ports, 'poc': hint, 'prio': priority_order.get(svc, 99)})
    except Exception:
        devops_exposure = []

    # Sort by priority, then by number of ports (desc)
    try:
        devops_exposure.sort(key=lambda x: (x.get('prio', 99), -len(x.get('ports', []))))
    except Exception:
        pass

    # Web checks summary from TechnologyDetector (if present)
    web_checks_summary: Dict[str, Any] = {}
    try:
        tech = recon_data.get('technologies') or {}
        web_checks = tech.get('web_checks') or {}
        web_checks_summary = {
            'graphql': web_checks.get('graphql') or {},
            'grpc': web_checks.get('grpc') or {},
            'oauth': web_checks.get('oauth') or {},
            'oidc': web_checks.get('oidc') or {},
            'jwt': web_checks.get('jwt') or {},
            'websockets_count': len(web_checks.get('websockets') or []),
            'api_keys_count': len(web_checks.get('api_keys') or []),
        }
    except Exception:
        web_checks_summary = {}

    # Optional AI correlation/compliance
    ai_correlation = analysis_results.get('correlation', {}) or {}
    compliance_map = analysis_results.get('compliance', {}) or {}

    template_data = {
        'target_domain': target,
        'scan_date': analysis_results.get('start_time', 'Unknown'),
        'ai_model': analysis_results.get('metadata', {}).get('ai_model', 'disabled'),
        'ai_enabled': ai_analysis.get('final_synthesis') is not None,
        'ai_rationale': ai_rationale,
        'executive_summary': executive_summary,
        'overall_risk_score': overall_risk_score,
        'risk_level': risk_level,
        'total_vulnerabilities': total_vulnerabilities,
        'critical_vulnerabilities': critical_vulnerabilities,
        'subdomains_found': subdomains_found,
        'open_ports': open_ports,
        'critical_findings': executive_summary.get('key_findings', []),
        'xss_vulnerabilities': vulnerabilities,
        'attack_scenarios': live_analysis.get('attack_scenarios', []),
        'immediate_actions': executive_summary.get('immediate_actions', ['Review security findings', 'Apply recommended patches']),
        'strategic_recommendations': executive_summary.get('strategic_recommendations', ['Implement security monitoring', 'Regular security assessments']),
        'include_technical_details': True,
        'data_quality': analysis_results.get('metadata', {}).get('data_quality', {}),
        'recon_summary': {
            'subdomains_found': subdomains_found,
            'open_ports': open_ports,
            'verified_open_ports': recon_data.get('verified_port_count', 0),
            'technologies_detected': len(recon_data.get('technologies', {})),
            'dns_security_issues': len(dns_data.get('security_issues', [])) if isinstance(dns_data, dict) else 0,
            'dnssec_status': dns_data.get('dnssec_status', 'unknown') if isinstance(dns_data, dict) else 'unknown',
            'caa_present': bool(dns_data.get('caa_records')) if isinstance(dns_data, dict) else False,
            'axfr_exposed': False,
            'spf_plus_all': False,
        },
        'xss_summary': {
            'contexts_affected': list(set(v.get('context', {}).get('type', 'unknown') for v in vulnerabilities)),
            'waf_bypasses_found': len([v for v in vulnerabilities if v.get('waf_bypass', False)]),
        },
        'dnssec_status_badge': 'badge-low' if (isinstance(dns_data, dict) and dns_data.get('dnssec_status') == 'enabled') else 'badge-medium',
        'payload_success_rate': round((critical_vulnerabilities / max(1, total_vulnerabilities)) * 100, 1),
        'report_timestamp': analysis_results.get('end_time', 'Unknown'),
        # Security headers (if provided by vulnerability phase)
        'header_hardening_percent': (analysis_results.get('xss_data', {})
            .get('security_headers_analysis', {})
            .get('header_hardening_percent', 0.0)),
        'header_findings': (analysis_results.get('xss_data', {})
            .get('security_headers_analysis', {})
            .get('findings', [])),
        # Threat intel for rendering
        'threat_intel_by_service': threat_intel.get('by_service', {}),
        'threat_intel_cves': merged_cves,
        'threat_intel_default_creds': threat_intel.get('default_creds', []),
        'threat_intel_critical_services': threat_intel.get('critical_services', []),
        'exploit_references': exploit_refs,
        'attack_paths_visual': attack_paths,
        'devops_exposure': devops_exposure,
        'web_checks': web_checks_summary,
        'ai_correlation_insights': ai_correlation.get('insights', []),
        'ai_correlation_highlights': ai_correlation.get('highlights', []),
        'compliance_frameworks': compliance_map.get('frameworks', {}),
        'compliance_summary': compliance_map.get('summary', ''),
        'pocs': (analysis_results.get('poc_generator', {}) or {}).get('pocs', []),
    # Render-friendly metrics
    'cost_queries': cost_metrics.get('queries', 0),
    'cost_tokens': cost_metrics.get('tokens', 0),
    'cost_usd': cost_metrics.get('cost_usd', 0.0),
    'perf_avg_query_time': perf_metrics.get('avg_query_time', 0.0),
    'perf_rate_limit': perf_metrics.get('rate_limit'),
    'perf_request_timeout': perf_metrics.get('request_timeout'),
    }

    return template_data


def calculate_scan_duration(analysis_results: Dict[str, Any]) -> str:
    start_time = analysis_results.get('start_time')
    end_time = analysis_results.get('end_time')
    if start_time and end_time:
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            duration = end - start
            total_seconds = int(duration.total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        except Exception:
            return "Unknown"
    return "Unknown"


def calculate_payload_success_rate(xss_data: Dict[str, Any]) -> int:
    vulnerabilities = xss_data.get('vulnerabilities', [])
    if not vulnerabilities:
        return 0
    successful_payloads = len([v for v in vulnerabilities if v.get('confidence', 0) > 0.7])
    total_payloads = len(vulnerabilities)
    return int((successful_payloads / total_payloads) * 100) if total_payloads > 0 else 0
