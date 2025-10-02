from brsgpt.core.report_generator import ReportGenerator


def test_report_dns_analysis_fallback_used_when_dns_records_missing():
    rg = ReportGenerator({'format': 'html', 'output': {}})
    analysis_results = {
        'target': 'example.com',
        'recon_data': {
            # legacy key intentionally omitted
            'dns_analysis': {
                'dnssec_status': 'enabled',
                'security_issues': ['issue1', 'issue2'],
                'caa_records': ['0 issue.com']
            },
            'subdomains': ['a.example.com', 'b.example.com'],
            'open_ports': [80, 443],
            'technologies': {'nginx': '1.20'}
        },
        'xss_data': {
            'vulnerabilities': []
        },
        'ai_analysis': {}
    }

    data = rg._prepare_html_template_data(analysis_results)

    recon = data['recon_summary']
    assert recon['dnssec_status'] == 'enabled'
    assert recon['dns_security_issues'] == 2
    assert recon['caa_present'] is True
    assert data['dnssec_status_badge'] == 'badge-low'
