from brsgpt.core.risk.risk_model import RiskModeler


def test_risk_model_posture_thresholds():
    rm = RiskModeler()
    # No issues -> excellent/good band
    model = rm.build_model({'open_ports_found': []}, {'vulnerabilities_found': [], 'missing_security_headers': []})
    assert model['risk_score'] <= 15
    # Add high severity + risky ports + headers
    recon = {
        'open_ports_found': [
            {'port': 23, 'evidence': {'connect': True}, 'security_notes': {'risk_level': 'high'}},
            {'port': 445, 'evidence': {'connect': True}, 'security_notes': {'risk_level': 'high'}},
            {'port': 3389, 'evidence': {'connect': True}, 'security_notes': {'risk_level': 'high'}},
        ]
    }
    vulns = {
        'vulnerabilities_found': [
            {'severity': 'high', 'type': 'xss', 'parameter': 'q'},
            {'severity': 'medium', 'type': 'xss', 'parameter': 'id'},
            {'severity': 'low', 'type': 'xss', 'parameter': 'p'}
        ],
        'missing_security_headers': ['Content-Security-Policy', 'X-Frame-Options']
    }
    model2 = rm.build_model(recon, vulns)
    assert model2['risk_score'] > model['risk_score']
    assert 'immediate' in model2['remediation_plan']
    assert any('Restrict/secure risky port' in a for a in model2['remediation_plan']['immediate'])


def test_risk_model_remediation_dedup():
    rm = RiskModeler()
    vulns = {
        'vulnerabilities_found': [
            {'severity': 'high', 'type': 'xss', 'parameter': 'q', 'url': 'https://example.com'},
            {'severity': 'high', 'type': 'xss', 'parameter': 'q', 'url': 'https://example.com'},
        ],
        'missing_security_headers': ['X-Content-Type-Options', 'X-Content-Type-Options']
    }
    model = rm.build_model(
        {
            'open_ports_found': [
                {'port': 23, 'evidence': {'connect': True}, 'security_notes': {'risk_level': 'high'}},
            ]
        },
        vulns,
    )
    immediate = model['remediation_plan']['immediate']
    # Ensure duplicate header / vuln entries are deduped
    assert len(immediate) == len(set(immediate))
