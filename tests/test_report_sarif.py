from brsgpt.core.report_generator import ReportGenerator


def test_convert_to_sarif_result_minimal():
    rg = ReportGenerator({'format': 'html'})
    vuln = {
        'type': 'xss_vulnerability',
        'url': 'https://example.com',
        'parameter': 'q',
        'severity': 'high',
        'context': {'type': 'html'},
        'payload': "<img src=x onerror=alert(1)>",
        'method': 'GET',
        'timestamp': '2025-01-01T00:00:00Z',
    }
    sarif = rg._convert_to_sarif_result(vuln)
    assert sarif['ruleId']
    assert sarif['message']['text']
    assert sarif['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'https://example.com'

