from brsgpt.core.reporting.sarif import convert_to_sarif_result, generate_sarif_rules
from brsgpt.core.reporting.data_prep import prepare_html_template_data


def test_sarif_rules_non_empty():
    rules = generate_sarif_rules()
    assert isinstance(rules, list) and len(rules) >= 1
    assert rules[0]["id"] == "XSS001"


def test_convert_to_sarif_result_minimal():
    vuln = {
        "type": "xss_vulnerability",
        "url": "https://example.com",
        "parameter": "q",
        "context": {"type": "html"},
        "severity": "medium",
        "confidence": 0.7,
        "payload": "<script>alert(1)</script>",
        "method": "GET",
        "impact": "Reflected XSS",
        "timestamp": "2025-09-09T00:00:00Z",
    }
    res = convert_to_sarif_result(vuln)
    assert res["ruleId"] == "XSS001"
    assert res["message"]["text"].startswith("XSS vulnerability in parameter")
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com"


def test_prepare_html_template_data_minimal():
    analysis = {
        "target": "example.com",
        "start_time": "2025-09-09T00:00:00Z",
        "end_time": "2025-09-09T00:01:00Z",
        "recon_data": {"subdomains": [], "open_ports": []},
        "xss_data": {"vulnerabilities": []},
        "ai_analysis": {
            "executive_summary": {"security_posture_rating": "Good", "executive_overview": "ok"},
            "correlation": {},
        },
    }
    data = prepare_html_template_data(analysis)
    assert data["target_domain"] == "example.com"
    assert "xss_vulnerabilities" in data
    assert "executive_summary" in data
