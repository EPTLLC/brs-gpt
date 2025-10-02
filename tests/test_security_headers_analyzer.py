from brsgpt.core.security.headers_analyzer import SecurityHeadersAnalyzer


def test_headers_analyzer_basic():
    analyzer = SecurityHeadersAnalyzer()
    headers = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    }
    result = analyzer.analyze(headers)
    assert result['total_header_score'] > 0
    assert result['header_hardening_percent'] > 0
    assert any(f['type'] == 'weak_csp_directive' for f in result['findings'])


def test_headers_analyzer_missing():
    analyzer = SecurityHeadersAnalyzer()
    result = analyzer.analyze({})
    missing = [f for f in result['findings'] if f['type'] == 'missing_header']
    assert len(missing) >= 5
