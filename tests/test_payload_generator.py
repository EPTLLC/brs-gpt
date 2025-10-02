from brsgpt.xss.payload_generator import PayloadGenerator


def test_generate_payloads_html_context_returns_items():
    pg = PayloadGenerator({'max_payloads': 50})
    ctx = {'type': 'html', 'subtype': 'attribute_value'}
    payloads = pg.generate_payloads(ctx)
    assert isinstance(payloads, list)
    assert payloads, "Expected non-empty payload list for HTML context"
    assert 'payload' in payloads[0]

