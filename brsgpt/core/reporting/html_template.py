"""HTML template for security report."""

# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-15 00:00:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BRS-GPT Security Analysis Report - {{ target_domain }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; padding: 40px 0; text-align: center; margin-bottom: 30px; border-radius: 12px; box-shadow: 0 8px 32px rgba(220, 38, 38, 0.3); }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; font-weight: 700; }
        .header .subtitle { font-size: 1.2rem; opacity: 0.9; font-weight: 300; }
        .executive-summary { background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 16px rgba(0,0,0,0.1); border-left: 5px solid #dc2626; }
        .security-score { display: flex; align-items: center; justify-content: space-between; margin-bottom: 25px; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: bold; color: white; }
        .score-excellent { background: #10b981; } .score-good { background: #059669; } .score-fair { background: #f59e0b; } .score-poor { background: #ef4444; } .score-critical { background: #dc2626; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.1); text-align: center; }
        .metric-value { font-size: 2.5rem; font-weight: bold; margin-bottom: 10px; }
        .metric-label { color: #666; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
        .section { background: white; margin-bottom: 30px; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.1); }
        .section-header { background: #374151; color: white; padding: 20px 30px; font-size: 1.3rem; font-weight: 600; }
        .section-content { padding: 30px; }
        .red-lamp { display:flex; align-items:center; gap:12px; padding:14px 18px; border-radius: 10px; margin-top: 16px; }
        .lamp-dot { width:14px; height:14px; border-radius:50%; box-shadow: 0 0 12px rgba(0,0,0,0.2); }
        .lamp-critical { background:#dc2626; color:#7f1d1d; }
        .lamp-high { background:#f87171; color:#7f1d1d; }
        .lamp-medium { background:#fbbf24; color:#7c2d12; }
        .lamp-low { background:#34d399; color:#064e3b; }
        .vulnerability-list { list-style: none; }
        .vulnerability-item { padding: 20px; border-left: 4px solid; margin-bottom: 15px; background: #f8f9fa; border-radius: 0 8px 8px 0; }
        .vuln-critical { border-left-color: #dc2626; } .vuln-high { border-left-color: #ef4444; } .vuln-medium { border-left-color: #f59e0b; } .vuln-low { border-left-color: #10b981; }
        .vulnerability-title { font-weight: 600; margin-bottom: 8px; font-size: 1.1rem; }
        .vulnerability-details { color: #666; font-size: 0.9rem; margin-bottom: 10px; }
        .vulnerability-payload { background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 6px; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.85rem; overflow-x: auto; margin-top: 10px; }
        .recommendations { background: #ecfdf5; border: 1px solid #10b981; border-radius: 8px; padding: 20px; margin-top: 20px; }
        .recommendations h4 { color: #065f46; margin-bottom: 10px; }
        .recommendations ul { color: #047857; }
        .attack-path { background: #fef2f2; border: 1px solid #f87171; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .attack-step { padding: 10px 0; border-bottom: 1px solid #fee2e2; }
        .attack-step:last-child { border-bottom: none; }
        .step-number { display: inline-block; width: 30px; height: 30px; background: #dc2626; color: white; border-radius: 50%; text-align: center; line-height: 30px; font-weight: bold; margin-right: 15px; }
        .footer { text-align: center; padding: 40px 0; color: #666; border-top: 1px solid #e5e7eb; margin-top: 50px; }
        .footer .company-info { font-weight: 600; margin-bottom: 10px; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-critical { background: #fee2e2; color: #991b1b; } .badge-high { background: #fef2f2; color: #b91c1c; } .badge-medium { background: #fef3c7; color: #92400e; } .badge-low { background: #d1fae5; color: #065f46; }
        @media (max-width: 768px) { .container { padding: 10px; } .header h1 { font-size: 2rem; } .metrics-grid { grid-template-columns: 1fr; } .security-score { flex-direction: column; gap: 20px; } }
    </style>
    </head>
<body>
    <div class="container">
        <div class="header">
            <h1>BRS-GPT Security Analysis</h1>
            <div class="subtitle">Comprehensive Cybersecurity Assessment Report</div>
            <div style="margin-top: 20px; font-size: 1.1rem;">
                Target: <strong>{{ target_domain }}</strong> | 
                Scan Date: <strong>{{ scan_date }}</strong> |
                AI Model: <strong>{{ ai_model }}</strong> |
                AI Mode: <strong>{{ 'Enabled' if ai_enabled else 'Disabled' }}</strong>
            </div>
        </div>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{{ cost_queries or 0 }}</div>
                <div class="metric-label">AI Queries</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ cost_tokens or 0 }}</div>
                <div class="metric-label">Tokens</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${{ '%.4f' % (cost_usd or 0.0) }}</div>
                <div class="metric-label">AI Cost</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ '%.2fs' % (perf_avg_query_time or 0.0) }}</div>
                <div class="metric-label">Avg Query Time</div>
            </div>
        </div>
        <div class="section">
            <div class="section-header">Quick Risk Indicator</div>
            <div class="section-content">
                <div class="red-lamp lamp-{{ risk_level }}">
                    <div class="lamp-dot" style="background:white;"></div>
                    <div>
                        <div style="font-weight:700;">{{ risk_level|upper }} RISK</div>
                        <div style="opacity:0.8;">Open ports: {{ open_ports }} | Overall score: {{ overall_risk_score }}/10</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="section">
            <div class="section-header">AI Intelligence Summary</div>
            <div class="section-content">
                <div style="display:flex; gap:30px; flex-wrap:wrap; margin-bottom:15px;">
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ ai_model }}</div>
                        <div class="metric-label">OpenAI Model</div>
                    </div>
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ cost_queries or 0 }}</div>
                        <div class="metric-label">AI Queries</div>
                    </div>
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ cost_tokens or 0 }}</div>
                        <div class="metric-label">Tokens</div>
                    </div>
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">${{ '%.4f' % (cost_usd or 0.0) }}</div>
                        <div class="metric-label">Estimated Cost</div>
                    </div>
                </div>
                {% if ai_rationale %}
                <div class="recommendations">
                    <h4>AI Rationale (Summary)</h4>
                    <p style="margin-top:6px;">{{ ai_rationale }}</p>
                </div>
                {% endif %}
            </div>
        </div>
        <div class="section">
            <div class="section-header">Threat Intelligence (Local KB)</div>
            <div class="section-content">
                {% if threat_intel_critical_services %}
                <p style="margin-bottom:10px;">Critical services detected: {{ ', '.join(threat_intel_critical_services) }}</p>
                {% endif %}
                {% if threat_intel_default_creds %}
                <div class="recommendations" style="margin-top:15px;">
                    <h4>Default Credentials Risks</h4>
                    <ul>
                        {% for d in threat_intel_default_creds[:10] %}<li>{{ d }}</li>{% endfor %}
                    </ul>
                </div>
                {% endif %}
                {% if threat_intel_cves %}
                <div class="section" style="margin-top:15px;">
                    <div class="section-header" style="background:#6b7280;">Relevant CVEs</div>
                    <div class="section-content">
                        <ul style="columns:2; -webkit-columns:2; -moz-columns:2;">
                            {% for cve in threat_intel_cves[:20] %}<li>{{ cve }}</li>{% endfor %}
                        </ul>
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
        <!-- Deterministic Risk Model Section (if provided) -->
        {% if det_risk_score %}
        <div class="section">
            <div class="section-header">Deterministic Risk Overview</div>
            <div class="section-content">
                <div style="display:flex; gap:30px; flex-wrap:wrap; margin-bottom:25px;">
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ '%.1f' % det_risk_score }}</div>
                        <div class="metric-label">Deterministic Risk Score (0-10)</div>
                    </div>
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ det_security_posture or 'unknown' }}</div>
                        <div class="metric-label">Security Posture</div>
                    </div>
                </div>
                <p style="margin-bottom:15px;">{{ det_summary }}</p>
                {% if det_immediate_actions %}
                <div class="recommendations">
                    <h4>Immediate Deterministic Actions</h4>
                    <ul>
                        {% for action in det_immediate_actions[:6] %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if det_immediate_actions or risk_model_remediation_short or risk_model_remediation_long %}
        <div class="section">
            <div class="section-header">Remediation Roadmap</div>
            <div class="section-content" style="display:flex; gap:25px; flex-wrap:wrap;">
                <div style="flex:1; min-width:250px;">
                    <h4>Immediate (0-24h)</h4>
                    <ul>
                        {% for a in det_immediate_actions[:8] %}<li>{{ a }}</li>{% endfor %}
                        {% if not det_immediate_actions %}<li>No immediate critical actions.</li>{% endif %}
                    </ul>
                </div>
                <div style="flex:1; min-width:250px;">
                    <h4>Short Term (7 days)</h4>
                    <ul>
                        {% for a in risk_model_remediation_short[:8] %}<li>{{ a }}</li>{% endfor %}
                        {% if not risk_model_remediation_short %}<li>No short term items.</li>{% endif %}
                    </ul>
                </div>
                <div style="flex:1; min-width:250px;">
                    <h4>Long Term (30 days+)</h4>
                    <ul>
                        {% for a in risk_model_remediation_long[:8] %}<li>{{ a }}</li>{% endfor %}
                        {% if not risk_model_remediation_long %}<li>No long term items.</li>{% endif %}
                    </ul>
                </div>
            </div>
        </div>
        {% endif %}

        {% if header_hardening_percent is not none %}
        <div class="section">
            <div class="section-header">Security Headers Hardening</div>
            <div class="section-content">
                <div style="display:flex; gap:30px; flex-wrap:wrap; margin-bottom:20px;">
                    <div class="metric-card" style="flex:1; min-width:220px;">
                        <div class="metric-value">{{ '%.1f' % header_hardening_percent }}%</div>
                        <div class="metric-label">Header Hardening Score</div>
                    </div>
                </div>
                {% if header_findings %}
                <ul style="list-style:disc; margin-left:20px;">
                    {% for f in header_findings[:12] %}
                    <li><strong>{{ f.type or f['type'] }}</strong>: {{ f.header or f.directive or f.get('directive') }} {{ f.recommendation or f.get('recommendation','') }}</li>
                    {% endfor %}
                </ul>
                {% else %}
                <p>No header issues detected.</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if exploit_references %}
        <div class="section">
            <div class="section-header">Exploit References</div>
            <div class="section-content">
                <ul style="columns:2; -webkit-columns:2; -moz-columns:2;">
                    {% for ex in exploit_references[:30] %}
                    <li>{{ ex }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        {% if ai_correlation_insights %}
        <div class="section">
            <div class="section-header">AI Correlation Insights</div>
            <div class="section-content">
                {% if ai_correlation_highlights %}
                <div class="recommendations"><h4>Highlights</h4>
                    <ul>{% for h in ai_correlation_highlights[:8] %}<li>{{ h }}</li>{% endfor %}</ul>
                </div>
                {% endif %}
                <ul class="vulnerability-list">
                    {% for i in ai_correlation_insights[:10] %}
                    <li class="vulnerability-item vul{{ ('n-' + i.severity)|lower if i.severity else 'n-low' }}">
                        <div class="vulnerability-title">{{ i.title }}</div>
                        <div class="vulnerability-details">{{ i.evidence }}</div>
                        {% if i.attack_chain %}
                        <div class="attack-path" style="margin-top:10px;">
                            {% for s in i.attack_chain %}
                            <div class="attack-step"><span class="step-number">{{ loop.index }}</span>{{ s }}</div>
                            {% endfor %}
                        </div>
                        {% endif %}
                        {% if i.remediation %}
                        <div class="recommendations" style="margin-top:10px;"><h4>Remediation</h4><ul><li>{{ i.remediation }}</li></ul></div>
                        {% endif %}
                    </li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        {% if compliance_frameworks %}
        <div class="section">
            <div class="section-header">Compliance Mapping</div>
            <div class="section-content">
                {% if compliance_summary %}<p style="margin-bottom:10px;">{{ compliance_summary }}</p>{% endif %}
                {% for framework, items in compliance_frameworks.items() %}
                <div class="section" style="margin-top:10px;">
                    <div class="section-header" style="background:#6b7280;">{{ framework }}</div>
                    <div class="section-content">
                        <ul>
                        {% for it in items[:12] %}
                            <li>{{ it.control or it.article }} — {{ it.finding_ref }} — {{ it.remediation }}</li>
                        {% endfor %}
                        </ul>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if devops_exposure %}
        <div class="section">
            <div class="section-header">DevOps/Infra Exposure Summary</div>
            <div class="section-content">
                <p style="margin-bottom:8px;">Detected potentially sensitive management services with quick PoC hints:</p>
                <ul>
                    {% for e in devops_exposure[:20] %}
                    <li><strong>{{ e.service }}</strong> on ports {{ e.ports }} — {{ e.poc }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        {% if pocs %}
        <div class="section">
            <div class="section-header">Exploit PoCs (Safe)</div>
            <div class="section-content">
                <ul>
                    {% for p in pocs[:12] %}
                    <li class="vulnerability-item">
                        <div class="vulnerability-title">{{ p.title }} ({{ p.severity }})</div>
                        <div class="vulnerability-details">Ref: {{ p.ref }}</div>
                        {% if p.command %}<div class="vulnerability-payload">{{ p.command }}</div>{% endif %}
                        {% if p.notes %}<div class="recommendations" style="margin-top:10px;"><h4>Notes</h4><ul><li>{{ p.notes }}</li></ul></div>{% endif %}
                    </li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        {% if web_checks %}
        <div class="section">
            <div class="section-header">Web Checks Summary</div>
            <div class="section-content">
                <ul>
                    {% if web_checks.graphql and web_checks.graphql.introspection_enabled %}
                    <li>GraphQL introspection enabled at {{ web_checks.graphql.endpoint }} (types: {{ web_checks.graphql.types_count or 'n/a' }}, mutations: {{ 'yes' if web_checks.graphql.has_mutations else 'no' }})
                        {% if web_checks.graphql.type_names_sample %}<div style="opacity:0.8; font-size:0.9em; margin-top:4px;">Types: {{ ', '.join(web_checks.graphql.type_names_sample) }}</div>{% endif %}
                    </li>
                    {% endif %}
                    {% if web_checks.grpc and (web_checks.grpc.suspected or web_checks.grpc.probe_suspected) %}
                    <li>gRPC suspected (headers/probe)</li>
                    {% endif %}
                    {% if web_checks.oauth and (web_checks.oauth.authorize or web_checks.oauth.well_known) %}
                    <li>OAuth2 endpoints present ({{ web_checks.oauth.authorize.endpoint if web_checks.oauth.authorize else web_checks.oauth.well_known.endpoint }})</li>
                    {% endif %}
                    {% if web_checks.oidc and web_checks.oidc.discovery_found %}
                    <li>OIDC discovery: {{ web_checks.oidc.endpoint }}</li>
                    {% endif %}
                    {% if web_checks.jwt and web_checks.jwt.present %}
                    <li>JWT detected ({{ ', '.join(web_checks.jwt.locations) }}). {% if web_checks.jwt.issues %}Issues: {{ ', '.join(web_checks.jwt.issues[:3]) }}{% endif %}</li>
                    {% endif %}
                    {% if web_checks.websockets_count or web_checks.api_keys_count %}
                    <li>WebSockets: {{ web_checks.websockets_count or 0 }}, API keys: {{ web_checks.api_keys_count or 0 }}</li>
                    {% endif %}
                </ul>
            </div>
        </div>
        {% endif %}

        {% if attack_paths_visual %}
        <div class="section">
            <div class="section-header">Attack Path Visualizer</div>
            <div class="section-content">
                {% for path in attack_paths_visual %}
                <div class="attack-path">
                    <div style="font-weight:700; margin-bottom:10px;">{{ path.title }}</div>
                    {% for step in path.steps %}
                    <div class="attack-step"><span class="step-number">{{ loop.index }}</span>{{ step }}</div>
                    {% endfor %}
                </div>
                {% endfor %}
                {% if not attack_paths_visual %}<p>No attack paths identified.</p>{% endif %}
            </div>
        </div>
        {% endif %}

        <!-- ...existing template content... -->
        {{ body_sections }}
        <div class="footer">
            <div class="company-info">EasyProTech LLC - Professional Cybersecurity Solutions</div>
            <div>Generated by BRS-GPT v{{ version }} | Contact: https://t.me/easyprotech</div>
            <div style="margin-top: 10px; font-size: 0.9rem;">
                Report generated on {{ report_timestamp }} | Methodology: AI + deterministic risk modeling
            </div>
        </div>
    </div>
</body>
</html>
"""
