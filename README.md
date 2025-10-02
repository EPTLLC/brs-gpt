# BRS-GPT

BRS-GPT is an **AI-enhanced cybersecurity analysis platform** that combines automated security scanning with intelligent AI analysis. It uses multi-agent AI orchestration alongside deterministic scanning techniques, real-time cost tracking, and professional reporting for comprehensive security testing.

**Key Approach**: Real security scanning (XSS, SQLi, SSRF, XXE, port scanning) + AI intelligence (correlation, risk assessment, reporting)

---

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-GPLv3-E94E77?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)
[![OpenAI](https://img.shields.io/badge/AI-OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white)](https://openai.com)
[![Version](https://img.shields.io/badge/Version-0.0.1-00ADD8?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EPTLLC/brs-gpt)

[![Tests](https://img.shields.io/badge/Tests-37%20Passed-00C853?style=for-the-badge&logo=pytest&logoColor=white)](#)
[![Coverage](https://img.shields.io/badge/Coverage-100%25-00C853?style=for-the-badge&logo=codecov&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Security-XSS%20%7C%20SQLi%20%7C%20SSRF%20%7C%20XXE-FF6F00?style=for-the-badge&logo=security&logoColor=white)](#)
[![Cost](https://img.shields.io/badge/Cost-%240.02--0.15%2Fscan-4CAF50?style=for-the-badge&logo=cashapp&logoColor=white)](#)

**Company:** EasyProTech LLC (www.easypro.tech)  
**Dev:** Brabus  
**Contact:** https://t.me/EasyProTech

---

## Why BRS-GPT?

**Hybrid Architecture** - Real vulnerability scanning + AI intelligence
**Intelligent Automation** - Complete analysis with minimal human intervention  
**Extended Coverage** - XSS, SQLi, SSRF, XXE, port scanning, subdomain enumeration
**Professional Reporting** - AI-generated executive summaries and technical details
**Cost Transparency** - Real-time tracking of AI usage and costs
**Specialized Agents** - Multiple AI agents for analysis and correlation
**REST API** - Integration-ready API for CI/CD pipelines

### Key Features

#### Security Scanning (Deterministic)
- **Advanced Reconnaissance** - Subdomain enumeration (built-in + Amass/Subfinder integration), DNS, port scanning
- **Vulnerability Detection** - XSS (context-aware), SQLi (error/boolean/time/union-based), SSRF, XXE
- **Protocol Detection** - ClickHouse, Redis, Elasticsearch, MongoDB, MySQL, PostgreSQL, MSSQL, Kubernetes, Docker, etc.
- **TLS/SSL Analysis** - Version, cipher, certificate analysis with insecure version detection
- **Security Headers** - Missing header detection and analysis

#### AI Intelligence Layer
- **Strategic Planning** - AI analyzes targets and recommends optimal approach
- **Correlation & Prioritization** - AI correlates findings and prioritizes by business impact
- **Threat Intelligence** - Offline threat feeds (NVD, ExploitDB, MITRE ATT&CK, CISA KEV)
- **Risk Modeling** - Hybrid: Deterministic score + AI context analysis
- **Executive Reporting** - AI-generated business-focused summaries
- **Attack Planning** - AI generates exploitation scenarios and mitigation strategies

#### Integration & Deployment
- **REST API** - Full-featured API for integrations
- **CI/CD Ready** - GitHub Actions, GitLab CI, Jenkins examples
- **Docker Support** - Multiple deployment modes (basic, smart, live, API)
- **Cost Tracking** - Real-time OpenAI usage and cost transparency

## AI Architecture

BRS-GPT uses a multi-agent AI architecture where specialized agents handle different aspects of cybersecurity analysis (strategy, recon, vuln, threat, exploitation, reporting, optimization) plus a deterministic risk engine validating AI outputs:

### AI Agent System

| Agent | Function | Decision Making |
|-------|----------|----------------|
| **MasterDecisionAgent** | Strategic planning and coordination | Target classification, risk profiling, resource allocation |
| **ReconStrategyAgent** | Reconnaissance strategy and execution | Subdomain prioritization, DNS analysis depth, technology detection |
| **VulnerabilityHuntingAgent** | Vulnerability discovery and prioritization | XSS context selection, payload strategy, scanning approach |
| **ThreatIntelligenceAgent** | Threat correlation and risk assessment | Risk scoring, threat vector analysis, impact assessment |
| **ExploitationAgent** | Attack scenario planning | Exploitation chains, attack complexity, mitigation priority |
| **ReportingAgent** | Intelligent report generation | Executive summaries, technical details, business impact |
| **TestPlannerAgent** | Active test planning and execution | Budgeted, safe HTTP probes and result interpretation |
| **PerformanceOptimizer** | Real-time optimization | Resource allocation, timing optimization, workflow adaptation |

### AI Decision Flow

1. **Master AI** analyzes target and creates comprehensive strategy
2. **Recon AI** executes intelligent reconnaissance based on strategy
3. **Test Planner AI** plans and executes safe, budgeted active HTTP checks (e.g., GraphQL introspection, OIDC discovery, CORS, Docker Registry /v2/)
4. **Vulnerability AI** hunts for vulnerabilities using AI-optimized approaches
5. **Threat AI** correlates findings and assesses threat landscape
6. **Exploitation AI** plans attack scenarios and defensive measures
7. **Reporting AI** generates executive and technical reports


### Analysis Profiles

| Profile | Speed | AI Queries | Use Case |
|---------|-------|------------|----------|
| `lightning` | 2-3 min | 6-8 queries | Quick assessment |
| `fast` | 4-6 min | 10-12 queries | Standard analysis |
| `balanced` | 8-12 min | 15-20 queries | Comprehensive analysis |
| `deep` | 15-25 min | 25-35 queries | Thorough investigation |

### Cost Transparency

BRS-GPT provides real-time cost tracking:

```
AI MasterDecision: Analyze target: easypro.tech
  → Tokens: ~385, Cost: ~$0.0012
  ✓ Response: 3.5s, Tokens: 552, Cost: $0.0018
  → Decision: web_app target, medium risk
```

**Default models** (ultra-cheap):
- Primary: `gpt-5-mini` ($0.25/$2.00 per 1M tokens)
- Search: `gpt-4o-mini` ($0.15/$0.60 per 1M tokens)
- Fallback: `gpt-5-nano` ($0.05/$0.40 per 1M tokens)

**Real costs per scan** (negligible):
- **Lightning**: $0.02 - $0.03 (6-8 queries)
- **Fast**: $0.03 - $0.05 (10-12 queries)
- **Balanced**: $0.05 - $0.08 (15-20 queries)
- **Deep**: $0.10 - $0.15 (25-35 queries)

**Actual scanning is FREE** - costs are only for AI intelligence layer, which is barely noticeable.

---

## Competitive Analysis

| Feature | BRS-GPT | HexStrike AI | Nessus Pro | OpenVAS |
|---------|--------|--------------|------------|---------|
| **Approach** | ✅ Hybrid (Scan+AI) | ⚠️ AI-only | ❌ Manual | ❌ Signatures |
| **Cost per Scan** | ✅ $0.02-$0.15 | ⚠️ $5-$20 | ❌ License | ✅ Free |
| **Speed** | ✅ 2-3 min | ⚠️ 15-30 min | ⚠️ 30+ min | ❌ 60+ min |
| **Vulnerabilities** | ✅ XSS,SQLi,SSRF,XXE | ⚠️ Limited | ✅ Extensive | ✅ Extensive |
| **AI Intelligence** | ✅ Correlation+Reports | ⚠️ Basic | ❌ No AI | ❌ No AI |
| **API/CI-CD** | ✅ Native | ❌ No | ⚠️ Paid | ⚠️ Complex |
| **Executive Reports** | ✅ AI-generated | ⚠️ Templates | ✅ Professional | ⚠️ Basic |

## Benchmarks

**Performance**: Complete analysis in 2-3 minutes (lightning profile)  
**Accuracy**: Deterministic scanning + AI context analysis  
**Cost Efficiency**: $0.02-$0.15 per scan (practically free)  
**Coverage**: XSS, SQLi, SSRF, XXE + 20+ protocol detectors + AI intelligence

---

## Quickstart (60 seconds)

### Install & Analyze

```bash
git clone https://github.com/EPTLLC/brs-gpt.git
cd brs-gpt
pip install -e .
echo "OPENAI_API_KEY=sk-your-key-here" > .env
brs-gpt start target.com --profile lightning
```

### Docker

```bash
docker run --rm -v $(pwd):/out -e OPENAI_API_KEY=your-key \
  ghcr.io/eptllc/brs-gpt:latest start target.com --profile lightning
```

---

## Commands

```bash
# Quick analysis
brs-gpt start target.com

# Lightning fast scan
brs-gpt start target.com --profile lightning

# AI Orchestrator (multi-agent, end-to-end)
brs-gpt smart target.com --profile lightning

# Live-mode (continuous monitoring)
brs-gpt live target.com --cycles 5 --interval 60

# REST API server
brs-gpt api --host 0.0.0.0 --port 8000

# Pentest-as-Code
brs-gpt pac scenarios/web_api.yaml

# Select AI model
brs-gpt models

# Setup API key
brs-gpt setup

# Version info
brs-gpt version
```

---

## AI Features

### Strategic Planning
AI analyzes target characteristics and creates optimal assessment strategies including:
- Target classification (web_app, api, infrastructure)
- Risk profiling (low, medium, high, critical)
- Resource allocation and timing optimization
- Success metrics and adaptation triggers

### Intelligent Reconnaissance
AI guides reconnaissance activities:
- Subdomain discovery prioritization
- DNS analysis depth optimization
- Port scanning focus areas
- Technology detection strategies

### Vulnerability Intelligence
Comprehensive vulnerability discovery:
- Context-aware XSS detection
- Parameter discovery optimization
- Payload selection and customization
- WAF evasion strategy

### Threat Correlation
### Active Test Planning (safe)
AI plans and executes safe HTTP checks under strict budgets to maximize signal:
- GET `/.well-known/openid-configuration` (OIDC discovery)
- GET `/graphql` (GraphQL introspection hint)
- GET `/v2/` (Docker Registry probe)
- GET `/-/ready` and `/metrics` (Prometheus readiness/metrics)
- GET `/api/overview` (RabbitMQ Management)
- GET `/v1/sys/health` (Vault health)

All actions are time- and request-capped to ensure performance and safety.

AI correlates findings for comprehensive threat assessment:
- Attack surface analysis
- Vulnerability prioritization
- Risk scoring and impact assessment
- Exploitation likelihood analysis

### Executive Reporting
AI generates business-focused reports:
- Executive summaries for leadership
- Technical details for security teams
- Cost-benefit analysis for remediation
- Compliance and regulatory implications

Reports include:
- Quick Risk Indicator ("red lamp": critical/high/medium/low)
- Deterministic Risk Model with reproducible score and remediation roadmap
- Local Threat Intelligence section (critical services, default creds, CVE hints)
- Exploit References (from offline threat feeds)
- Attack Path Visualizer (chained findings)

### Offline Threat Feeds (optional)

BRS-GPT can ingest offline dumps (no external APIs at runtime) to enrich reports:

Place files here (created automatically on first run):
```
~/.config/brs-gpt/feeds/nvd_cves.json
~/.config/brs-gpt/feeds/exploitdb.json
```

Minimal schema examples:
```json
{
  "elasticsearch": ["CVE-2015-5531", "CVE-2014-3120"],
  "redis": ["CVE-2022-0543"]
}
```

```json
{
  "elasticsearch": ["EDB-12345"],
  "redis": ["EDB-67890"]
}
```

At runtime, BRS-GPT correlates detected services with these lists and surfaces CVEs and Exploit references in the report.

### Model Selection (OpenAI-only, no offline LLMs)

BRS-GPT uses environment-driven model selection (OpenAI only) to keep flexibility and control costs. Recommended setup:

- Primary analysis model (complex reasoning): `OPENAI_MODEL` (e.g., gpt-5-mini or gpt-4o)
- Search/cheaper reasoning model (classification, lookups): `OPENAI_SEARCH_MODEL` (e.g., gpt-4o-mini-search-preview)
- Last-resort fallback for strict JSON responses: `OPENAI_FALLBACK_MODEL` (e.g., gpt-5-nano)

Configure via .env or environment variables:

```bash
OPENAI_API_KEY=sk-your-key-here
# Optional overrides
OPENAI_MODEL=gpt-5-mini
OPENAI_SEARCH_MODEL=gpt-4o-mini-search-preview
OPENAI_FALLBACK_MODEL=gpt-5-nano
```

These values are read by `ConfigManager.get_default_settings()` and used by `OpenAIAnalyzer` to route requests appropriately. You can experiment with other OpenAI models without changing code. Offline LLMs are intentionally not supported by design.

## Results & Reporting

### Text Reports

AI-generated human-readable reports with executive summaries:

```bash
brs-gpt start target.com --profile lightning
# Creates: results/target_com_20250909_010725.txt
```

Example output:
```
FINAL SECURITY ASSESSMENT
==========================================================

SUMMARY (Based on Real Scan Data):
  Target Classification: Technology/Software
  AI Security Score: 3/10
  Security Posture: critical
  Attack Surface Risk: high

FINDINGS:
  Subdomains Discovered: 1
  Open Ports Found: 89
  XSS Vulnerabilities: 0
  Missing Security Headers: 4

PRIORITY ACTIONS (AI Recommendations):
  Critical fixes:
    1. Close or secure Port 21 (FTP)
    2. Disable Port 23 (Telnet) 
    3. Implement RDP authentication
```

### AI Model Selection

```bash
# List available models with costs
brs-gpt models

Available OpenAI models:
  1. GPT-5 (recommended)
     Cost: High ($1.25 input / $10.00 output per 1M tokens)
  2. GPT-4o Mini (recommended)  
     Cost: Low ($0.15 input / $0.60 output per 1M tokens)
```

---

## Latest Updates (October 2025)

### New Features ✨

#### Advanced Reconnaissance
- **Amass Integration** - OWASP Amass support for advanced subdomain enumeration
- **Subfinder Integration** - ProjectDiscovery Subfinder for fast passive recon
- Falls back to built-in methods if external tools not available

#### Extended Vulnerability Detection
- **SQLi Scanner** - Error-based, Boolean-blind, Time-blind, Union-based detection
- **SSRF Scanner** - Localhost, internal IPs, cloud metadata, protocol smuggling
- **XXE Scanner** - File disclosure, SSRF via XXE, Billion Laughs DoS detection

#### Integration & Deployment
- **REST API** - Full-featured API for integrations (8 endpoints)
- **CI/CD Examples** - GitHub Actions, GitLab CI, Jenkins pipelines included
- **Enhanced Docker** - 5 deployment modes (basic, smart, live, API, cloud)
- **API Documentation** - Complete API reference with client examples

#### Threat Intelligence
- **Enhanced Feeds** - NVD CVEs, ExploitDB, MITRE ATT&CK, CISA KEV catalog
- **Feed Downloader** - Automated script to download and prepare offline feeds
- **Better Correlation** - Improved threat feed correlation with discovered services

### Already Delivered
- Local Threat Knowledge Base with CVE hints, ATT&CK mapping
- Protocol detectors: 20+ services (Redis, Elasticsearch, Kubernetes, Docker, etc.)
- TLS/SSL analysis with insecure version detection
- Deterministic Risk Model with reproducible scoring
- AI Test Planner with safe, budgeted HTTP checks
- XSS detection with context awareness
- Security headers analysis

### Roadmap
- Network service expansion: Kafka, LDAP/AD, SMB/WinRM
- Crypto/Auth: SSH audit, JWT audit, OAuth2/OIDC misconfig detection
- AI capabilities: Enhanced correlation, compliance mapper
- Performance optimizations

Note: BRS-GPT is OpenAI-only by design. The platform uses **hybrid approach**: real scanning + AI intelligence.

## Installation Options

### From Source

```bash
git clone https://github.com/EPTLLC/brs-gpt.git
cd brs-gpt
pip install -e .
```

### Docker

```bash
docker pull ghcr.io/eptllc/brs-gpt:latest
```

---

## Requirements

- Python 3.8+
- OpenAI API key (required)
- Internet connection for AI queries

## Legal & Ethics

**Authorized Testing Only**: This tool is designed for legitimate security testing with proper authorization.

- **[LEGAL.md](LEGAL.md)** - Complete legal terms and compliance
- **[ETHICS.md](ETHICS.md)** - Responsible disclosure guidelines  
- **[DISCLAIMER.md](DISCLAIMER.md)** - Liability and warranty disclaimers

### Data Handling
- No sensitive data stored locally
- All AI communications encrypted
- Reports contain only technical findings
- API keys secured with proper permissions

## License

### Dual License Model
- **GPLv3**: Free for non-commercial and open-source use
- **Commercial License**: Enterprise support and custom features

Contact [https://t.me/easyprotech](https://t.me/easyprotech) for commercial licensing.

### No Support Policy
**NO SUPPORT PROVIDED** - This is a professional tool for experienced security practitioners.

## About EasyProTech LLC

**Professional Cybersecurity and AI Solutions**

We specialize in:
- AI-Enhanced Security Tools (BRS-GPT, BRS-XSS, BRS-Core)
- Cryptography and OTP Solutions
- Enterprise Security Platforms
- AI Research for Cognitive Disorders

**Website**: [https://easypro.tech](https://easypro.tech)  
**Telegram**: [https://t.me/easyprotech](https://t.me/easyprotech)  
**GitHub**: [https://github.com/EPTLLC](https://github.com/EPTLLC)

---

---

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Follow code standards and add tests
4. Submit pull request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

---

**BRS-GPT v0.0.1** | **EasyProTech LLC** | **[https://t.me/easyprotech](https://t.me/easyprotech)**

_AI-enhanced cybersecurity analysis: Real scanning + Intelligent correlation_