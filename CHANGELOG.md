# BRS-GPT: AI-Enhanced Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Modified
# Telegram: https://t.me/easyprotech

# Changelog

All notable changes to BRS-GPT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1+enhancements] - 2025-10-03

### Added
- **Advanced Reconnaissance Modules**
  - Amass integration for advanced subdomain enumeration
  - Subfinder integration for fast passive reconnaissance
  - Fallback to built-in methods if external tools unavailable

- **Extended Vulnerability Detection**
  - SQLi Scanner: error-based, boolean-blind, time-blind, union-based detection
  - SSRF Scanner: localhost, internal IPs, cloud metadata, protocol smuggling
  - XXE Scanner: file disclosure, SSRF via XXE, Billion Laughs DoS detection

- **REST API Server**
  - 8 REST endpoints for full integration
  - Authentication with Bearer tokens
  - Async scan execution and result tracking
  - CORS support

- **CI/CD Integration Examples**
  - GitHub Actions workflow with SARIF upload
  - GitLab CI pipeline with multiple stages
  - Jenkins pipeline with parameterized builds

- **Enhanced Docker Support**
  - 5 deployment modes: basic, smart, live, API, cloud
  - Health checks
  - Multiple volume mounts
  - Better layer caching

- **Expanded Threat Intelligence**
  - MITRE ATT&CK framework support
  - CISA KEV (Known Exploited Vulnerabilities) catalog
  - Enhanced NVD CVE correlation
  - Automated threat feeds downloader script

### Changed
- **Positioning**: "AI-controlled" → "AI-enhanced" for honest marketing
- **Cost transparency**: Updated to show real costs ($0.02-$0.15 per scan)
- **Default models**: gpt-5-mini, gpt-4o-mini, gpt-5-nano for minimal costs
- **README**: Restructured to clearly separate scanning from AI intelligence

### Technical
- All new modules properly tested with virtual environment
- 15 new files created, 6 modified
- Comprehensive test coverage for new features
- Documentation: API.md, DOCKER.md

## [0.0.1] - 2025-09-08

### Initial Release
- AI-enhanced cybersecurity analysis platform
- Multi-agent AI architecture (9 specialized agents)
- Support for 12 OpenAI models
- Real-time cost tracking
- Lightning-fast analysis profiles (2-3 minutes)
- Reconnaissance: subdomain enumeration, port scanning, DNS, tech detection
- XSS vulnerability scanning with context awareness
- Security header analysis
- Executive summary generation
- CLI interface with model selection
- Professional documentation (LEGAL.md, ETHICS.md, DISCLAIMER.md)
- Dual license model (GPLv3 + Commercial)

### Features
- **AI Strategic Planning**: Target classification and analysis strategy
- **Intelligent Reconnaissance**: AI-guided subdomain and port discovery
- **Vulnerability Intelligence**: Context-aware XSS detection
- **Threat Correlation**: AI-enhanced risk assessment and scoring
- **Cost Transparency**: Real-time tracking of OpenAI API usage and costs
- **Executive Reporting**: Business-focused security summaries

### Technical Details
- Python 3.8+ support
- Async/await architecture for performance
- Rate limiting and timeout controls
- Error handling and graceful degradation
- Secure API key management
- Modular agent-based design

### Security
- API key protection with .gitignore
- Local-only data storage
- Encrypted API communications
- No data transmission to EasyProTech servers

---

## Roadmap

### Planned for v0.1.0
- ✅ ~~Enhanced subdomain discovery (Amass/Subfinder)~~ **COMPLETED**
- ✅ ~~SARIF output format~~ **COMPLETED**
- ✅ ~~HTML report generation~~ **COMPLETED**
- ✅ ~~Docker containerization~~ **COMPLETED**
- ✅ ~~CI/CD integration examples~~ **COMPLETED**
- ✅ ~~API endpoint for integrations~~ **COMPLETED**
- Additional vulnerability scanners (CSRF, IDOR, Auth bypass)
- Enhanced error handling and logging

### Planned for v0.2.0
- WebSocket security testing
- GraphQL deep audit
- JWT audit (alg:none, weak HMAC)
- OAuth2/OIDC misconfiguration detection
- Custom prompt templates
- Batch analysis capabilities

### Planned for v1.0.0
- Network service expansion (Kafka, LDAP/AD, SMB/WinRM)
- Crypto/Auth comprehensive audit
- AI correlation agent improvements
- Compliance mapper (NIST, ISO, GDPR, PCI)
- Performance optimizations
- Enterprise features
- Production-ready stability

---

**Note**: This changelog follows [Keep a Changelog](https://keepachangelog.com/) format. For latest updates, see the GitHub repository.
