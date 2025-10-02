# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Output Formatter

Professional output formatting utilities for various data formats:
- SARIF 2.1.0 compliant vulnerability reports
- JSON Schema validated security data
- CSV exports for spreadsheet analysis
- XML reports for legacy systems
- Markdown documentation generation

Ensures consistent, professional formatting across all output types.
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from pathlib import Path
import re
from ..version import VERSION


class OutputFormatter:
    """Professional output formatting utilities for cybersecurity data."""
    
    def __init__(self):
        """Initialize output formatter with standard schemas."""
        
        # SARIF 2.1.0 schema validation patterns
        self.sarif_severity_levels = ['error', 'warning', 'note', 'info']
        
        # Standard CWE mappings for XSS
        self.cwe_mappings = {
            'xss': 'CWE-79',
            'stored_xss': 'CWE-79',
            'reflected_xss': 'CWE-79',
            'dom_xss': 'CWE-79',
            'blind_xss': 'CWE-79'
        }
        
        # OWASP Top 10 mappings
        self.owasp_mappings = {
            'xss': 'A03:2021 - Injection',
            'injection': 'A03:2021 - Injection',
            'broken_auth': 'A07:2021 - Identification and Authentication Failures',
            'sensitive_exposure': 'A02:2021 - Cryptographic Failures'
        }
        
        # CVSS base metrics for severity calculation
        self.cvss_base_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
    
    def format_sarif_report(self, vulnerabilities: List[Dict[str, Any]], 
                           scan_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format vulnerabilities as SARIF 2.1.0 compliant report.
        
        Args:
            vulnerabilities: List of vulnerability objects
            scan_metadata: Scan metadata and configuration
            
        Returns:
            SARIF compliant report structure
        """
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BRS-GPT",
                            "version": VERSION,
                            "informationUri": "https://www.easypro.tech",
                            "organization": "EasyProTech LLC",
                            "shortDescription": {
                                "text": "AI-Powered Cybersecurity Analysis Tool"
                            },
                            "fullDescription": {
                                "text": "Comprehensive cybersecurity analysis combining reconnaissance, vulnerability scanning, and AI-powered risk assessment."
                            },
                            "rules": self._generate_sarif_rules(vulnerabilities)
                        }
                    },
                    "originalUriBaseIds": {
                        "ROOTPATH": {
                            "uri": scan_metadata.get('target_url', ''),
                            "description": {
                                "text": "Target application root"
                            }
                        }
                    },
                    "results": [],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": scan_metadata.get('start_time', datetime.utcnow().isoformat()),
                            "endTimeUtc": scan_metadata.get('end_time', datetime.utcnow().isoformat()),
                            "machine": "BRS-GPT Scanner",
                            "account": "automated",
                            "workingDirectory": {
                                "uri": "/"
                            }
                        }
                    ],
                    "properties": {
                        "scanType": "cybersecurity_assessment",
                        "targetUrl": scan_metadata.get('target_url'),
                        "scannerVersion": f"BRS-GPT v{VERSION}",
                        "company": "EasyProTech LLC",
                        "contact": "https://t.me/easyprotech"
                    }
                }
            ]
        }
        
        # Convert vulnerabilities to SARIF results
        for vuln in vulnerabilities:
            if self._is_valid_vulnerability(vuln):
                sarif_result = self._convert_vulnerability_to_sarif(vuln)
                sarif_report["runs"][0]["results"].append(sarif_result)
        
        return sarif_report
    
    def format_json_schema_report(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format analysis data with JSON Schema validation.
        
        Args:
            analysis_data: Complete analysis results
            
        Returns:
            JSON Schema compliant report
        """
        schema_report = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "BRS-GPT Cybersecurity Analysis Report",
            "description": "Comprehensive cybersecurity analysis results with AI-powered insights",
            "type": "object",
            "report": {
                "metadata": {
                    "generator": f"BRS-GPT v{VERSION}",
                    "company": "EasyProTech LLC",
                    "contact": "https://t.me/easyprotech",
                    "report_id": self._generate_report_id(),
                    "timestamp": datetime.utcnow().isoformat(),
                    "schema_version": "1.0.0"
                },
                "target": {
                    "url": analysis_data.get('target'),
                    "domain": self._extract_domain(analysis_data.get('target', '')),
                    "scan_scope": "full_assessment"
                },
                "executive_summary": self._format_executive_summary(
                    analysis_data.get('ai_analysis', {}).get('executive_summary', {})
                ),
                "risk_assessment": self._format_risk_assessment(
                    analysis_data.get('ai_analysis', {}).get('risk_assessment', {})
                ),
                "technical_findings": {
                    "reconnaissance": self._format_recon_findings(
                        analysis_data.get('recon_data', {})
                    ),
                    "vulnerabilities": self._format_vulnerability_findings(
                        analysis_data.get('xss_data', {})
                    ),
                    "attack_vectors": self._format_attack_vectors(
                        analysis_data.get('ai_analysis', {}).get('attack_paths', {})
                    )
                },
                "recommendations": self._format_recommendations(analysis_data),
                "appendices": {
                    "methodology": "AI-powered cybersecurity analysis combining automated scanning with intelligent risk assessment",
                    "tools_used": ["BRS-GPT Recon Engine", "BRS-GPT XSS Scanner", "OpenAI GPT-4 Analysis"],
                    "compliance_frameworks": ["OWASP Top 10", "CWE", "NIST Cybersecurity Framework"]
                }
            }
        }
        
        return schema_report
    
    def format_csv_export(self, vulnerabilities: List[Dict[str, Any]], 
                         output_file: str) -> Optional[str]:
        """
        Export vulnerabilities to CSV format for spreadsheet analysis.
        
        Args:
            vulnerabilities: List of vulnerability objects
            output_file: Output CSV file path
            
        Returns:
            Path to generated CSV file or None if failed
        """
        try:
            csv_headers = [
                'Vulnerability_ID', 'Severity', 'Confidence', 'URL', 'Parameter',
                'Method', 'Context_Type', 'Payload', 'CWE', 'OWASP_Category',
                'Impact_Description', 'Remediation_Summary', 'Detection_Date',
                'Scanner_Version', 'WAF_Bypass', 'Bypass_Technique'
            ]
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
                writer.writeheader()
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    if self._is_valid_vulnerability(vuln):
                        csv_row = {
                            'Vulnerability_ID': f"BRS-GPT-{i:04d}",
                            'Severity': vuln.get('severity', 'medium').title(),
                            'Confidence': f"{vuln.get('confidence', 0) * 100:.1f}%",
                            'URL': vuln.get('url', ''),
                            'Parameter': vuln.get('parameter', ''),
                            'Method': vuln.get('method', 'GET'),
                            'Context_Type': vuln.get('context', {}).get('type', 'unknown'),
                            'Payload': vuln.get('payload', ''),
                            'CWE': vuln.get('cwe', 'CWE-79'),
                            'OWASP_Category': vuln.get('owasp', 'A03:2021 - Injection'),
                            'Impact_Description': vuln.get('impact', ''),
                            'Remediation_Summary': vuln.get('remediation', {}).get('summary', ''),
                            'Detection_Date': vuln.get('timestamp', ''),
                            'Scanner_Version': vuln.get('scanner', f'BRS-GPT v{VERSION}'),
                            'WAF_Bypass': 'Yes' if vuln.get('waf_bypass', False) else 'No',
                            'Bypass_Technique': vuln.get('bypass_technique', '')
                        }
                        writer.writerow(csv_row)
            
            return str(output_path.absolute())
            
        except Exception as e:
            return None
    
    def format_xml_report(self, analysis_data: Dict[str, Any], 
                         output_file: str) -> Optional[str]:
        """
        Generate XML report for legacy systems integration.
        
        Args:
            analysis_data: Complete analysis results
            output_file: Output XML file path
            
        Returns:
            Path to generated XML file or None if failed
        """
        try:
            # Create root XML element
            root = ET.Element("BRS_GPT_Security_Report")
            root.set("version", "1.0.0")
            root.set("xmlns", "https://www.easypro.tech/brs-gpt/schema")
            
            # Report metadata
            metadata = ET.SubElement(root, "Metadata")
            ET.SubElement(metadata, "Generator").text = f"BRS-GPT v{VERSION}"
            ET.SubElement(metadata, "Company").text = "EasyProTech LLC"
            ET.SubElement(metadata, "Contact").text = "https://t.me/easyprotech"
            ET.SubElement(metadata, "Timestamp").text = datetime.utcnow().isoformat()
            ET.SubElement(metadata, "Target").text = analysis_data.get('target', '')
            
            # Executive summary
            exec_summary = analysis_data.get('ai_analysis', {}).get('executive_summary', {})
            if exec_summary:
                summary_elem = ET.SubElement(root, "ExecutiveSummary")
                ET.SubElement(summary_elem, "SecurityPosture").text = exec_summary.get('security_posture_rating', '')
                ET.SubElement(summary_elem, "Overview").text = exec_summary.get('executive_overview', '')
                
                # Key findings
                findings_elem = ET.SubElement(summary_elem, "KeyFindings")
                for finding in exec_summary.get('key_findings', []):
                    finding_elem = ET.SubElement(findings_elem, "Finding")
                    ET.SubElement(finding_elem, "Description").text = finding.get('finding', '')
                    ET.SubElement(finding_elem, "BusinessImpact").text = finding.get('business_impact', '')
                    ET.SubElement(finding_elem, "Urgency").text = finding.get('urgency', '')
            
            # Vulnerabilities
            vulnerabilities = analysis_data.get('xss_data', {}).get('vulnerabilities', [])
            if vulnerabilities:
                vulns_elem = ET.SubElement(root, "Vulnerabilities")
                vulns_elem.set("count", str(len(vulnerabilities)))
                
                for vuln in vulnerabilities:
                    if self._is_valid_vulnerability(vuln):
                        vuln_elem = ET.SubElement(vulns_elem, "Vulnerability")
                        vuln_elem.set("id", f"BRS-GPT-{hash(vuln.get('url', '')) % 10000:04d}")
                        
                        ET.SubElement(vuln_elem, "Severity").text = vuln.get('severity', 'medium')
                        ET.SubElement(vuln_elem, "URL").text = vuln.get('url', '')
                        ET.SubElement(vuln_elem, "Parameter").text = vuln.get('parameter', '')
                        ET.SubElement(vuln_elem, "Method").text = vuln.get('method', 'GET')
                        ET.SubElement(vuln_elem, "Context").text = vuln.get('context', {}).get('type', '')
                        ET.SubElement(vuln_elem, "CWE").text = vuln.get('cwe', 'CWE-79')
                        ET.SubElement(vuln_elem, "OWASP").text = vuln.get('owasp', 'A03:2021 - Injection')
                        ET.SubElement(vuln_elem, "Impact").text = vuln.get('impact', '')
                        
                        # Remediation
                        remediation = vuln.get('remediation', {})
                        if remediation:
                            rem_elem = ET.SubElement(vuln_elem, "Remediation")
                            ET.SubElement(rem_elem, "Summary").text = remediation.get('summary', '')
                            
                            details_elem = ET.SubElement(rem_elem, "Details")
                            for detail in remediation.get('details', []):
                                ET.SubElement(details_elem, "Step").text = detail
            
            # Write XML file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)  # Pretty formatting
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            return str(output_path.absolute())
            
        except Exception as e:
            return None
    
    def format_markdown_report(self, analysis_data: Dict[str, Any], 
                              output_file: str) -> Optional[str]:
        """
        Generate Markdown documentation report.
        
        Args:
            analysis_data: Complete analysis results
            output_file: Output Markdown file path
            
        Returns:
            Path to generated Markdown file or None if failed
        """
        try:
            target = analysis_data.get('target', 'Unknown Target')
            domain = self._extract_domain(target)
            
            markdown_content = f"""# BRS-GPT Security Analysis Report

**Target:** {target}  
**Scan Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Generated by:** BRS-GPT v{VERSION} | EasyProTech LLC  
**Contact:** https://t.me/easyprotech

---

## Executive Summary

"""
            
            # Add executive summary
            exec_summary = analysis_data.get('ai_analysis', {}).get('executive_summary', {})
            if exec_summary:
                markdown_content += f"""
**Security Posture:** {exec_summary.get('security_posture_rating', 'Unknown')}

{exec_summary.get('executive_overview', 'No executive overview available.')}

### Key Findings

"""
                for finding in exec_summary.get('key_findings', []):
                    markdown_content += f"""
#### {finding.get('finding', 'Unknown Finding')}
- **Business Impact:** {finding.get('business_impact', 'Not specified')}
- **Urgency:** {finding.get('urgency', 'Unknown')}
- **Estimated Cost to Fix:** {finding.get('estimated_cost_to_fix', 'Not estimated')}

"""
            
            # Add vulnerability details
            vulnerabilities = analysis_data.get('xss_data', {}).get('vulnerabilities', [])
            if vulnerabilities:
                markdown_content += f"""
---

## Vulnerability Details

**Total Vulnerabilities Found:** {len(vulnerabilities)}

"""
                
                # Group by severity
                severity_groups = {}
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'medium')
                    if severity not in severity_groups:
                        severity_groups[severity] = []
                    severity_groups[severity].append(vuln)
                
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in severity_groups:
                        vulns = severity_groups[severity]
                        markdown_content += f"""
### {severity.title()} Severity ({len(vulns)} issues)

"""
                        for i, vuln in enumerate(vulns, 1):
                            markdown_content += f"""
#### {severity.title()}-{i}: XSS in {vuln.get('parameter', 'Unknown Parameter')}

- **URL:** `{vuln.get('url', 'Unknown')}`
- **Parameter:** `{vuln.get('parameter', 'Unknown')}`
- **Method:** `{vuln.get('method', 'GET')}`
- **Context:** {vuln.get('context', {}).get('type', 'Unknown')}
- **Confidence:** {vuln.get('confidence', 0) * 100:.1f}%
- **CWE:** {vuln.get('cwe', 'CWE-79')}
- **OWASP:** {vuln.get('owasp', 'A03:2021 - Injection')}

**Impact:** {vuln.get('impact', 'Not specified')}

**Payload:**
```
{vuln.get('payload', 'No payload available')}
```

**Remediation:**
{vuln.get('remediation', {}).get('summary', 'No remediation guidance available.')}

"""
                        
                        remediation_details = vuln.get('remediation', {}).get('details', [])
                        if remediation_details:
                            markdown_content += "**Detailed Steps:**\n"
                            for detail in remediation_details:
                                markdown_content += f"- {detail}\n"
                            markdown_content += "\n"
            
            # Add attack scenarios
            attack_paths = analysis_data.get('ai_analysis', {}).get('attack_paths', {})
            attack_scenarios = attack_paths.get('attack_scenarios', [])
            if attack_scenarios:
                markdown_content += """
---

## Potential Attack Scenarios

"""
                for scenario in attack_scenarios:
                    markdown_content += f"""
### {scenario.get('scenario_name', 'Unknown Scenario')}

**Severity:** {scenario.get('severity', 'Unknown')}  
**Complexity:** {scenario.get('complexity', 'Unknown')}  
**Impact:** {scenario.get('impact', 'Not specified')}

**Attack Steps:**
"""
                    for step in scenario.get('attack_steps', []):
                        markdown_content += f"""
{step.get('step', 0)}. **{step.get('action', 'Unknown action')}**
   - Vulnerability Used: {step.get('vulnerability_used', 'Not specified')}
   - Tools Required: {', '.join(step.get('tools_required', []))}
   - Success Indicators: {step.get('success_indicators', 'Not specified')}

"""
                    
                    markdown_content += f"""
**Primary Mitigation:** {scenario.get('mitigation', 'No mitigation specified')}

"""
            
            # Add recommendations
            markdown_content += """
---

## Recommendations

### Immediate Actions (24-48 hours)

"""
            for action in exec_summary.get('immediate_actions', []):
                markdown_content += f"- {action}\n"
            
            markdown_content += """
### Strategic Recommendations

"""
            for recommendation in exec_summary.get('strategic_recommendations', []):
                markdown_content += f"- {recommendation}\n"
            
            # Add footer
            markdown_content += f"""

---

## Report Information

**Generated by:** BRS-GPT v{VERSION}  
**Company:** EasyProTech LLC  
**Contact:** https://t.me/easyprotech  
**Methodology:** AI-powered cybersecurity analysis  
**Report Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

---

*This report contains confidential security information. Handle according to your organization's data classification policies.*
"""
            
            # Write Markdown file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            return str(output_path.absolute())
            
        except Exception as e:
            return None
    
    def _generate_sarif_rules(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate SARIF rules based on found vulnerabilities."""
        rules = []
        
        # Standard XSS rule
        rules.append({
            "id": "XSS001",
            "name": "CrossSiteScripting",
            "shortDescription": {
                "text": "Cross-Site Scripting (XSS) vulnerability"
            },
            "fullDescription": {
                "text": "A Cross-Site Scripting vulnerability allows attackers to inject malicious scripts into web applications, potentially leading to session hijacking, data theft, or other malicious activities."
            },
            "help": {
                "text": "Implement proper input validation and output encoding to prevent XSS attacks.",
                "markdown": "## Cross-Site Scripting (XSS)\n\nXSS vulnerabilities occur when user input is not properly validated or encoded before being displayed in web applications.\n\n### Remediation\n- Implement input validation\n- Use output encoding\n- Deploy Content Security Policy (CSP)\n- Use secure coding practices"
            },
            "properties": {
                "category": "security",
                "precision": "high",
                "tags": ["security", "xss", "injection", "owasp-top-10"]
            },
            "defaultConfiguration": {
                "level": "warning"
            }
        })
        
        return rules
    
    def _convert_vulnerability_to_sarif(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Convert vulnerability to SARIF result format."""
        return {
            "ruleId": "XSS001",
            "ruleIndex": 0,
            "level": self._map_severity_to_sarif_level(vulnerability.get('severity', 'medium')),
            "message": {
                "text": f"XSS vulnerability detected in parameter '{vulnerability.get('parameter', 'unknown')}' using {vulnerability.get('context', {}).get('type', 'unknown')} context",
                "markdown": f"**XSS Vulnerability**\n\n- **Parameter:** `{vulnerability.get('parameter', 'unknown')}`\n- **Context:** {vulnerability.get('context', {}).get('type', 'unknown')}\n- **Severity:** {vulnerability.get('severity', 'medium')}\n- **Confidence:** {vulnerability.get('confidence', 0) * 100:.1f}%"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": vulnerability.get('url', ''),
                            "uriBaseId": "ROOTPATH",
                            "description": {
                                "text": f"XSS vulnerability location"
                            }
                        },
                        "region": {
                            "snippet": {
                                "text": vulnerability.get('payload', '')[:200]  # Truncate for display
                            }
                        }
                    }
                }
            ],
            "properties": {
                "severity": vulnerability.get('severity'),
                "confidence": vulnerability.get('confidence'),
                "context_type": vulnerability.get('context', {}).get('type'),
                "parameter": vulnerability.get('parameter'),
                "method": vulnerability.get('method'),
                "payload": vulnerability.get('payload'),
                "impact": vulnerability.get('impact'),
                "cwe": vulnerability.get('cwe'),
                "owasp": vulnerability.get('owasp'),
                "waf_bypass": vulnerability.get('waf_bypass', False),
                "bypass_technique": vulnerability.get('bypass_technique', ''),
                "scanner_version": vulnerability.get('scanner', f'BRS-GPT v{VERSION}'),
                "detection_timestamp": vulnerability.get('timestamp')
            },
            "fixes": [
                {
                    "description": {
                        "text": vulnerability.get('remediation', {}).get('summary', 'Implement proper input validation and output encoding'),
                        "markdown": f"## Remediation\n\n{vulnerability.get('remediation', {}).get('summary', 'Implement proper input validation and output encoding')}\n\n### Steps:\n" + '\n'.join([f"- {step}" for step in vulnerability.get('remediation', {}).get('details', [])])
                    }
                }
            ],
            "relatedLocations": [],
            "codeFlows": [],
            "stacks": [],
            "baselineState": "new"
        }
    
    def _is_valid_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """Validate vulnerability object has required fields."""
        required_fields = ['url', 'parameter', 'severity']
        return all(field in vulnerability for field in required_fields)
    
    def _map_severity_to_sarif_level(self, severity: str) -> str:
        """Map vulnerability severity to SARIF level."""
        mapping = {
            'critical': 'error',
            'high': 'error', 
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'warning')
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        return f"BRS-GPT_{timestamp}"
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        if not url:
            return 'unknown'
        
        # Remove protocol
        domain = re.sub(r'^https?://', '', url)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        
        return domain
    
    def _format_executive_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Format executive summary with proper structure."""
        return {
            "security_posture": summary.get('security_posture_rating', 'Unknown'),
            "overview": summary.get('executive_overview', ''),
            "key_findings_count": len(summary.get('key_findings', [])),
            "immediate_actions_count": len(summary.get('immediate_actions', [])),
            "strategic_recommendations_count": len(summary.get('strategic_recommendations', [])),
            "compliance_status": summary.get('compliance_status', 'Unknown')
        }
    
    def _format_risk_assessment(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format risk assessment with proper structure."""
        return {
            "overall_score": risk_data.get('overall_risk_score', 0),
            "risk_justification": risk_data.get('risk_justification', ''),
            "business_impact": risk_data.get('business_impact', {}),
            "risk_categories": risk_data.get('risk_categories', {}),
            "exploitation_likelihood": risk_data.get('exploitation_likelihood', 'Unknown'),
            "mitigation_timeline": risk_data.get('mitigation_timeline', {})
        }
    
    def _format_recon_findings(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format reconnaissance findings."""
        return {
            "subdomains_discovered": len(recon_data.get('subdomains', [])),
            "open_ports_found": len(recon_data.get('open_ports', [])),
            "technologies_identified": len(recon_data.get('technologies', {})),
            "dns_security_issues": len(recon_data.get('dns_records', {}).get('security_issues', [])),
            "critical_services": len([
                port for port in recon_data.get('open_ports', [])
                if port.get('security_notes', {}).get('risk_level') == 'critical'
            ])
        }
    
    def _format_vulnerability_findings(self, xss_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format vulnerability findings."""
        vulnerabilities = xss_data.get('vulnerabilities', [])
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": {
                "critical": len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                "high": len([v for v in vulnerabilities if v.get('severity') == 'high']),
                "medium": len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                "low": len([v for v in vulnerabilities if v.get('severity') == 'low'])
            },
            "contexts_affected": list(set(v.get('context', {}).get('type', 'unknown') for v in vulnerabilities)),
            "waf_bypasses_successful": len([v for v in vulnerabilities if v.get('waf_bypass', False)])
        }
    
    def _format_attack_vectors(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format attack vector information."""
        scenarios = attack_data.get('attack_scenarios', [])
        
        return {
            "total_scenarios": len(scenarios),
            "critical_scenarios": len([s for s in scenarios if s.get('severity') == 'Critical']),
            "attack_complexity": {
                "low": len([s for s in scenarios if s.get('complexity') == 'Low']),
                "medium": len([s for s in scenarios if s.get('complexity') == 'Medium']),
                "high": len([s for s in scenarios if s.get('complexity') == 'High'])
            },
            "critical_paths": attack_data.get('critical_attack_paths', [])
        }
    
    def _format_recommendations(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format recommendations from analysis."""
        exec_summary = analysis_data.get('ai_analysis', {}).get('executive_summary', {})
        
        return {
            "immediate_actions": exec_summary.get('immediate_actions', []),
            "strategic_recommendations": exec_summary.get('strategic_recommendations', []),
            "budget_recommendations": exec_summary.get('budget_recommendations', {}),
            "next_steps": exec_summary.get('next_steps', [])
        }
