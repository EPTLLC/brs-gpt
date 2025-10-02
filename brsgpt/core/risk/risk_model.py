# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-15 00:00:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""Deterministic risk modeling for BRS-GPT.

Produces a reproducible risk score and remediation plan from raw scan outputs.
"""
from __future__ import annotations
from typing import Dict, Any, List

try:
    # Optional KB for contextual risk boosts (no external APIs)
    from .threat_kb import ThreatKnowledgeBase  # type: ignore
except Exception:
    ThreatKnowledgeBase = None  # type: ignore

try:
    # Offline Threat Feeds (no external APIs)
    from .threat_feeds_importer import ThreatFeedsImporter  # type: ignore
except Exception:
    ThreatFeedsImporter = None  # type: ignore


class RiskModeler:
    VULN_WEIGHTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}
    HIGH_RISK_PORTS = {
        # Legacy insecure protocols
        21, 23, 25, 53,
        # Remote access
        445, 3389, 5900, 22,
        # Databases
        1433, 1521, 3306, 5432, 6379, 27017, 9000, 9042, 9200, 5984, 8086, 7474,
        # Management interfaces
        2375, 2376, 6443, 3000, 9090, 8500, 8200,
        # Network services
        389, 636, 88, 123, 110, 143, 993, 995
    }
    HEADER_WEIGHTS = {
        "Content-Security-Policy": 10,
        "Strict-Transport-Security": 8,
        "X-Frame-Options": 5,
        "X-Content-Type-Options": 4,
    }
    POSTURE_BANDS = [
        (15, "excellent"), (30, "good"), (55, "fair"), (80, "poor"), (101, "critical")
    ]

    def build_model(self, recon: Dict[str, Any], vulns: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities: List[Dict[str, Any]] = vulns.get("vulnerabilities_found", [])
        missing_headers: List[str] = vulns.get("missing_security_headers", [])
        open_ports: List[Dict[str, Any]] = recon.get("open_ports_found", [])

        vuln_score = 0
        sev_breakdown = {k: 0 for k in self.VULN_WEIGHTS}
        for v in vulnerabilities:
            sev = (v.get("severity") or "medium").lower()
            sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1
            vuln_score += self.VULN_WEIGHTS.get(sev, 0)

        port_score = 0.0
        risky_ports = []
        verified_ports = 0
        for p in open_ports:
            port_num = p.get("port")
            connect_confirmed = bool(p.get("evidence", {}).get("connect"))
            if connect_confirmed:
                verified_ports += 1
            risk_level = (p.get("security_notes", {}).get("risk_level") or "low").lower()
            service_conf = p.get("service_confidence", "unknown")
            base = 0.0
            if risk_level == "critical":
                base = 12.0
            elif risk_level == "high":
                base = 8.0
            elif risk_level == "medium":
                base = 4.0
            elif connect_confirmed:
                base = 2.0

            if service_conf != "confirmed":
                base *= 0.5

            port_score += base

            if isinstance(port_num, int) and risk_level in {"high", "critical"}:
                risky_ports.append(port_num)

        header_score = 0
        header_details = []
        for h in missing_headers:
            w = self.HEADER_WEIGHTS.get(h, 2)
            header_score += w
            header_details.append({"header": h, "weight": w})

        # Optional threat intel context
        threat_intel_summary: Dict[str, Any] = {}
        intel_bonus = 0
        if ThreatKnowledgeBase is not None:
            try:
                kb = ThreatKnowledgeBase()
                threat_intel_summary = kb.analyze_open_ports(open_ports)
                intel_bonus = kb.compute_risk_bonus(threat_intel_summary)
            except Exception:
                intel_bonus = 0

        # Optional offline threat feeds correlation (NVD/ExploitDB dumps)
        threat_feeds_summary: Dict[str, Any] = {}
        if ThreatFeedsImporter is not None:
            try:
                feeds = ThreatFeedsImporter()
                threat_feeds_summary = feeds.correlate_with_open_ports(open_ports)
            except Exception:
                threat_feeds_summary = {}

        risky_ports = sorted({p for p in risky_ports})

        raw_total = vuln_score + port_score + header_score + intel_bonus
        risk_score = min(int(raw_total), 100)
        posture = self._map_posture(risk_score)

        summary_bits = []
        if sev_breakdown.get("critical"): summary_bits.append(f"{sev_breakdown['critical']} critical vulns")
        if sev_breakdown.get("high"): summary_bits.append(f"{sev_breakdown['high']} high")
        if not summary_bits and sum(sev_breakdown.values()) == 0: summary_bits.append("no confirmed vulnerabilities")
        if verified_ports: summary_bits.append(f"{verified_ports} ports verified open")
        if risky_ports: summary_bits.append(f"{len(risky_ports)} high-risk ports exposed")
        if missing_headers: summary_bits.append(f"{len(missing_headers)} missing headers")
        if not summary_bits: summary_bits.append("minimal issues detected")

        remediation_plan = self._build_remediation_plan(vulnerabilities, risky_ports, missing_headers)

        return {
            "risk_score": risk_score,
            "security_posture": posture,
            "summary": "; ".join(summary_bits),
            "components": {
                "vulnerability_score": vuln_score,
                "port_exposure_score": round(port_score, 2),
                "header_deficit_score": header_score,
                "intel_bonus": intel_bonus,
                "verified_open_ports": verified_ports,
                "severity_breakdown": sev_breakdown,
                "high_risk_ports": risky_ports,
                "missing_headers": missing_headers,
                "header_details": header_details,
                "threat_intel": threat_intel_summary,
                "threat_feeds": threat_feeds_summary,
            },
            "remediation_plan": remediation_plan,
        }

    def _map_posture(self, score: int) -> str:
        for threshold, label in self.POSTURE_BANDS:
            if score < threshold:
                return label
        return "critical"

    def _build_remediation_plan(self, vulns: List[Dict[str, Any]], risky_ports: List[int], missing_headers: List[str]):
        immediate: List[str] = []
        short_term: List[str] = []
        long_term: List[str] = []
        for v in vulns:
            sev = (v.get("severity") or "medium").lower()
            desc = v.get("type", "vulnerability")
            if sev in ("critical", "high"):
                immediate.append(f"Fix {sev} {desc} in {v.get('parameter', 'param')} at {v.get('url', 'target')}")
            elif sev == "medium":
                short_term.append(f"Remediate medium {desc} ({v.get('parameter', 'param')})")
            else:
                long_term.append(f"Review low {desc} ({v.get('parameter', 'param')})")
        for port in risky_ports:
            immediate.append(f"Restrict/secure risky port {port}")
        for h in missing_headers:
            immediate.append(f"Implement security header: {h}")
        def _dedupe(items: List[str]) -> List[str]:
            seen=set(); out=[]
            for i in items:
                if i not in seen:
                    seen.add(i); out.append(i)
            return out
        return {"immediate": _dedupe(immediate), "short_term": _dedupe(short_term), "long_term": _dedupe(long_term)}

__all__ = ["RiskModeler"]
