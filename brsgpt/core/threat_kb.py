# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-15 15:20:00 UTC
# Status: Created
# Telegram: https://t.me/easyprotech

"""Local Threat Knowledge Base (no external APIs).

Provides curated, static intelligence about common services and protocols:
- Known risky defaults (e.g., anonymous access, default credentials)
- Representative CVE identifiers (non-exhaustive) for awareness
- MITRE ATT&CK technique mappings (high-level)

This KB intentionally avoids any network calls. It is designed to guide the
AI correlation and the deterministic risk model with grounded context.
"""

from __future__ import annotations

from typing import Dict, List, Any, Tuple


class ThreatKnowledgeBase:
    """Embedded knowledge base for protocol/service risks and intel.

    Data here is intentionally concise. It should be expanded over time.
    """

    def __init__(self) -> None:
        self.services: Dict[str, Dict[str, Any]] = {
            # Databases / Data stores
            "mysql": {
                "severity": "high",
                "default_creds": ["root:(empty)", "root:root"],
                "cves": ["CVE-2012-2122", "CVE-2016-6662"],
                "attck": ["T1190", "T1078"],
                "notes": "Check auth, network exposure, test for weak creds",
            },
            "postgresql": {
                "severity": "high",
                "default_creds": ["postgres:(empty)", "postgres:postgres"],
                "cves": ["CVE-2019-9193"],
                "attck": ["T1190"],
            },
            "mongodb": {
                "severity": "critical",
                "default_creds": ["(unauthenticated)"],
                "cves": ["CVE-2019-2386"],
                "attck": ["T1190"],
                "notes": "Historically exposed instances without auth",
            },
            "redis": {
                "severity": "critical",
                "default_creds": ["(noauth required)"],
                "cves": ["CVE-2022-0543"],
                "attck": ["T1110", "T1190"],
                "notes": "If INFO works without AUTH, treat as critical",
            },
            "couchdb": {
                "severity": "high",
                "default_creds": ["admin:admin"],
                "cves": ["CVE-2017-12636"],
                "attck": ["T1190"],
            },
            "influxdb": {
                "severity": "high",
                "default_creds": ["(unauthenticated)"],
                "cves": ["CVE-2019-20933"],
                "attck": ["T1190"],
            },
            "elasticsearch": {
                "severity": "critical",
                "default_creds": ["(unauthenticated REST)", "elastic:changeme"],
                "cves": ["CVE-2015-1427", "CVE-2014-3120"],
                "attck": ["T1190"],
                "notes": "Check / and /_cat/indices; unsecured clusters leak data",
            },
            "clickhouse": {
                "severity": "critical",
                "default_creds": ["default:(empty)"],
                "cves": ["CVE-2021-43304"],
                "attck": ["T1190", "T1078"],
            },
            "mssql": {
                "severity": "high",
                "default_creds": ["sa:(empty)", "sa:password"],
                "cves": ["CVE-2012-2552"],
                "attck": ["T1190"],
            },
            "oracle": {
                "severity": "high",
                "default_creds": ["system:manager", "sys:change_on_install"],
                "cves": ["CVE-2012-1675"],
                "attck": ["T1190"],
            },

            # Management / DevOps
            "docker_api": {
                "severity": "critical",
                "default_creds": [],
                "cves": ["CVE-2019-5736", "CVE-2020-15257"],
                "attck": ["T1611", "T1190"],
                "notes": "2375 is insecure (no TLS). Remote container control risk",
            },
            "kubernetes_api": {
                "severity": "critical",
                "default_creds": [],
                "cves": ["CVE-2018-1002105"],
                "attck": ["T1613", "T1078"],
                "notes": "Unauthenticated /version or open API suggests misconfig",
            },

            # DevOps/Tooling (HTTP-based)
            "gitlab": {"severity": "high", "default_creds": [], "cves": ["CVE-2021-22205"], "attck": ["T1190"]},
            "jenkins": {"severity": "high", "default_creds": ["admin:admin"], "cves": ["CVE-2018-1000861"], "attck": ["T1190"]},
            "sonarqube": {"severity": "high", "default_creds": ["admin:admin"], "cves": ["CVE-2020-27986"], "attck": ["T1190"]},
            "vault": {"severity": "critical", "default_creds": [], "cves": ["CVE-2020-16250"], "attck": ["T1552"]},
            "consul": {"severity": "high", "default_creds": [], "cves": ["CVE-2018-19653"], "attck": ["T1046"]},
            "minio": {"severity": "critical", "default_creds": ["minioadmin:minioadmin"], "cves": ["CVE-2023-28432"], "attck": ["T1530"]},
            "etcd": {"severity": "critical", "default_creds": ["(unauthenticated)"], "cves": ["CVE-2018-1098"], "attck": ["T1552"]},
            "docker_registry": {"severity": "high", "default_creds": ["(unauthenticated)"], "cves": [], "attck": ["T1525"]},
            "harbor": {"severity": "high", "default_creds": ["admin:Harbor12345"], "cves": [], "attck": ["T1525"]},
            "prometheus": {"severity": "medium", "default_creds": [], "cves": [], "attck": ["T1046"]},
            "grafana": {"severity": "high", "default_creds": ["admin:admin"], "cves": ["CVE-2021-43798"], "attck": ["T1190"]},

            # Messaging / Queues
            "rabbitmq": {"severity": "high", "default_creds": ["guest:guest"], "cves": [], "attck": ["T1041"]},
            "kafka": {"severity": "high", "default_creds": ["(unauthenticated)"], "cves": [], "attck": ["T1041"]},

            # OS/Network services
            "smb": {"severity": "critical", "default_creds": ["guest:(no password)"], "cves": ["CVE-2017-0144"], "attck": ["T1021"]},
            "ldap": {"severity": "high", "default_creds": ["anonymous bind"], "cves": [], "attck": ["T1069"]},
            "ldaps": {"severity": "high", "default_creds": ["anonymous bind"], "cves": [], "attck": ["T1069"]},
            "winrm": {"severity": "high", "default_creds": [], "cves": [], "attck": ["T1021"]},
            "rdp": {"severity": "high", "default_creds": [], "cves": ["CVE-2019-0708"], "attck": ["T1021"]},
            "nfs": {"severity": "high", "default_creds": ["(unauthenticated)"], "cves": [], "attck": ["T1021"]},
            "iscsi": {"severity": "high", "default_creds": ["(unauthenticated)"], "cves": [], "attck": ["T1021"]},

            # Messaging / IoT
            "mqtt": {
                "severity": "high",
                "default_creds": ["(unauthenticated)", "guest:guest"],
                "cves": ["CVE-2020-13849"],
                "attck": ["T1041", "T1071"],
            },

            # Legacy protocols
            "ftp": {"severity": "high", "default_creds": ["anonymous:anonymous"], "cves": [], "attck": ["T1041"]},
            "telnet": {"severity": "critical", "default_creds": [], "cves": [], "attck": ["T1021"]},
            "smtp": {"severity": "medium", "default_creds": [], "cves": [], "attck": ["T1071"]},
        }

        # Map hints from port/service fields to KB keys
        self.service_aliases: Dict[str, str] = {
            "mysql": "mysql",
            "postgresql": "postgresql",
            "postgres": "postgresql",
            "mongodb": "mongodb",
            "redis": "redis",
            "couchdb": "couchdb",
            "influxdb": "influxdb",
            "elasticsearch": "elasticsearch",
            "clickhouse": "clickhouse",
            "mssql": "mssql",
            "microsoft sql server": "mssql",
            "oracle": "oracle",
            "docker": "docker_api",
            "docker api": "docker_api",
            "kubernetes": "kubernetes_api",
            "kube-apiserver": "kubernetes_api",
            "mqtt": "mqtt",
            "ftp": "ftp",
            "telnet": "telnet",
            "smtp": "smtp",
            "http": "http",
            "https": "http",
            # DevOps aliases
            "gitlab": "gitlab",
            "jenkins": "jenkins",
            "sonarqube": "sonarqube",
            "vault": "vault",
            "consul": "consul",
            "minio": "minio",
            "s3": "minio",
            "s3_like": "minio",
            "etcd": "etcd",
            "docker registry": "docker_registry",
            "docker_registry": "docker_registry",
            "harbor": "harbor",
            "prometheus": "prometheus",
            "grafana": "grafana",
            "rabbitmq": "rabbitmq",
            "amqp": "rabbitmq",
            # OS/Network aliases
            "smb": "smb",
            "ldap": "ldap",
            "ldaps": "ldaps",
            "winrm": "winrm",
            "rdp": "rdp",
            "nfs": "nfs",
            "iscsi": "iscsi",
        }

    def _normalize_service_key(self, text: str | None) -> str | None:
        if not text:
            return None
        key = text.strip().lower()
        return self.service_aliases.get(key, key)

    def analyze_open_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build threat intel summary for discovered services.

        Args:
            open_ports: list of port info dicts from recon (port, service, database_type, banner...)
        Returns:
            Dict with per-service intel and flat lists for reporting
        """
        per_service: Dict[str, Dict[str, Any]] = {}
        cve_list: List[str] = []
        default_creds_findings: List[str] = []
        critical_services: List[str] = []

        for p in open_ports or []:
            service_hint = p.get("database_type") or p.get("service") or p.get("protocol") or ""
            kb_key = self._normalize_service_key(str(service_hint))
            if not kb_key:
                continue
            if kb_key not in self.services:
                continue
            intel = self.services[kb_key]
            per_service.setdefault(kb_key, {"ports": [], "intel": intel})["ports"].append(p.get("port"))
            cve_list.extend(intel.get("cves", []))
            for cred in intel.get("default_creds", []):
                default_creds_findings.append(f"{kb_key}: {cred}")
            if intel.get("severity") in ("critical", "high"):
                critical_services.append(kb_key)

        return {
            "by_service": per_service,
            "cves": sorted(set(cve_list)),
            "default_creds": sorted(set(default_creds_findings)),
            "critical_services": sorted(set(critical_services)),
        }

    def compute_risk_bonus(self, intel: Dict[str, Any]) -> int:
        """Compute additional deterministic score based on intel presence.

        Very conservative additive model to avoid over-penalizing.
        """
        if not intel:
            return 0
        bonus = 0
        # Each critical service adds 3 points; high adds 2 (approx via names)
        for svc in intel.get("critical_services", []):
            # treat all listed as critical for simplicity
            bonus += 3
        # Default credentials findings are very dangerous
        if intel.get("default_creds"):
            bonus += min(10, len(intel["default_creds"]))  # cap
        # CVEs presence adds small contextual weight
        if intel.get("cves"):
            bonus += min(5, len(intel["cves"]) // 3)
        return bonus


__all__ = ["ThreatKnowledgeBase"]



