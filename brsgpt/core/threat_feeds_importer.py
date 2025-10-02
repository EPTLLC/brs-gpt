# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
Offline Threat Feeds Importer

Loads pre-downloaded JSON/YAML dumps (e.g., NVD CVEs, ExploitDB hints, MITRE ATT&CK) from the
configuration directory and provides lightweight correlation utilities.

No external network calls. Expected files (if present):
  ~/.config/brs-gpt/feeds/nvd_cves.json
  ~/.config/brs-gpt/feeds/exploitdb.json
  ~/.config/brs-gpt/feeds/mitre_attack.json
  ~/.config/brs-gpt/feeds/cisa_kev.json

Minimal expected schema examples:
  nvd_cves.json: { "elasticsearch": ["CVE-2015-5531", ...], "redis": ["CVE-2022-0543", ...] }
  exploitdb.json: { "elasticsearch": ["EDB-XXXX"], "redis": ["EDB-YYYY"] }
  mitre_attack.json: { "techniques": [...], "tactics": [...] }
  cisa_kev.json: { "vulnerabilities": [...] }
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from pathlib import Path
import json

try:
    # Optional YAML support if pyyaml is installed; fallback to JSON only
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


class ThreatFeedsImporter:
    """Loads offline threat feeds and correlates with discovered services."""

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        if config_dir is None:
            from ..utils.config_manager import ConfigManager
            cfg = ConfigManager()
            config_dir = cfg.config_dir
        self.base_dir = Path(config_dir) / "feeds"
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.nvd_index: Dict[str, List[str]] = {}
        self.exploitdb_index: Dict[str, List[str]] = {}
        self.mitre_attack_index: Dict[str, Any] = {}
        self.cisa_kev_index: Dict[str, List[str]] = {}
        self._load_indexes()

    def _load_indexes(self) -> None:
        """Load JSON/YAML indexes if present. Silently ignore missing files."""
        def load_file(path: Path) -> Dict[str, Any]:
            if not path.exists():
                return {}
            try:
                if path.suffix.lower() in (".yaml", ".yml") and yaml is not None:
                    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return {}

        self.nvd_index = load_file(self.base_dir / "nvd_cves.json") or {}
        self.exploitdb_index = load_file(self.base_dir / "exploitdb.json") or {}
        self.mitre_attack_index = load_file(self.base_dir / "mitre_attack.json") or {}
        self.cisa_kev_index = load_file(self.base_dir / "cisa_kev.json") or {}

    def correlate_with_services(self, service_keys: List[str]) -> Dict[str, List[str]]:
        """Return CVE/Exploit matches for given service keys.

        Args:
            service_keys: normalized service identifiers (e.g., 'redis', 'elasticsearch')
        Returns:
            Dict with 'cves' and 'exploits' lists (deduplicated)
        """
        cves: List[str] = []
        exploits: List[str] = []
        for key in service_keys:
            cves.extend(self.nvd_index.get(key, []))
            exploits.extend(self.exploitdb_index.get(key, []))
        # Dedupe while preserving order
        def _dedupe(items: List[str]) -> List[str]:
            seen = set(); out: List[str] = []
            for it in items:
                if it not in seen:
                    seen.add(it); out.append(it)
            return out
        return {"cves": _dedupe(cves), "exploits": _dedupe(exploits)}

    def correlate_with_open_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Map open ports to service keys and correlate against feeds."""
        keys: List[str] = []
        for p in open_ports or []:
            svc = (p.get("database_type") or p.get("service") or "").strip().lower()
            if not svc:
                continue
            # Normalize a few common aliases
            if svc == "microsoft sql server":
                svc = "mssql"
            if svc == "https" or svc == "http":
                continue
            keys.append(svc)
        # Normalize unique
        uniq = []
        seen = set()
        for k in keys:
            if k not in seen:
                seen.add(k); uniq.append(k)
        return self.correlate_with_services(uniq)

    def get_mitre_techniques(self, tactic: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get MITRE ATT&CK techniques.
        
        Args:
            tactic: Filter by tactic (e.g., 'initial-access', 'execution')
            
        Returns:
            List of MITRE techniques
        """
        techniques = self.mitre_attack_index.get('techniques', [])
        
        if tactic:
            return [t for t in techniques if tactic.lower() in [k.lower() for k in t.get('tactics', [])]]
        
        return techniques

    def get_cisa_kev_for_cves(self, cves: List[str]) -> List[Dict[str, Any]]:
        """
        Check if CVEs are in CISA Known Exploited Vulnerabilities catalog.
        
        Args:
            cves: List of CVE IDs
            
        Returns:
            List of matching KEV entries
        """
        kev_vulns = self.cisa_kev_index.get('vulnerabilities', [])
        matching = []
        
        for cve in cves:
            for vuln in kev_vulns:
                if vuln.get('cveID', '').upper() == cve.upper():
                    matching.append(vuln)
        
        return matching

    def get_threat_intelligence_summary(self, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get comprehensive threat intelligence summary.
        
        Args:
            open_ports: List of open ports with service information
            
        Returns:
            Comprehensive threat intelligence summary
        """
        # Correlate services with threat feeds
        correlation = self.correlate_with_open_ports(open_ports)
        cves = correlation.get('cves', [])
        exploits = correlation.get('exploits', [])
        
        # Check CISA KEV
        kev_matches = self.get_cisa_kev_for_cves(cves)
        
        # Get relevant MITRE techniques
        mitre_techniques = self.mitre_attack_index.get('techniques', [])[:10]  # Top 10
        
        return {
            'cves_found': len(cves),
            'cves': cves[:20],  # Limit to 20 for readability
            'exploits_found': len(exploits),
            'exploits': exploits[:20],
            'cisa_kev_matches': len(kev_matches),
            'cisa_kev': kev_matches,
            'mitre_techniques': mitre_techniques,
            'severity_summary': {
                'critical': len([k for k in kev_matches if k.get('knownRansomwareCampaignUse', '').lower() == 'known']),
                'high': len(kev_matches),
                'medium': max(0, len(cves) - len(kev_matches))
            }
        }


__all__ = ["ThreatFeedsImporter"]



