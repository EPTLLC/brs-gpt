# BRS-GPT: AI-Enhanced Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""Tests for Threat Feeds Importer."""

import pytest
import tempfile
import json
from pathlib import Path
from brsgpt.core.threat_feeds_importer import ThreatFeedsImporter


def test_threat_feeds_initialization():
    """Test threat feeds importer initializes correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        feeds = ThreatFeedsImporter(Path(tmpdir))
        
        assert feeds.base_dir.exists()
        assert feeds.nvd_index == {}
        assert feeds.exploitdb_index == {}
        assert feeds.mitre_attack_index == {}
        assert feeds.cisa_kev_index == {}


def test_threat_feeds_load_nvd():
    """Test loading NVD CVE data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        feeds_dir = config_dir / 'feeds'
        feeds_dir.mkdir(parents=True)
        
        # Create test NVD data
        nvd_data = {
            'redis': ['CVE-2022-0543', 'CVE-2021-32672'],
            'elasticsearch': ['CVE-2015-5531']
        }
        
        nvd_file = feeds_dir / 'nvd_cves.json'
        nvd_file.write_text(json.dumps(nvd_data))
        
        feeds = ThreatFeedsImporter(config_dir)
        
        assert feeds.nvd_index == nvd_data
        assert 'redis' in feeds.nvd_index
        assert len(feeds.nvd_index['redis']) == 2


def test_threat_feeds_correlate_services():
    """Test correlation with services."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        feeds_dir = config_dir / 'feeds'
        feeds_dir.mkdir(parents=True)
        
        # Create test data
        nvd_data = {'redis': ['CVE-2022-0543']}
        exploitdb_data = {'redis': ['EDB-50749']}
        
        (feeds_dir / 'nvd_cves.json').write_text(json.dumps(nvd_data))
        (feeds_dir / 'exploitdb.json').write_text(json.dumps(exploitdb_data))
        
        feeds = ThreatFeedsImporter(config_dir)
        result = feeds.correlate_with_services(['redis'])
        
        assert 'CVE-2022-0543' in result['cves']
        assert 'EDB-50749' in result['exploits']


def test_threat_feeds_correlate_open_ports():
    """Test correlation with open ports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        feeds_dir = config_dir / 'feeds'
        feeds_dir.mkdir(parents=True)
        
        nvd_data = {'redis': ['CVE-2022-0543']}
        (feeds_dir / 'nvd_cves.json').write_text(json.dumps(nvd_data))
        
        feeds = ThreatFeedsImporter(config_dir)
        
        open_ports = [
            {'port': 6379, 'service': 'redis'},
            {'port': 80, 'service': 'http'}
        ]
        
        result = feeds.correlate_with_open_ports(open_ports)
        
        assert 'CVE-2022-0543' in result['cves']


def test_threat_feeds_mitre_techniques():
    """Test MITRE ATT&CK techniques retrieval."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        feeds_dir = config_dir / 'feeds'
        feeds_dir.mkdir(parents=True)
        
        mitre_data = {
            'techniques': [
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactics': ['initial-access']},
                {'id': 'T1210', 'name': 'Exploitation of Remote Services', 'tactics': ['lateral-movement']}
            ]
        }
        
        (feeds_dir / 'mitre_attack.json').write_text(json.dumps(mitre_data))
        
        feeds = ThreatFeedsImporter(config_dir)
        
        # Get all techniques
        all_techniques = feeds.get_mitre_techniques()
        assert len(all_techniques) == 2
        
        # Filter by tactic
        initial_access = feeds.get_mitre_techniques('initial-access')
        assert len(initial_access) == 1
        assert initial_access[0]['id'] == 'T1190'


def test_threat_feeds_cisa_kev():
    """Test CISA KEV catalog lookup."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        feeds_dir = config_dir / 'feeds'
        feeds_dir.mkdir(parents=True)
        
        kev_data = {
            'vulnerabilities': [
                {'cveID': 'CVE-2024-21626', 'product': 'Docker Engine'},
                {'cveID': 'CVE-2023-12345', 'product': 'Test App'}
            ]
        }
        
        (feeds_dir / 'cisa_kev.json').write_text(json.dumps(kev_data))
        
        feeds = ThreatFeedsImporter(config_dir)
        
        cves = ['CVE-2024-21626', 'CVE-9999-9999']
        matches = feeds.get_cisa_kev_for_cves(cves)
        
        assert len(matches) == 1
        assert matches[0]['cveID'] == 'CVE-2024-21626'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

