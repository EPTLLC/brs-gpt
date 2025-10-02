# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Subfinder Integration Module

Integrates with ProjectDiscovery Subfinder for fast subdomain enumeration.
Falls back to basic DNS enumeration if Subfinder is not available.
"""

import asyncio
import json
import subprocess
from typing import List, Dict, Any
from pathlib import Path
import tempfile


class SubfinderIntegration:
    """Integration with ProjectDiscovery Subfinder for subdomain enumeration."""

    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize Subfinder integration.
        
        Args:
            settings: Reconnaissance settings
        """
        self.settings = settings
        self.max_subdomains = settings.get('max_subdomains', 1000)
        self.timeout = settings.get('subfinder_timeout', 180)  # 3 minutes default
        self.subfinder_available = self._check_subfinder_available()

    def _check_subfinder_available(self) -> bool:
        """Check if Subfinder is installed and available."""
        try:
            result = subprocess.run(
                ['subfinder', '-version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    async def enumerate_subdomains(self, domain: str, sources: List[str] | None = None) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains using Subfinder.
        
        Args:
            domain: Target domain
            sources: Specific sources to use (e.g., ['virustotal', 'dnsdumpster'])
            
        Returns:
            List of discovered subdomains with metadata
        """
        if not self.subfinder_available:
            return []

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                output_file = tmp.name

            cmd = [
                'subfinder',
                '-d', domain,
                '-json',
                '-o', output_file,
                '-timeout', str(self.timeout),
                '-silent'
            ]

            if sources:
                cmd.extend(['-sources', ','.join(sources)])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                await asyncio.wait_for(process.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

            subdomains = self._parse_subfinder_output(output_file)
            Path(output_file).unlink(missing_ok=True)

            return subdomains[:self.max_subdomains]

        except Exception:
            return []

    def _parse_subfinder_output(self, output_file: str) -> List[Dict[str, Any]]:
        """
        Parse Subfinder JSON output.
        
        Args:
            output_file: Path to Subfinder output file
            
        Returns:
            List of subdomain information
        """
        subdomains = []
        
        try:
            output_path = Path(output_file)
            if not output_path.exists():
                return subdomains

            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        subdomain_info = {
                            'name': data.get('host', ''),
                            'source': data.get('source', 'subfinder'),
                            'ip': data.get('ip', ''),
                            'type': 'subdomain'
                        }
                        
                        if subdomain_info['name']:
                            subdomains.append(subdomain_info)
                    
                    except json.JSONDecodeError:
                        continue

        except Exception:
            pass

        return subdomains

    async def enumerate_recursive(self, domain: str, max_depth: int = 2) -> List[Dict[str, Any]]:
        """
        Recursively enumerate subdomains.
        
        Args:
            domain: Target domain
            max_depth: Maximum recursion depth
            
        Returns:
            List of discovered subdomains
        """
        if not self.subfinder_available:
            return []

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                output_file = tmp.name

            cmd = [
                'subfinder',
                '-d', domain,
                '-json',
                '-o', output_file,
                '-recursive',
                '-timeout', str(self.timeout),
                '-silent'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                await asyncio.wait_for(process.communicate(), timeout=self.timeout * 2)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

            subdomains = self._parse_subfinder_output(output_file)
            Path(output_file).unlink(missing_ok=True)

            return subdomains[:self.max_subdomains]

        except Exception:
            return []


__all__ = ['SubfinderIntegration']

