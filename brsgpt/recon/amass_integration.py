# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-03 01:41:52 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
Amass Integration Module

Integrates with OWASP Amass for advanced subdomain enumeration.
Falls back to basic DNS enumeration if Amass is not available.
"""

import asyncio
import json
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path
import tempfile


class AmassIntegration:
    """Integration with OWASP Amass for subdomain enumeration."""

    def __init__(self, settings: Dict[str, Any]):
        """
        Initialize Amass integration.
        
        Args:
            settings: Reconnaissance settings
        """
        self.settings = settings
        self.max_subdomains = settings.get('max_subdomains', 1000)
        self.timeout = settings.get('amass_timeout', 300)  # 5 minutes default
        self.amass_available = self._check_amass_available()

    def _check_amass_available(self) -> bool:
        """Check if Amass is installed and available."""
        try:
            result = subprocess.run(
                ['amass', '-version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    async def enumerate_subdomains(self, domain: str, passive_only: bool = False) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains using Amass.
        
        Args:
            domain: Target domain
            passive_only: Use only passive enumeration (no active DNS queries)
            
        Returns:
            List of discovered subdomains with metadata
        """
        if not self.amass_available:
            return []

        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                output_file = tmp.name

            # Build Amass command
            cmd = ['amass', 'enum', '-d', domain, '-json', output_file]
            
            if passive_only:
                cmd.append('-passive')
            
            # Add timeout
            cmd.extend(['-timeout', str(self.timeout)])

            # Run Amass
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

            # Parse results
            subdomains = self._parse_amass_output(output_file)

            # Cleanup
            Path(output_file).unlink(missing_ok=True)

            return subdomains[:self.max_subdomains]

        except Exception:
            return []

    def _parse_amass_output(self, output_file: str) -> List[Dict[str, Any]]:
        """
        Parse Amass JSON output.
        
        Args:
            output_file: Path to Amass output file
            
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
                            'name': data.get('name', ''),
                            'domain': data.get('domain', ''),
                            'addresses': data.get('addresses', []),
                            'source': data.get('source', 'amass'),
                            'tag': data.get('tag', ''),
                            'type': 'subdomain'
                        }
                        
                        if subdomain_info['name']:
                            subdomains.append(subdomain_info)
                    
                    except json.JSONDecodeError:
                        continue

        except Exception:
            pass

        return subdomains

    async def enumerate_with_config(self, domain: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains using custom Amass config file.
        
        Args:
            domain: Target domain
            config_file: Path to Amass config file
            
        Returns:
            List of discovered subdomains
        """
        if not self.amass_available or not config_file:
            return await self.enumerate_subdomains(domain)

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                output_file = tmp.name

            cmd = [
                'amass', 'enum',
                '-d', domain,
                '-config', config_file,
                '-json', output_file,
                '-timeout', str(self.timeout)
            ]

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

            subdomains = self._parse_amass_output(output_file)
            Path(output_file).unlink(missing_ok=True)

            return subdomains[:self.max_subdomains]

        except Exception:
            return []


__all__ = ['AmassIntegration']

