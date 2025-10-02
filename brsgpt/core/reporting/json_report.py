from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime

from .data_prep import calculate_scan_duration
from ...version import VERSION


async def generate_json_report(settings: Dict[str, Any], analysis_results: Dict[str, Any], output_file: str) -> Optional[str]:
    try:
        json_report = {
            'report_metadata': {
                'generator': f'BRS-GPT v{VERSION}',
                'company': 'EasyProTech LLC',
                'contact': 'https://t.me/easyprotech',
                'report_timestamp': datetime.utcnow().isoformat(),
                'report_type': 'cybersecurity_assessment',
                'target': analysis_results.get('target'),
                'scan_duration': calculate_scan_duration(analysis_results),
            },
            'executive_summary': analysis_results.get('ai_analysis', {}).get('executive_summary', {}),
            'risk_assessment': analysis_results.get('ai_analysis', {}).get('risk_assessment', {}),
            'reconnaissance_results': analysis_results.get('recon_data', {}),
            'vulnerability_results': analysis_results.get('xss_data', {}),
            'attack_path_analysis': analysis_results.get('ai_analysis', {}).get('attack_paths', {}),
            'correlation_analysis': analysis_results.get('ai_analysis', {}).get('correlation', {}),
            'technical_metadata': {
                'scan_start_time': analysis_results.get('start_time'),
                'scan_end_time': analysis_results.get('end_time'),
                'scanner_version': f'BRS-GPT v{VERSION}',
                'methodology': 'AI-powered cybersecurity analysis',
            },
        }

        if settings.get('include_raw_data', False):
            json_report['raw_data'] = analysis_results

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(json_report, indent=2, default=str), encoding='utf-8')
        return str(output_path.absolute())
    except Exception:
        return None
