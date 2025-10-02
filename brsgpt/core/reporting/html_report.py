from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Template

from .data_prep import prepare_html_template_data
from .html_template import HTML_TEMPLATE


async def generate_html_report(settings: Dict[str, Any], analysis_results: Dict[str, Any], output_file: str) -> Optional[str]:
    try:
        template_data = prepare_html_template_data(analysis_results)
        template = Template(HTML_TEMPLATE)
        html_content = template.render(**template_data)

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        return str(output_path.absolute())
    except Exception:
        return None
