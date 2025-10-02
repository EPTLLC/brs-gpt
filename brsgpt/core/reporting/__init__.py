"""Reporting subpackage: HTML, JSON, SARIF generation and data prep."""

from .html_template import HTML_TEMPLATE  # re-export for convenience
from .data_prep import (
    prepare_html_template_data,
    calculate_scan_duration,
    calculate_payload_success_rate,
)
from .sarif import (
    generate_sarif_rules,
    convert_to_sarif_result,
)
from .html_report import generate_html_report
from .json_report import generate_json_report

__all__ = [
    "HTML_TEMPLATE",
    "prepare_html_template_data",
    "calculate_scan_duration",
    "calculate_payload_success_rate",
    "generate_sarif_rules",
    "convert_to_sarif_result",
    "generate_html_report",
    "generate_json_report",
]
