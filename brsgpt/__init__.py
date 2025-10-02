# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 17:15:41 MSK
# Status: Created
# Telegram: https://t.me/easyprotech

"""
BRS-GPT: Autonomous AI-Powered Cybersecurity Analysis Tool

A comprehensive cybersecurity analysis platform that combines:
- Built-in reconnaissance capabilities
- Context-aware XSS vulnerability scanning  
- OpenAI-powered intelligent analysis and correlation
- Professional reporting with risk prioritization

Philosophy: One command, zero configuration, maximum intelligence.
"""

from .version import VERSION as __version__
__author__ = "Brabus"
__company__ = "EasyProTech LLC"
__website__ = "https://www.easypro.tech"
__telegram__ = "https://t.me/easyprotech"

# Core imports for easy access
from .core.intelligent_orchestrator import IntelligentOrchestrator
from .core.openai_analyzer import OpenAIAnalyzer
from .core.report_generator import ReportGenerator

__all__ = [
    "IntelligentOrchestrator",
    "OpenAIAnalyzer", 
    "ReportGenerator",
    "__version__",
    "__author__",
    "__company__",
]
