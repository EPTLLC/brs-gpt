# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:12:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""Compatibility shim: re-export split AI agents to keep imports stable."""

from .agents.base import BaseAIAgent  # noqa: F401
from .agents.master import MasterDecisionAgent  # noqa: F401
from .agents.recon import ReconStrategyAgent  # noqa: F401
from .agents.vuln import VulnerabilityHuntingAgent  # noqa: F401
from .agents.threat import ThreatIntelligenceAgent  # noqa: F401
from .agents.exploit import ExploitationAgent  # noqa: F401
from .agents.reporting import ReportingAgent  # noqa: F401
from .agents.optimizer import PerformanceOptimizer  # noqa: F401
from .agents.test_planner import TestPlannerAgent  # noqa: F401
from .agents.correlation import CorrelationAgent  # noqa: F401
from .agents.compliance import ComplianceMapperAgent  # noqa: F401
