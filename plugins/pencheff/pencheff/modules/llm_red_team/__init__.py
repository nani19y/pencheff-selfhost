"""LLM red-team modules — OWASP LLM Top 10 black-box probes.

All OWASP LLM Top 10 (2025) categories are represented. Categories
that depend on application internals (supply chain, memory poisoning,
agent actions, embeddings, and misinformation) use black-box probes
plus optional custom policy/intent payloads from ``llm_config``.

Each subclass of ``LlmRedTeamModule`` points at one YAML payload
file under ``payloads/`` and inherits the dispatch + verdict +
technique-level aggregation pipeline from base.py.
"""
from __future__ import annotations

from .base import LlmRedTeamModule
from .custom import ExcessiveAgencyModule, MisinformationPolicyModule
from .data_poisoning import DataPoisoningModule
from .engine import LlmProbe, ProbeResponse, ProviderError, TestCase, Verdict, evaluate, extract_path
from .info_disclosure import InfoDisclosureModule
from .output_handling import OutputHandlingModule
from .prompt_injection import PromptInjectionModule
from .supply_chain import SupplyChainModule
from .system_prompt_leak import SystemPromptLeakModule
from .unbounded_consumption import UnboundedConsumptionModule
from .vector_weaknesses import VectorWeaknessModule

# Stable mapping consumed by ``server.scan_llm_red_team``. Keys are
# OWASP LLM IDs; the MCP tool accepts a categories filter and looks
# up each name in this dict so adding a new category later is a
# one-line change here.
LLM_RED_TEAM_MODULES: dict[str, type[LlmRedTeamModule]] = {
    "LLM01": PromptInjectionModule,
    "LLM02": InfoDisclosureModule,
    "LLM03": SupplyChainModule,
    "LLM04": DataPoisoningModule,
    "LLM05": OutputHandlingModule,
    "LLM06": ExcessiveAgencyModule,
    "LLM07": SystemPromptLeakModule,
    "LLM08": VectorWeaknessModule,
    "LLM09": MisinformationPolicyModule,
    "LLM10": UnboundedConsumptionModule,
}

__all__ = [
    "InfoDisclosureModule",
    "DataPoisoningModule",
    "ExcessiveAgencyModule",
    "LlmProbe",
    "LlmRedTeamModule",
    "LLM_RED_TEAM_MODULES",
    "MisinformationPolicyModule",
    "OutputHandlingModule",
    "ProbeResponse",
    "ProviderError",
    "PromptInjectionModule",
    "SupplyChainModule",
    "SystemPromptLeakModule",
    "TestCase",
    "UnboundedConsumptionModule",
    "VectorWeaknessModule",
    "Verdict",
    "evaluate",
    "extract_path",
]
