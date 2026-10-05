"""LLM03 — Supply Chain."""
from __future__ import annotations

from .base import LlmRedTeamModule


class SupplyChainModule(LlmRedTeamModule):
    name = "llm_supply_chain"
    category = "LLM Red Team"
    owasp_categories = ["LLM03"]
    owasp_category = "LLM03"
    description = "OWASP LLM03: package, model, and integration supply-chain risk"
    payload_file = "llm03_supply_chain.yaml"
