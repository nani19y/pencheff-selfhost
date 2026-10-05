"""LLM10 — Unbounded Consumption."""
from __future__ import annotations

from .base import LlmRedTeamModule


class UnboundedConsumptionModule(LlmRedTeamModule):
    name = "llm_unbounded_consumption"
    category = "LLM Red Team"
    owasp_categories = ["LLM10"]
    owasp_category = "LLM10"
    description = "OWASP LLM10: token bombs, recursion, repetition, ZWSP flooding"
    payload_file = "llm10_unbounded_consumption.yaml"
