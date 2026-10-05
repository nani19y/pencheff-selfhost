"""LLM04 — Data and Model Poisoning."""
from __future__ import annotations

from .base import LlmRedTeamModule


class DataPoisoningModule(LlmRedTeamModule):
    name = "llm_data_poisoning"
    category = "LLM Red Team"
    owasp_categories = ["LLM04"]
    owasp_category = "LLM04"
    description = "OWASP LLM04: poisoned context, memory, and training-data influence"
    payload_file = "llm04_data_poisoning.yaml"
