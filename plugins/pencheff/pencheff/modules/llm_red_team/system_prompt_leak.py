"""LLM07 — System Prompt Leakage."""
from __future__ import annotations

from .base import LlmRedTeamModule


class SystemPromptLeakModule(LlmRedTeamModule):
    name = "llm_system_prompt_leak"
    category = "LLM Red Team"
    owasp_categories = ["LLM07"]
    owasp_category = "LLM07"
    description = "OWASP LLM07: extraction of the deployed system prompt"
    payload_file = "llm07_system_prompt_leak.yaml"
