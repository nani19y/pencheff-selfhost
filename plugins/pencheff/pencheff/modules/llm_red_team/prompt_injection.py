"""LLM01 — Prompt Injection.

Tests refusal robustness against direct override, role-play, encoded
payloads, suffix injection, and multilingual variants. The full
payload library lives in ``payloads/llm01_prompt_injection.yaml``.
"""
from __future__ import annotations

from .base import LlmRedTeamModule
from .datasets import dataset_cases
from .engine import TestCase


class PromptInjectionModule(LlmRedTeamModule):
    name = "llm_prompt_injection"
    category = "LLM Red Team"
    owasp_categories = ["LLM01"]
    owasp_category = "LLM01"
    description = "OWASP LLM01: prompt-injection refusal robustness"
    payload_file = "llm01_prompt_injection.yaml"

    def _extra_cases(self, llm_config: dict) -> list[TestCase]:
        return dataset_cases(llm_config, category="LLM01")
