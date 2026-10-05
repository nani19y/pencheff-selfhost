"""LLM05 — Improper Output Handling."""
from __future__ import annotations

from .base import LlmRedTeamModule
from .datasets import dataset_cases
from .engine import TestCase
from .guardrails import guardrail_cases


class OutputHandlingModule(LlmRedTeamModule):
    name = "llm_output_handling"
    category = "LLM Red Team"
    owasp_categories = ["LLM05"]
    owasp_category = "LLM05"
    description = "OWASP LLM05: XSS-via-output, markdown injection, unsafe HTML/JS"
    payload_file = "llm05_output_handling.yaml"

    def _extra_cases(self, llm_config: dict) -> list[TestCase]:
        return dataset_cases(llm_config, category="LLM05") + guardrail_cases(llm_config, category="LLM05")
