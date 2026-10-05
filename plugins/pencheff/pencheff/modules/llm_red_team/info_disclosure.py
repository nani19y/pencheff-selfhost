"""LLM02 — Sensitive Information Disclosure."""
from __future__ import annotations

from .base import LlmRedTeamModule
from .engine import TestCase
from .guardrails import guardrail_cases


class InfoDisclosureModule(LlmRedTeamModule):
    name = "llm_info_disclosure"
    category = "LLM Red Team"
    owasp_categories = ["LLM02"]
    owasp_category = "LLM02"
    description = "OWASP LLM02: PII / training-data / secret exfiltration"
    payload_file = "llm02_info_disclosure.yaml"

    def _extra_cases(self, llm_config: dict) -> list[TestCase]:
        return guardrail_cases(llm_config, category="LLM02")
