"""LLM08 — Vector and Embedding Weaknesses."""
from __future__ import annotations

from .base import LlmRedTeamModule


class VectorWeaknessModule(LlmRedTeamModule):
    name = "llm_vector_weakness"
    category = "LLM Red Team"
    owasp_categories = ["LLM08"]
    owasp_category = "LLM08"
    description = "OWASP LLM08: vector search, embedding, and RAG retrieval weakness"
    payload_file = "llm08_vector_weaknesses.yaml"
