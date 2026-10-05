# SPDX-License-Identifier: AGPL-3.0-or-later
"""DAST rule synthesis + community rule pack scaffolding (Phase 2.2).

Two entry points:

* ``rule_synth.synthesize_pulse_template(cve_record, poc_text, ...)``
  — turns a (CVE record + permissively-licensed PoC) pair into a
  Pulse JSON template via a deterministic schema validator on top of
  an LLM call. Provenance JSONL written under
  ``~/.pencheff/data/provenance/dast/<advisory-id>.jsonl``.

* ``tools/nuclei2pulse.py`` — bulk-imports ProjectDiscovery's Nuclei
  templates (MIT) into the same Pulse JSON format with attribution
  preserved.

Both pipelines drop their output under
``bench/rules/community/pulse/`` (the new ``COMMUNITY_TEMPLATE_DIR``
exposed by ``core/pulse.py``).
"""
from __future__ import annotations

from .rule_synth import synthesize_pulse_template

__all__ = ["synthesize_pulse_template"]
