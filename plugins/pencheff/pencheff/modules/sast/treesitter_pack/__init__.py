# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tree-sitter SAST query pack (Phase 2.3).

Fills the SAST coverage gap left by removing CodeQL — for languages
that Semgrep OSS / Bandit / gosec / Brakeman / ESLint don't cover
cleanly (Solidity, Lua, Scala, Dart, Kotlin/Swift outside Mobile,
COBOL, Erlang/Elixir).

Design:

* Per-language sub-packs live as siblings of this ``__init__`` —
  ``treesitter_pack/solidity/``, ``treesitter_pack/lua/``, etc.
* Each sub-pack ships ``queries.scm`` (tree-sitter S-expression
  query syntax) plus a ``rules.json`` index file describing each
  named match: id, severity, title, description, remediation, cwe.
* Queries can be hand-curated, AI-generated, or both — the
  ``rules.json`` ``source`` field per rule records which.
* Loader (``loader.py``) is graceful: if ``tree_sitter`` or a
  language grammar isn't installed, the relevant sub-pack is
  skipped with a clear message rather than blocking the SAST pass.

Tree-sitter parsers are language grammars distributed under each
upstream's own license; Pencheff only ships query files (which are
queries against those grammars) under MIT — no grammar code is
bundled.
"""
from __future__ import annotations

from .loader import (
    SubPack,
    available_subpacks,
    is_treesitter_available,
    run_subpack,
)

__all__ = [
    "SubPack",
    "available_subpacks",
    "is_treesitter_available",
    "run_subpack",
]
