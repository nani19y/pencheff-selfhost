# SPDX-License-Identifier: AGPL-3.0-or-later
"""Community probe corpus + provenance machinery (Phase 2.1).

The built-in YAML payloads under ``llm_red_team/payloads/`` are the
hand-curated OWASP-LLM Top 10 minimum. The corpus under
``community/probes/`` is the **extensible** pile — populated by:

* Permissive imports from upstream OSS corpora (Promptfoo, Garak,
  JailbreakBench, AgentDojo, DoNotAnswer, HH-RLHF). One importer per
  upstream lives under ``tools/`` at the repo root.
* AI-synthesised probes seeded from those imports plus the user's
  discovered profile (purpose, limitations, tools). The synthesis
  pipeline reuses the existing ``synthesis.py`` machinery; this
  package adds the seed-loader + provenance-writer.

Every imported / synthesised probe ships with metadata recording
``source``, ``license``, ``attribution``, ``import_date``, and
``synthesizer_inputs[]`` (when AI-generated). The metadata is the
audit trail that lets a downstream user answer "where did this
probe come from?" if a generated jailbreak is challenged.

License posture: every importer rejects probes whose source license
is not on ``tools/license-allowlist.txt`` for inputs. HarmBench (non-
commercial), AgentHarm (custom academic), BeaverTails (restrictive)
are documented in ``IMPORTERS.md`` as **excluded** until upstream
relicenses.
"""
from __future__ import annotations

from .loader import load_community_probes
from .schema import ProbeMetadata, ProbeRow

__all__ = ["ProbeMetadata", "ProbeRow", "load_community_probes"]
