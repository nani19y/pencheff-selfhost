# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tree-sitter sub-pack discovery + execution.

The runner iterates the per-language sub-packs co-located with this
module and runs each one's ``queries.scm`` against files matching the
sub-pack's ``extensions``. Tree-sitter is an *optional* dependency —
if either ``tree_sitter`` or the language grammar isn't installed, the
sub-pack is skipped with a clear message; the rest of the SAST pass
continues normally.

Sub-pack layout:

    treesitter_pack/<language>/
        rules.json          — per-query metadata (id, severity, title,
                              description, remediation, cwe, source)
        queries.scm         — tree-sitter query file (one ``;name`` per
                              capture group matches a ``rules.json``
                              entry by id)

Each ``rules.json`` row:

    {
        "id":          "solidity-tx-origin-auth",
        "severity":    "high",
        "title":       "Authorization check via tx.origin",
        "description": "...",
        "remediation": "Use msg.sender for caller-identity checks.",
        "cwe":         "CWE-477",
        "source":      "hand-curated"   // or "ai-generated"
    }

The shared ``Finding`` dict shape returned by ``run_subpack`` mirrors
the rest of ``sast/runner.py`` so the orchestrator just appends.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PACK_ROOT = Path(__file__).resolve().parent

# Each sub-pack declares the language id (matches the
# ``tree_sitter_<lang>`` package name) and the file extensions it
# applies to. Directory name ↔ language id by convention.
_SUBPACK_CONFIG: dict[str, dict[str, Any]] = {
    "solidity": {
        "tree_sitter_module": "tree_sitter_solidity",
        "extensions": (".sol",),
    },
    "lua": {
        "tree_sitter_module": "tree_sitter_lua",
        "extensions": (".lua",),
    },
    "scala": {
        "tree_sitter_module": "tree_sitter_scala",
        "extensions": (".scala", ".sc"),
    },
    "dart": {
        "tree_sitter_module": "tree_sitter_dart",
        "extensions": (".dart",),
    },
    "kotlin": {
        "tree_sitter_module": "tree_sitter_kotlin",
        "extensions": (".kt", ".kts"),
    },
    "swift": {
        "tree_sitter_module": "tree_sitter_swift",
        "extensions": (".swift",),
    },
    # COBOL / Erlang / Elixir grammars exist but ship from less stable
    # upstreams — the loader picks them up automatically once
    # ``tree_sitter_<lang>`` resolves at import time, so contributors
    # only need to drop a sub-pack directory + add a row here.
}


@dataclass
class SubPack:
    name: str
    queries_path: Path
    rules: dict[str, dict[str, Any]]
    extensions: tuple[str, ...]
    tree_sitter_module: str
    available: bool = False
    skip_reason: str = ""
    misconfigured: list[str] = field(default_factory=list)


def is_treesitter_available() -> bool:
    """Cheap probe used by the orchestrator before iterating sub-packs."""
    try:
        import tree_sitter  # noqa: F401
        return True
    except ImportError:
        return False


def available_subpacks() -> list[SubPack]:
    """Return one ``SubPack`` per directory under ``treesitter_pack/``.

    A sub-pack is included even when its grammar isn't installed —
    ``available`` flags whether it's runnable. That lets the SAST
    orchestrator log "solidity skipped: tree_sitter_solidity not
    installed" instead of silently doing nothing.
    """
    out: list[SubPack] = []
    for child in sorted(PACK_ROOT.iterdir()):
        if not child.is_dir() or child.name.startswith("_"):
            continue
        cfg = _SUBPACK_CONFIG.get(child.name)
        if cfg is None:
            continue  # subdir without a config row — ignore
        rules_path = child / "rules.json"
        queries_path = child / "queries.scm"
        if not rules_path.is_file() or not queries_path.is_file():
            out.append(SubPack(
                name=child.name,
                queries_path=queries_path,
                rules={},
                extensions=tuple(cfg["extensions"]),
                tree_sitter_module=cfg["tree_sitter_module"],
                available=False,
                skip_reason="missing rules.json or queries.scm",
            ))
            continue
        try:
            rules_list = json.loads(rules_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            out.append(SubPack(
                name=child.name,
                queries_path=queries_path,
                rules={},
                extensions=tuple(cfg["extensions"]),
                tree_sitter_module=cfg["tree_sitter_module"],
                available=False,
                skip_reason=f"rules.json: {exc}",
            ))
            continue
        rules_index = {
            r["id"]: r for r in rules_list
            if isinstance(r, dict) and r.get("id")
        }
        sp = SubPack(
            name=child.name,
            queries_path=queries_path,
            rules=rules_index,
            extensions=tuple(cfg["extensions"]),
            tree_sitter_module=cfg["tree_sitter_module"],
        )
        # Lazy import — record the reason instead of raising.
        if not is_treesitter_available():
            sp.skip_reason = "tree_sitter not installed"
        else:
            try:
                __import__(sp.tree_sitter_module)
                sp.available = True
            except ImportError:
                sp.skip_reason = f"{sp.tree_sitter_module} not installed"
        out.append(sp)
    return out


def run_subpack(
    sp: SubPack,
    repo_root: Path,
) -> list[dict[str, Any]]:
    """Execute one sub-pack's queries against a cloned repo tree.

    Returns finding dicts in the same shape as the other SAST
    runners' output (``scanner``, ``rule_id``, ``severity``, ``title``,
    ``description``, ``file_path``, ``line_start``, ``line_end``,
    ``cwe``, ``raw``).
    """
    if not sp.available:
        log.info("treesitter pack %s skipped: %s", sp.name, sp.skip_reason)
        return []

    # Imports gated by ``sp.available`` above, so the unguarded
    # imports here are fine.
    import tree_sitter  # type: ignore[import-not-found]
    grammar_mod = __import__(sp.tree_sitter_module)
    language = tree_sitter.Language(grammar_mod.language())
    parser = tree_sitter.Parser(language)
    try:
        query = language.query(sp.queries_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — broken queries.scm
        log.warning("treesitter pack %s queries.scm rejected: %s", sp.name, exc)
        return []

    findings: list[dict[str, Any]] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in sp.extensions:
            continue
        try:
            source = path.read_bytes()
        except OSError:
            continue
        tree = parser.parse(source)
        try:
            captures = query.captures(tree.root_node)
        except Exception as exc:  # noqa: BLE001
            log.debug("treesitter pack %s query failed on %s: %s", sp.name, path, exc)
            continue
        # ``captures`` is dict[capture_name, list[Node]] in tree-sitter
        # ≥ 0.22; older versions return list[(node, name)]. Handle both.
        cap_iter = (
            ((name, n) for name, nodes in captures.items() for n in nodes)
            if isinstance(captures, dict)
            else ((name, n) for n, name in captures)
        )
        for capture_name, node in cap_iter:
            rule = sp.rules.get(capture_name)
            if rule is None:
                continue
            try:
                rel_path = path.resolve().relative_to(repo_root.resolve())
            except (ValueError, OSError):
                rel_path = path
            findings.append({
                "scanner": f"treesitter:{sp.name}",
                "rule_id": rule["id"],
                "severity": rule.get("severity", "medium"),
                "title": rule.get("title", rule["id"]),
                "description": rule.get("description"),
                "file_path": str(rel_path),
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "code_snippet": (
                    source[node.start_byte:node.end_byte]
                        .decode("utf-8", errors="replace")[:500]
                ),
                "cve": None,
                "package": None,
                "installed_version": None,
                "fixed_version": None,
                "raw": {
                    "rule": rule,
                    "subpack": sp.name,
                    "capture": capture_name,
                },
            })
    return findings
