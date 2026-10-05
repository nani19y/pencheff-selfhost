"""Deterministic, code-aware fix recipes for common DAST findings.

The DAST proposer's free path used to fall back to a TODO-comment-only
patch when no LLM was available. That's annoying — many DAST findings
have a textbook one-line fix that doesn't need a model:

  * YAML deserialization → ``yaml.load(`` → ``yaml.safe_load(``
  * Eval injection       → ``eval(...)`` flagged with a leading guard
  * Weak hashing         → ``hashlib.md5(`` → ``hashlib.sha256(``
  * Pickle / marshal     → flagged with a TODO above the import
  * Insecure cookies     → ``secure=False`` → ``secure=True``
  * HTTP redirect        → ``http://`` → ``https://`` in literal URLs
  * Wildcard CORS        → ``"*"`` → ``"<your_origin>"`` in CORS configs
  * subprocess shell=True → ``shell=True`` → ``shell=False`` (with caveat)
  * MD5/SHA1 in JS       → ``createHash('md5')`` → ``createHash('sha256')``

Each recipe is keyed off lowercase signal strings that appear in the
finding's title / description / remediation. The proposer picks the
highest-priority matching recipe, runs it against the candidate file
first, and — if no hits — across the whole repo (subject to language
constraints).

The recipes are intentionally conservative: they only replace tokens
that are *almost always* safe to swap. Anything ambiguous (e.g.
removing ``shell=True``) prepends a TODO comment instead of editing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class Recipe:
    """One deterministic transform."""
    name: str
    description: str
    languages: tuple[str, ...]                     # file suffixes the recipe targets
    apply: Callable[[str], str | None]             # text → new text or None
    signals: tuple[str, ...]                       # lowercase substrings that pick this recipe
    priority: int = 0                              # higher wins on ties


# ── Individual transforms ───────────────────────────────────────────


def _yaml_load_to_safe_load(text: str) -> str | None:
    rx = re.compile(r"\byaml\.load\s*\(")
    if not rx.search(text):
        return None
    return rx.sub("yaml.safe_load(", text)


def _md5_to_sha256_python(text: str) -> str | None:
    rx = re.compile(r"\bhashlib\.md5\s*\(")
    rx2 = re.compile(r"\bhashlib\.sha1\s*\(")
    new = rx.sub("hashlib.sha256(", text)
    new = rx2.sub("hashlib.sha256(", new)
    return new if new != text else None


def _md5_to_sha256_js(text: str) -> str | None:
    rx = re.compile(r"""createHash\(\s*['"](md5|sha1)['"]\s*\)""")
    if not rx.search(text):
        return None
    return rx.sub("createHash('sha256')", text)


def _http_to_https(text: str) -> str | None:
    """Only swap http:// in obvious URL literals — not in code-like strings.

    Conservative: requires the URL to be inside quotes and to be a public
    host (not localhost / 127.* / 0.0.0.0 / *.local / *.test).
    """
    rx = re.compile(
        r"""(['"])http://(?!(?:localhost|127\.|0\.0\.0\.0|[\w.-]+\.local|[\w.-]+\.test))([\w.-]+(?:/[^'"\s]*)?)\1"""
    )
    if not rx.search(text):
        return None
    return rx.sub(r"\1https://\2\1", text)


def _insecure_cookie(text: str) -> str | None:
    """``secure=False`` → ``secure=True`` and ``httponly=False`` → ``httponly=True``."""
    new = text
    for kw in ("secure", "httponly", "Secure", "HttpOnly"):
        rx = re.compile(rf"\b{kw}\s*=\s*False\b")
        new = rx.sub(f"{kw}=True", new)
    return new if new != text else None


def _wildcard_cors(text: str) -> str | None:
    """``Access-Control-Allow-Origin: *`` and friends → ``<your-origin>``.

    Doesn't pretend to know the right origin; leaves a clearly-marked
    placeholder so the developer's PR review surfaces it.
    """
    placeholder = "https://your-origin.example.com"
    rx_header = re.compile(r"""(['"])\*\1""")
    rx_yaml = re.compile(
        r"(allow_origins|allowed_origins|origin)(\s*[:=]\s*)\[\s*['\"]\*['\"]\s*\]",
        re.IGNORECASE,
    )
    new = rx_yaml.sub(rf"\1\2['{placeholder}']", text)
    # Header value form
    rx_header_val = re.compile(
        r'(Access-Control-Allow-Origin\s*[:=]\s*)["\']?\*["\']?',
        re.IGNORECASE,
    )
    new = rx_header_val.sub(rf"\1'{placeholder}'", new)
    return new if new != text else None


def _subprocess_shell_true(text: str) -> str | None:
    """Flag-only: prepend a TODO comment above lines using ``shell=True``.

    Removing ``shell=True`` outright would break the call (the args need
    to switch from a string to a list), so we mark it for human review
    rather than silently change behaviour.
    """
    if "shell=True" not in text:
        return None
    out: list[str] = []
    for ln in text.splitlines(keepends=True):
        if "shell=True" in ln and "# pencheff:" not in ln:
            indent = re.match(r"\s*", ln).group(0)
            out.append(
                f"{indent}# pencheff: shell=True is dangerous with user input; "
                f"switch to args list and shell=False.\n"
            )
        out.append(ln)
    new = "".join(out)
    return new if new != text else None


def _eval_or_exec_call(text: str) -> str | None:
    """Flag-only: leave a TODO comment above bare ``eval(`` / ``exec(`` calls."""
    rx = re.compile(r"^(\s*)(?P<call>eval|exec)\s*\(", re.MULTILINE)
    if not rx.search(text):
        return None
    def _annotate(m: re.Match) -> str:
        indent = m.group(1)
        call = m.group("call")
        return (
            f"{indent}# pencheff: {call}() with untrusted input is RCE — "
            "replace with a safe parser or strict allowlist.\n"
            f"{indent}{call}("
        )
    new = rx.sub(_annotate, text)
    return new if new != text else None


def _pickle_load(text: str) -> str | None:
    rx = re.compile(r"\b(pickle|marshal)\.(loads?|Unpickler)\s*\(")
    if not rx.search(text):
        return None
    out: list[str] = []
    for ln in text.splitlines(keepends=True):
        if rx.search(ln) and "# pencheff:" not in ln:
            indent = re.match(r"\s*", ln).group(0)
            out.append(
                f"{indent}# pencheff: pickle/marshal load on untrusted input is RCE; "
                f"switch to JSON or a schema-validated codec.\n"
            )
        out.append(ln)
    new = "".join(out)
    return new if new != text else None


def _hardcoded_debug(text: str) -> str | None:
    """``DEBUG = True`` → ``DEBUG = False`` (Django/Flask convention)."""
    rx = re.compile(r"^(\s*DEBUG\s*=\s*)True\s*$", re.MULTILINE)
    if not rx.search(text):
        return None
    return rx.sub(r"\1False", text)


# ── Registry ────────────────────────────────────────────────────────


_RECIPES: list[Recipe] = [
    Recipe(
        name="yaml-load-to-safe-load",
        description="Replace yaml.load(...) with yaml.safe_load(...).",
        languages=(".py",),
        apply=_yaml_load_to_safe_load,
        signals=("yaml.load", "yaml deserialization", "yaml.safe_load",
                 "yaml constructor", "unsafe yaml"),
        priority=10,
    ),
    Recipe(
        name="md5-sha1-to-sha256-python",
        description="Replace hashlib.md5/sha1 with hashlib.sha256.",
        languages=(".py",),
        apply=_md5_to_sha256_python,
        signals=("md5", "sha1", "weak hash", "weak cryptographic hash",
                 "broken or risky cryptographic", "hashlib.md5", "hashlib.sha1"),
        priority=8,
    ),
    Recipe(
        name="md5-sha1-to-sha256-js",
        description="Replace createHash('md5'|'sha1') with createHash('sha256').",
        languages=(".js", ".jsx", ".ts", ".tsx"),
        apply=_md5_to_sha256_js,
        signals=("md5", "sha1", "createhash", "weak hash"),
        priority=8,
    ),
    Recipe(
        name="http-to-https",
        description="Upgrade public http:// URL literals to https://.",
        languages=(".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java"),
        apply=_http_to_https,
        signals=("plaintext http", "http instead of https", "insecure transport",
                 "missing tls", "http url"),
        priority=6,
    ),
    Recipe(
        name="insecure-cookie",
        description="Set secure=True and httponly=True on session cookies.",
        languages=(".py", ".js", ".ts"),
        apply=_insecure_cookie,
        signals=("missing secure", "missing httponly", "insecure cookie",
                 "cookie without secure", "cookie without httponly"),
        priority=7,
    ),
    Recipe(
        name="wildcard-cors",
        description="Replace wildcard CORS origin with a placeholder.",
        languages=(".py", ".js", ".ts", ".yaml", ".yml", ".json"),
        apply=_wildcard_cors,
        signals=("cors", "access-control-allow-origin", "wildcard origin",
                 "permissive cross-origin"),
        priority=5,
    ),
    Recipe(
        name="subprocess-shell-true",
        description="Flag dangerous shell=True calls for review.",
        languages=(".py",),
        apply=_subprocess_shell_true,
        signals=("shell=true", "command injection", "os command injection",
                 "subprocess with shell"),
        priority=9,
    ),
    Recipe(
        name="eval-exec-call",
        description="Flag eval()/exec() calls — almost always RCE.",
        languages=(".py",),
        apply=_eval_or_exec_call,
        signals=("eval(", "code injection", "dynamic code execution"),
        priority=9,
    ),
    Recipe(
        name="pickle-load",
        description="Flag pickle.load on untrusted input as RCE.",
        languages=(".py",),
        apply=_pickle_load,
        signals=("pickle", "marshal", "deserialization", "unsafe deserialization"),
        priority=8,
    ),
    Recipe(
        name="hardcoded-debug",
        description="Flip DEBUG = True to False.",
        languages=(".py",),
        apply=_hardcoded_debug,
        signals=("debug=true", "debug mode enabled", "django debug"),
        priority=4,
    ),
]


def find_recipe(finding) -> Recipe | None:
    """Pick the highest-priority recipe whose signals match the finding's
    text. Returns ``None`` when nothing matches — caller falls back to
    the TODO-comment-only patch.
    """
    blob = " ".join(
        s for s in (
            getattr(finding, "title", None),
            getattr(finding, "description", None),
            getattr(finding, "remediation", None),
            getattr(finding, "category", None),
        ) if s
    ).lower()
    if not blob:
        return None
    candidates = [r for r in _RECIPES if any(s in blob for s in r.signals)]
    if not candidates:
        return None
    candidates.sort(key=lambda r: r.priority, reverse=True)
    return candidates[0]


def apply_recipe(
    recipe: Recipe,
    repo_root: Path,
    *,
    primary_file: str | None = None,
    max_files: int = 6,
) -> list[tuple[str, str, str]]:
    """Run ``recipe`` over ``repo_root`` and return a list of
    ``(rel_path, original_text, modified_text)`` tuples for files that
    actually changed.

    Tries ``primary_file`` first (the route_index winner). Only walks the
    rest of the repo if the primary file produced no change — keeps the
    diff minimal.
    """
    changes: list[tuple[str, str, str]] = []
    seen: set[Path] = set()

    def _try(file: Path) -> None:
        if file in seen:
            return
        seen.add(file)
        if file.suffix.lower() not in recipe.languages:
            return
        try:
            text = file.read_text(errors="replace")
        except OSError:
            return
        new = recipe.apply(text)
        if new and new != text:
            rel = str(file.relative_to(repo_root))
            changes.append((rel, text, new))

    # 1. Primary file
    if primary_file:
        candidate = (repo_root / primary_file).resolve()
        try:
            candidate.relative_to(repo_root.resolve())
            if candidate.is_file():
                _try(candidate)
        except (ValueError, OSError):
            pass
    if changes:
        return changes

    # 2. Whole-repo walk, capped so we don't generate sprawling PRs.
    for path in _iter_files(repo_root):
        if len(changes) >= max_files:
            break
        _try(path)
    return changes


def _iter_files(root: Path) -> Iterable[Path]:
    skip = {".git", "node_modules", ".next", "dist", "build", ".venv",
            "venv", "__pycache__", "target", "vendor", "coverage"}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(p in skip for p in path.relative_to(root).parts):
            continue
        try:
            if path.stat().st_size > 1_500_000:
                continue
        except OSError:
            continue
        yield path
