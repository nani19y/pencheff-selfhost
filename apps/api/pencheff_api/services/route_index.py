"""Static route extraction across attached repos.

Used by the DAST fix proposer to map a live URL like
``https://app.example.com/api/users/123`` to the source-code handler that
serves it. We scan a repo's working tree once per attach (or on demand)
and cache the result keyed by ``(repo_path, mtime_signature)`` so a busy
findings page doesn't re-walk a 100k-LOC repo on every click.

We only do **structural** extraction — regex over the well-known router
declarations. The LLM ranking layer (Pro tier) sits on top of this output.

Supported families today:

  * Python — Flask, FastAPI, Starlette, Django ``urls.py``
  * JavaScript / TypeScript — Express, Fastify, Next.js (app router +
    pages/api), NestJS decorator-style controllers
  * Ruby — Rails ``config/routes.rb``
  * Go — chi/gin/echo router methods

The output is a list of ``Route`` records. Matching against an incoming
URL path is a separate step — see ``match_path``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# Walk only files under these many bytes — anything larger is almost
# certainly a build artifact, vendored dump, or generated file.
_MAX_FILE_BYTES = 1_500_000

# Don't bother descending into these; they balloon walk time and never
# carry route declarations worth showing the user.
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", ".venv", "venv",
    "__pycache__", "target", "vendor", ".cache", "coverage", ".pytest_cache",
}

_LANG_BY_SUFFIX = {
    ".py": "python", ".js": "js", ".jsx": "js", ".ts": "ts", ".tsx": "ts",
    ".rb": "ruby", ".go": "go",
}


@dataclass
class Route:
    """One detected handler."""
    method: str               # GET/POST/PUT/DELETE/PATCH/* (lowercase is fine)
    pattern: str              # raw pattern as the framework wrote it (e.g. "/api/users/<id>")
    file: str                 # repo-relative path
    line: int                 # 1-indexed
    framework: str            # "flask" | "fastapi" | "express" | …
    handler: str | None = None  # function name when we can spot it
    raw: str = ""             # original source line, trimmed

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "pattern": self.pattern,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "handler": self.handler,
            "raw": self.raw,
        }


# ── Python ──────────────────────────────────────────────────────────

# @app.route("/foo") | @blueprint.route("/foo", methods=["POST"])
_FLASK_RE = re.compile(
    r"""@\s*(?P<obj>[\w.]+)\.route\s*\(\s*['"](?P<path>[^'"]+)['"]"""
    r"""(?:\s*,\s*methods\s*=\s*\[(?P<methods>[^\]]*)\])?""",
    re.VERBOSE,
)

# @router.get("/foo") | @app.post("/bar") (FastAPI / Starlette)
_FASTAPI_RE = re.compile(
    r"""@\s*(?P<obj>[\w.]+)\.(?P<method>get|post|put|delete|patch|options|head|api_route|websocket)\s*\(\s*['"](?P<path>[^'"]+)['"]""",
)

# Django path("/foo/", view) | re_path(r"^foo$", view)
_DJANGO_RE = re.compile(
    r"""\b(?:path|re_path|url)\s*\(\s*[r]?['"](?P<path>[^'"]+)['"]\s*,\s*(?P<view>[\w.]+)""",
)


def _parse_python(text: str, rel: str, routes: list[Route]) -> None:
    lines = text.splitlines()
    # Track the next def for handler attribution after a decorator hit.
    def_after: dict[int, str] = {}
    for i, ln in enumerate(lines):
        m = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", ln)
        if m:
            def_after[i] = m.group(1)

    def _handler_for(line_idx: int) -> str | None:
        for j in range(line_idx + 1, min(line_idx + 6, len(lines))):
            if j in def_after:
                return def_after[j]
        return None

    for i, ln in enumerate(lines):
        for m in _FLASK_RE.finditer(ln):
            methods_field = m.group("methods") or ""
            methods = [
                x.strip().strip("'\"").upper()
                for x in methods_field.split(",")
                if x.strip()
            ] or ["GET"]
            for meth in methods:
                routes.append(Route(
                    method=meth, pattern=m.group("path"), file=rel,
                    line=i + 1, framework="flask",
                    handler=_handler_for(i), raw=ln.strip(),
                ))
        for m in _FASTAPI_RE.finditer(ln):
            method = m.group("method").upper()
            if method == "API_ROUTE":
                method = "*"
            elif method == "WEBSOCKET":
                method = "WS"
            routes.append(Route(
                method=method, pattern=m.group("path"), file=rel,
                line=i + 1, framework="fastapi",
                handler=_handler_for(i), raw=ln.strip(),
            ))
        for m in _DJANGO_RE.finditer(ln):
            routes.append(Route(
                method="*", pattern=m.group("path"), file=rel,
                line=i + 1, framework="django",
                handler=m.group("view"), raw=ln.strip(),
            ))


# ── JS / TS ─────────────────────────────────────────────────────────

# app.get("/foo", handler) | router.post('/bar', handler)
_EXPRESS_RE = re.compile(
    r"""\b(?P<obj>app|router|route|server|fastify)\.(?P<method>get|post|put|delete|patch|options|head|all)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]""",
)

# @Get('/foo') | @Post('/bar', …) (NestJS)
_NEST_RE = re.compile(
    r"""@(?P<method>Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]\s*\)""",
)


def _parse_js_like(text: str, rel: str, routes: list[Route]) -> None:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        for m in _EXPRESS_RE.finditer(ln):
            framework = "fastify" if m.group("obj").lower() == "fastify" else "express"
            routes.append(Route(
                method=m.group("method").upper(), pattern=m.group("path"),
                file=rel, line=i + 1, framework=framework, raw=ln.strip(),
            ))
        for m in _NEST_RE.finditer(ln):
            routes.append(Route(
                method=m.group("method").upper(), pattern=m.group("path"),
                file=rel, line=i + 1, framework="nestjs", raw=ln.strip(),
            ))


def _next_routes_from_path(rel: str) -> list[Route]:
    """Next.js app-router and pages/api conventions are filename-based."""
    p = Path(rel)
    parts = p.parts
    routes: list[Route] = []
    # app/**/route.ts → /<segments without (groups) and route.ts>
    if "app" in parts and p.name in ("route.ts", "route.tsx", "route.js", "route.jsx"):
        idx = parts.index("app")
        segs = []
        for seg in parts[idx + 1:-1]:
            if seg.startswith("(") and seg.endswith(")"):
                continue  # route group
            seg = re.sub(r"^\[(\.\.\.)?([\w-]+)\]$", r":\2", seg)
            segs.append(seg)
        pattern = "/" + "/".join(segs) if segs else "/"
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            routes.append(Route(method=m, pattern=pattern, file=rel, line=1,
                                framework="next-app", handler=m.lower()))
    # pages/api/**/*.ts → /api/<segments>
    elif "pages" in parts and "api" in parts:
        idx = parts.index("pages")
        if parts[idx + 1] == "api":
            segs = ["api"]
            for seg in parts[idx + 2:]:
                seg = seg.removesuffix(".ts").removesuffix(".tsx").removesuffix(".js").removesuffix(".jsx")
                if seg == "index":
                    continue
                seg = re.sub(r"^\[(\.\.\.)?([\w-]+)\]$", r":\2", seg)
                segs.append(seg)
            pattern = "/" + "/".join(segs)
            routes.append(Route(method="*", pattern=pattern, file=rel, line=1,
                                framework="next-pages", handler="default"))
    return routes


# ── Ruby ────────────────────────────────────────────────────────────

# Rails routes.rb: get "/foo", to: "foos#show"  |  resources :users
_RAILS_RE = re.compile(
    r"""\b(?P<method>get|post|put|delete|patch|match|root)\s+['"](?P<path>[^'"]+)['"]""",
)


def _parse_ruby(text: str, rel: str, routes: list[Route]) -> None:
    if "routes.rb" not in rel:
        return
    for i, ln in enumerate(text.splitlines()):
        for m in _RAILS_RE.finditer(ln):
            routes.append(Route(
                method=m.group("method").upper(), pattern=m.group("path"),
                file=rel, line=i + 1, framework="rails", raw=ln.strip(),
            ))


# ── Go ──────────────────────────────────────────────────────────────

# r.Get("/foo", handler)  | router.HandleFunc("/foo", h)  | e.GET("/foo", h)
_GO_RE = re.compile(
    r'\b\w+\.(?P<method>Get|Post|Put|Delete|Patch|Head|Options|HandleFunc|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"(?P<path>[^"]+)"'
)


def _parse_go(text: str, rel: str, routes: list[Route]) -> None:
    for i, ln in enumerate(text.splitlines()):
        for m in _GO_RE.finditer(ln):
            method = m.group("method").upper()
            if method == "HANDLEFUNC":
                method = "*"
            routes.append(Route(
                method=method, pattern=m.group("path"), file=rel,
                line=i + 1, framework="go", raw=ln.strip(),
            ))


# ── Walker + cache ──────────────────────────────────────────────────


_INDEX_CACHE: dict[str, tuple[float, int, list[Route]]] = {}


def _signature(root: Path) -> tuple[float, int]:
    """Cheap mtime+filecount signature for cache invalidation."""
    latest = 0.0
    count = 0
    for p in root.rglob("*"):
        if p.is_dir() and p.name in _SKIP_DIRS:
            continue
        if p.is_file():
            try:
                latest = max(latest, p.stat().st_mtime)
                count += 1
                if count > 50_000:
                    break
            except OSError:
                continue
    return latest, count


def index_repo(repo_root: Path, *, use_cache: bool = True) -> list[Route]:
    """Return every detected route declaration in ``repo_root``.

    Cached by directory mtime so repeated lookups during a scan are O(1).
    """
    repo_root = Path(repo_root).resolve()
    if not repo_root.is_dir():
        return []
    key = str(repo_root)
    if use_cache and key in _INDEX_CACHE:
        latest_cached, count_cached, cached = _INDEX_CACHE[key]
        latest_now, count_now = _signature(repo_root)
        if abs(latest_now - latest_cached) < 0.5 and count_now == count_cached:
            return cached

    routes: list[Route] = []
    for path in repo_root.rglob("*"):
        if path.is_dir():
            if path.name in _SKIP_DIRS:
                # Skip descendants by clearing the iterator path component.
                # rglob doesn't support pruning directly, so rely on the
                # check above when we re-encounter children.
                continue
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(repo_root).parts):
            continue
        suffix = path.suffix.lower()
        lang = _LANG_BY_SUFFIX.get(suffix)
        if not lang and path.name not in ("routes.rb",):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(repo_root))
        if lang == "python":
            _parse_python(text, rel, routes)
        elif lang in ("js", "ts"):
            _parse_js_like(text, rel, routes)
            routes.extend(_next_routes_from_path(rel))
        elif lang == "ruby":
            _parse_ruby(text, rel, routes)
        elif lang == "go":
            _parse_go(text, rel, routes)
        elif path.name == "routes.rb":
            _parse_ruby(text, rel, routes)

    if use_cache:
        latest, count = _signature(repo_root)
        _INDEX_CACHE[key] = (latest, count, routes)
    return routes


# ── Path matching ───────────────────────────────────────────────────


_PARAM_TOKEN_RE = re.compile(
    r"""(?:\{[^}]+\}|<[^>]+>|:\w+|\*[\w]*)""",  # FastAPI/Express/Flask/Django/Rails
)


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert a router pattern to a regex anchored at the path's start.

    Coarsely supports {name}, :name, <name>, <int:name>, *splat. Produces a
    forgiving match that's good enough for ranking; precision lives in the
    caller's parameter-overlap scoring.
    """
    escaped = ""
    i = 0
    while i < len(pattern):
        m = _PARAM_TOKEN_RE.match(pattern, i)
        if m:
            escaped += r"[^/]+"
            i = m.end()
        else:
            ch = pattern[i]
            escaped += re.escape(ch)
            i += 1
    if not escaped.startswith("/"):
        escaped = "/" + escaped
    # Trailing slash is optional; allow an arbitrary suffix only after an
    # explicit splat, but keep the tail anchor strict otherwise.
    return re.compile("^" + escaped.rstrip("/") + r"/?$")


def _param_names(pattern: str) -> list[str]:
    """Extract parameter names from a router pattern."""
    names: list[str] = []
    for m in _PARAM_TOKEN_RE.finditer(pattern):
        token = m.group(0)
        if token.startswith("{"):
            names.append(token.strip("{}").split(":")[0])
        elif token.startswith("<"):
            names.append(token.strip("<>").split(":")[-1])
        elif token.startswith(":"):
            names.append(token[1:])
    return names


@dataclass
class RouteMatch:
    """One ranked candidate."""
    route: Route
    confidence: float            # 0..1
    reason: str
    matched_params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "route": self.route.to_dict(),
            "confidence": self.confidence,
            "reason": self.reason,
            "matched_params": self.matched_params,
        }


def match_path(
    routes: list[Route],
    *,
    method: str | None,
    url_path: str,
    parameter: str | None = None,
) -> list[RouteMatch]:
    """Score routes against a live URL path. Highest confidence first.

    Heuristic: exact-pattern match (no params) > param-aware regex match;
    bonus when the vulnerable parameter name appears in the route's params
    or in the surrounding source line.
    """
    method_norm = (method or "*").upper()
    matches: list[RouteMatch] = []
    for r in routes:
        if r.method != "*" and method_norm != "*" and r.method != method_norm:
            continue
        try:
            rx = _pattern_to_regex(r.pattern)
        except re.error:
            continue
        if not rx.match(url_path):
            continue
        # Score
        params = _param_names(r.pattern)
        confidence = 0.55
        reason_bits = [f"path matched pattern `{r.pattern}`"]
        if r.method == method_norm:
            confidence += 0.10
            reason_bits.append(f"method {method_norm} matches")
        if not params:
            confidence += 0.10
            reason_bits.append("static route (no params)")
        matched_params: list[str] = []
        if parameter:
            if parameter in params:
                confidence += 0.20
                matched_params.append(parameter)
                reason_bits.append(f"vuln param `{parameter}` is a route variable")
            elif parameter.lower() in (r.raw or "").lower():
                confidence += 0.10
                matched_params.append(parameter)
                reason_bits.append(f"vuln param `{parameter}` mentioned on route line")
        confidence = min(confidence, 0.99)
        matches.append(RouteMatch(
            route=r, confidence=confidence,
            reason="; ".join(reason_bits), matched_params=matched_params,
        ))
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


_COMMON_PREFIXES = ("/api", "/v1", "/v2", "/v3", "/api/v1", "/api/v2")


def _path_variants(url_path: str) -> list[str]:
    """Generate progressively-relaxed variants of ``url_path`` so a route
    declaration that the API server mounts under a prefix (or that the
    front-end rewrites) still matches.
    """
    p = url_path or "/"
    variants: list[str] = [p]
    for prefix in _COMMON_PREFIXES:
        if p.startswith(prefix + "/"):
            variants.append(p[len(prefix):])
        if p == prefix:
            variants.append("/")
    # Trailing-segment fallback: matches a route that was declared bare in
    # the framework (`@app.post("/signup")`) even when the live URL is
    # mounted under a deep prefix.
    segs = [s for s in p.split("/") if s]
    for i in range(1, len(segs)):
        variants.append("/" + "/".join(segs[i:]))
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _path_tokens(url_path: str) -> list[str]:
    """Tokens we can use for filename / source-file fuzzy search when no
    route declaration matches. Drops common scaffolding tokens so we don't
    light up on every file in the repo.
    """
    p = url_path or "/"
    raw = [s.strip().lower() for s in p.split("/") if s.strip()]
    drop = {"api", "v1", "v2", "v3", "internal", "public"}
    return [t for t in raw if t and t not in drop and not t.isdigit()]


def _filename_fallback(
    root: Path,
    *,
    tokens: list[str],
    parameter: str | None,
    limit: int = 5,
) -> list[RouteMatch]:
    """Find files whose name / path contains any of the URL tokens.

    Used only when no real route declaration matches. Confidence is
    capped so the proposer can tell this is a soft guess.
    """
    if not tokens and not parameter:
        return []
    needles = [t for t in tokens] + ([parameter.lower()] if parameter else [])
    needles = [n for n in needles if n]
    if not needles:
        return []
    matches: list[RouteMatch] = []
    candidate_count = 0
    for path in root.rglob("*"):
        if path.is_dir():
            if path.name in _SKIP_DIRS:
                continue
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in _LANG_BY_SUFFIX:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = str(path.relative_to(root))
        rel_low = rel.lower()
        score = 0
        hit_tokens: list[str] = []
        for n in needles:
            if n in rel_low:
                score += 1
                hit_tokens.append(n)
        if not score:
            continue
        candidate_count += 1
        # Confidence ranges 0.30 - 0.55: low enough that the UI badges it
        # as soft, high enough to surface above the empty-result error.
        confidence = min(0.30 + 0.08 * score, 0.55)
        matches.append(RouteMatch(
            route=Route(
                method="*", pattern="(unknown)", file=rel, line=1,
                framework="filename-fallback",
                handler=None,
                raw=f"filename matched: {', '.join(hit_tokens)}",
            ),
            confidence=confidence,
            reason=(
                f"No route declaration matched the live URL; closest source "
                f"file by filename tokens ({', '.join(hit_tokens)})."
            ),
            matched_params=hit_tokens,
        ))
        if candidate_count >= 200:
            # Early exit on huge repos — we sort + truncate immediately below.
            break
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches[:limit]


def find_provenance(
    repo_roots: list[Path],
    *,
    method: str | None,
    url_path: str,
    parameter: str | None = None,
    top_k: int = 5,
) -> list[tuple[Path, RouteMatch]]:
    """Top-K candidates across every attached repo, sorted by confidence.

    Cascade:
      1. Exact match against the original URL path.
      2. Try variants — strip ``/api`` / version prefixes, trailing-segment
         only — so framework-side bare declarations still pin.
      3. Filename fallback — files whose name contains URL tokens.
      4. Last resort — repo-root README / index file as a documentation
         landing spot, so the proposer always has *something* to patch.
    """
    out: list[tuple[Path, RouteMatch]] = []
    indexes: list[tuple[Path, list[Route]]] = []
    for root in repo_roots:
        try:
            indexes.append((root, index_repo(root)))
        except Exception as exc:  # noqa: BLE001
            log.warning("route_index failed for %s: %s", root, exc)

    # 1 + 2: try every path variant in order. Stop as soon as one variant
    # produces matches across any repo so we don't muddy the rankings.
    for variant in _path_variants(url_path):
        bucket: list[tuple[Path, RouteMatch]] = []
        for root, routes in indexes:
            for m in match_path(routes, method=method, url_path=variant, parameter=parameter):
                if variant != url_path:
                    # Variant matches are slightly less confident than exact.
                    m.confidence = max(0.0, min(1.0, m.confidence - 0.05))
                    m.reason = m.reason + f"; matched against relaxed path `{variant}`"
                bucket.append((root, m))
        if bucket:
            out.extend(bucket)
            break

    # 3: filename fallback — only when nothing matched structurally.
    if not out:
        tokens = _path_tokens(url_path)
        for root, _routes in indexes:
            for m in _filename_fallback(root, tokens=tokens, parameter=parameter):
                out.append((root, m))

    # 4: last resort — README at the root of any indexed repo so the
    # proposer can drop a documentation patch and open a PR.
    if not out:
        for root, _routes in indexes:
            readme = next(
                (root / name for name in (
                    "README.md", "Readme.md", "readme.md", "README", "README.rst",
                ) if (root / name).is_file()),
                None,
            )
            if readme is None:
                # Fall back to ANY file at root so we always produce something.
                for child in root.iterdir():
                    if child.is_file():
                        readme = child
                        break
            if readme is None:
                continue
            rel = str(readme.relative_to(root))
            out.append((root, RouteMatch(
                route=Route(
                    method="*", pattern="(unknown)", file=rel, line=1,
                    framework="repo-root-fallback", handler=None,
                    raw="no source-level provenance available",
                ),
                confidence=0.20,
                reason=(
                    "No source code matched the live URL; landing the patch "
                    "on the repo's README so the developer has the security "
                    "context in their PR queue."
                ),
                matched_params=[],
            )))
            break

    out.sort(key=lambda t: t[1].confidence, reverse=True)
    return out[:top_k]
