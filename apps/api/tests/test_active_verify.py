"""Unit tests for the deterministic helpers in services.active_verify.

The probes themselves are integration-tested against a live target — they
issue real HTTP requests. Here we cover only the pure helpers and the
probe-registry matcher so a regression in URL parameter handling or marker
detection surfaces immediately."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from pencheff_api.services.active_verify import (
    _DOTENV_RE,
    _GITCONFIG_RE,
    _HTACCESS_RE,
    _SPA_FALLBACK_RE,
    _SQL_ERROR_RE,
    _auth_headers_from_creds,
    _find_probe,
    _set_param,
    _probe_cmdi,
    _probe_cors,
    _probe_open_redirect,
    _probe_sensitive_file,
    _probe_sqli,
    _probe_ssti,
    _probe_xss,
)


def _f(category="injection", title=None, endpoint=None, parameter=None):
    """Build a Finding-shaped object for the probe registry matchers."""
    return SimpleNamespace(
        category=category,
        title=title,
        endpoint=endpoint,
        parameter=parameter,
    )


# ──────────────────────────────────────────────────────────────── _set_param


class TestSetParam:
    def test_replaces_existing_param(self):
        assert (
            _set_param("https://x.test/path?a=1&b=2", "a", "9")
            == "https://x.test/path?a=9&b=2"
        )

    def test_appends_when_missing(self):
        assert (
            _set_param("https://x.test/path?a=1", "b", "2")
            == "https://x.test/path?a=1&b=2"
        )

    def test_handles_no_query_string(self):
        assert (
            _set_param("https://x.test/path", "a", "1")
            == "https://x.test/path?a=1"
        )

    def test_url_encodes_value(self):
        out = _set_param("https://x.test/p", "q", "1' OR 1=1-- ")
        assert "1%27+OR+1%3D1--+" in out or "1%27%20OR%201%3D1--%20" in out

    def test_preserves_path_and_fragment(self):
        out = _set_param("https://x.test/a/b?x=1#frag", "x", "2")
        assert out.startswith("https://x.test/a/b?x=2")
        assert out.endswith("#frag")


# ─────────────────────────────────────────────────────── _auth_headers_from_creds


class TestAuthHeaders:
    def test_none_yields_empty(self):
        assert _auth_headers_from_creds(None) == {}

    def test_token_becomes_bearer(self):
        h = _auth_headers_from_creds({"token": "abc.def"})
        assert h["Authorization"] == "Bearer abc.def"

    def test_basic_auth_when_no_token(self):
        h = _auth_headers_from_creds({"username": "u", "password": "p"})
        decoded = base64.b64decode(h["Authorization"].split()[1]).decode()
        assert decoded == "u:p"

    def test_token_wins_over_basic(self):
        h = _auth_headers_from_creds(
            {"token": "tok", "username": "u", "password": "p"}
        )
        assert h["Authorization"] == "Bearer tok"

    def test_api_key_cookie_and_custom_headers(self):
        h = _auth_headers_from_creds({
            "api_key": "k",
            "cookie": "session=xyz",
            "custom_headers": {"X-Tenant": "acme"},
        })
        assert h["X-API-Key"] == "k"
        assert h["Cookie"] == "session=xyz"
        assert h["X-Tenant"] == "acme"

    def test_ignores_non_string_custom_headers(self):
        h = _auth_headers_from_creds(
            {"custom_headers": {"X-Bad": 123, 1: "ok", "X-Good": "yes"}}
        )
        assert h == {"X-Good": "yes"}


# ─────────────────────────────────────────────────────────────── marker regexes


class TestSqlErrorRegex:
    @pytest.mark.parametrize("body", [
        "Warning: mysqli_num_rows() expects parameter 1 to be mysqli_result",
        "ORA-01756: quoted string not properly terminated",
        "PostgreSQL ERROR: unterminated quoted string at or near \"'foo\"",
        "You have an error in your SQL syntax; check the manual",
        "SQLSTATE[42000]: Syntax error or access violation",
        "Microsoft OLE DB Provider for ODBC Drivers SQL Server",
        "System.Data.SqlClient.SqlException: Incorrect syntax",
    ])
    def test_matches_db_error_fragments(self, body):
        assert _SQL_ERROR_RE.search(body) is not None

    @pytest.mark.parametrize("body", [
        "Welcome to the application",
        "<html><head><title>Login</title></head></html>",
        "Error: invalid credentials",  # generic error, not DB
        "404 Not Found",
    ])
    def test_does_not_match_benign_responses(self, body):
        assert _SQL_ERROR_RE.search(body) is None


class TestSensitiveFileRegexes:
    def test_dotenv_pattern(self):
        body = "DB_HOST=db.internal\nAWS_ACCESS_KEY_ID=AKIA1234\n"
        assert _DOTENV_RE.search(body) is not None

    def test_dotenv_does_not_match_html(self):
        assert _DOTENV_RE.search("<!doctype html><html><body>") is None

    def test_gitconfig_pattern(self):
        assert _GITCONFIG_RE.search('[remote "origin"]\n\turl = git@…') is not None
        assert _GITCONFIG_RE.search("[core]\n\trepositoryformatversion = 0") is not None

    def test_htaccess_pattern(self):
        assert _HTACCESS_RE.search("RewriteEngine On\nRewriteRule ^.*$ index.php") is not None
        assert _HTACCESS_RE.search('<Files "secret.txt">\n  Require all denied\n</Files>') is not None

    def test_spa_fallback_matches_html_and_404(self):
        assert _SPA_FALLBACK_RE.search("<!DOCTYPE html><html lang=\"en\">") is not None
        assert _SPA_FALLBACK_RE.search("Page not found") is not None
        assert _SPA_FALLBACK_RE.search("404 - this page does not exist") is not None


# ─────────────────────────────────────────────────────────── probe registry


class TestProbeRegistry:
    def test_sqli_routed_for_sql_injection_finding(self):
        f = _f(category="injection", title="SQL Injection (Error-Based, MySQL)")
        assert _find_probe(f) is _probe_sqli

    def test_cmdi_routed_for_os_command_injection(self):
        f = _f(category="injection", title="OS Command Injection (Time-Based)")
        assert _find_probe(f) is _probe_cmdi

    def test_ssti_routed_for_template_injection(self):
        f = _f(category="injection", title="Server-Side Template Injection (Jinja2)")
        assert _find_probe(f) is _probe_ssti

    def test_open_redirect_routed_by_category(self):
        f = _f(category="open_redirect", title="Open Redirect: /go [next]")
        assert _find_probe(f) is _probe_open_redirect

    def test_xss_routed_by_category(self):
        f = _f(category="xss", title="Reflected XSS")
        assert _find_probe(f) is _probe_xss

    def test_cors_routed_via_misconfiguration_title(self):
        f = _f(category="misconfiguration", title="CORS misconfiguration on /api")
        assert _find_probe(f) is _probe_cors

    def test_sensitive_file_routed_by_endpoint(self):
        f = _f(
            category="misconfiguration",
            title="Sensitive file accessible",
            endpoint="https://x.test/.env",
        )
        assert _find_probe(f) is _probe_sensitive_file

    def test_unrecognised_category_returns_none(self):
        f = _f(category="components", title="Vulnerable dependency: lodash 4.0")
        assert _find_probe(f) is None

    def test_matcher_crash_does_not_propagate(self):
        # Pass an object missing the .title / .endpoint attrs entirely;
        # _find_probe's broad except should swallow the AttributeError.
        class Broken:
            __slots__ = ("category",)

            def __init__(self):
                self.category = "injection"

        # Should return None rather than raise.
        assert _find_probe(Broken()) is None
