"""Tests for the multi-ecosystem SCA dependency-upgrade patcher used by
``fix_proposer._dependency_upgrade_patch``. Covers all 9 supported manifest
formats plus the lockfile-refusal contract.
"""
from __future__ import annotations

import json

from pencheff_api.services.fix_proposer import _dependency_upgrade_patch


def _autofix(pkg: str, fix: str, ecosystem: str = "PyPI") -> dict:
    return {
        "tool": "osv",
        "ecosystem": ecosystem,
        "package": pkg,
        "fix_version": fix,
    }


# ── Python ───────────────────────────────────────────────────────────


def test_requirements_txt_pinned():
    src = "flask==2.0.0\nrequests>=2.20\n# comment\n"
    out = _dependency_upgrade_patch(src, "requirements.txt",
                                    _autofix("flask", "2.3.3"))
    assert out is not None
    assert "flask==2.3.3" in out
    assert "requests>=2.20" in out  # untouched


def test_requirements_txt_unpinned_with_extras():
    src = "django[bcrypt]>=3.2\n"
    out = _dependency_upgrade_patch(src, "requirements.txt",
                                    _autofix("django", "4.2.10"))
    # Extras should be preserved — patcher only edits the version spec.
    assert out is not None and "django[bcrypt]==4.2.10" in out


def test_requirements_txt_no_match_returns_none():
    src = "flask==2.0.0\n"
    assert _dependency_upgrade_patch(src, "requirements.txt",
                                     _autofix("nonexistent", "1.0")) is None


def test_pyproject_pep621():
    src = (
        "[project]\n"
        'dependencies = ["requests >=2.0", "flask==2.0.0"]\n'
    )
    out = _dependency_upgrade_patch(src, "pyproject.toml",
                                    _autofix("flask", "2.3.3"))
    assert out is not None and 'flask==2.3.3' in out


def test_pyproject_poetry_string_form():
    src = (
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'flask = "^2.0.0"\n'
    )
    out = _dependency_upgrade_patch(src, "pyproject.toml",
                                    _autofix("flask", "2.3.3"))
    assert out is not None and "flask = \"^2.3.3\"" in out


def test_pyproject_poetry_table_form():
    src = (
        "[tool.poetry.dependencies]\n"
        'flask = { version = "^2.0.0", extras = ["async"] }\n'
    )
    out = _dependency_upgrade_patch(src, "pyproject.toml",
                                    _autofix("flask", "2.3.3"))
    assert out is not None and '"^2.3.3"' in out


def test_pipfile():
    src = (
        "[packages]\n"
        'flask = "==2.0.0"\n'
    )
    out = _dependency_upgrade_patch(src, "Pipfile",
                                    _autofix("flask", "2.3.3"))
    assert out is not None and 'flask = "==2.3.3"' in out


# ── Node ─────────────────────────────────────────────────────────────


def test_package_json_dependencies():
    src = json.dumps({
        "name": "x",
        "dependencies": {"lodash": "^4.0.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }, indent=2)
    out = _dependency_upgrade_patch(src, "package.json",
                                    _autofix("lodash", "4.17.21",
                                             ecosystem="npm"))
    assert out is not None
    parsed = json.loads(out)
    assert parsed["dependencies"]["lodash"] == "^4.17.21"
    assert parsed["devDependencies"]["jest"] == "^29.0.0"


def test_package_lock_refused():
    src = '{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}'
    assert _dependency_upgrade_patch(src, "package-lock.json",
                                     _autofix("x", "1.1.0",
                                              ecosystem="npm")) is None


# ── Go ───────────────────────────────────────────────────────────────


def test_go_mod_block_form():
    src = (
        "module example.com/m\n\n"
        "go 1.22\n\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.9.0\n"
        "    github.com/stretchr/testify v1.8.4\n"
        ")\n"
    )
    out = _dependency_upgrade_patch(
        src, "go.mod",
        _autofix("github.com/gin-gonic/gin", "v1.10.0", ecosystem="Go"),
    )
    assert out is not None and "gin v1.10.0" in out
    assert "testify v1.8.4" in out  # unchanged


def test_go_mod_bare_semver_input_gets_v_prefix():
    src = "module x\n\nrequire github.com/foo/bar v1.0.0\n"
    out = _dependency_upgrade_patch(
        src, "go.mod",
        _autofix("github.com/foo/bar", "1.2.3", ecosystem="Go"),
    )
    assert out is not None and "github.com/foo/bar v1.2.3" in out


# ── Rust ─────────────────────────────────────────────────────────────


def test_cargo_toml_string_form():
    src = (
        "[dependencies]\n"
        'serde = "1.0.150"\n'
        'tokio = { version = "1.20", features = ["full"] }\n'
    )
    out = _dependency_upgrade_patch(
        src, "Cargo.toml",
        _autofix("serde", "1.0.200", ecosystem="crates.io"),
    )
    assert out is not None and 'serde = "1.0.200"' in out


def test_cargo_toml_inline_table_version():
    src = (
        "[dependencies]\n"
        'tokio = { version = "1.20", features = ["full"] }\n'
    )
    out = _dependency_upgrade_patch(
        src, "Cargo.toml",
        _autofix("tokio", "1.35.0", ecosystem="crates.io"),
    )
    assert out is not None and '"1.35.0"' in out


# ── Ruby ─────────────────────────────────────────────────────────────


def test_gemfile_with_version():
    src = 'gem "rails", "7.0.0"\ngem "puma"\n'
    out = _dependency_upgrade_patch(
        src, "Gemfile",
        _autofix("rails", "7.1.3", ecosystem="RubyGems"),
    )
    assert out is not None and '"~> 7.1.3"' in out


def test_gemfile_without_version_appends():
    src = 'gem "puma"\n'
    out = _dependency_upgrade_patch(
        src, "Gemfile",
        _autofix("puma", "6.4.2", ecosystem="RubyGems"),
    )
    assert out is not None and '"~> 6.4.2"' in out


# ── PHP ──────────────────────────────────────────────────────────────


def test_composer_json():
    src = json.dumps({
        "require": {"symfony/console": "^5.0"},
    }, indent=4)
    out = _dependency_upgrade_patch(
        src, "composer.json",
        _autofix("symfony/console", "6.4.0", ecosystem="Packagist"),
    )
    assert out is not None
    parsed = json.loads(out)
    assert parsed["require"]["symfony/console"] == "^6.4.0"


# ── Java ─────────────────────────────────────────────────────────────


def test_pom_xml_replace_existing_version():
    src = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.10</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>30.0-jre</version>
    </dependency>
  </dependencies>
</project>"""
    out = _dependency_upgrade_patch(
        src, "pom.xml",
        _autofix("org.apache.commons:commons-lang3", "3.14.0",
                 ecosystem="Maven"),
    )
    assert out is not None
    assert "<version>3.14.0</version>" in out
    assert "<version>30.0-jre</version>" in out  # untouched


def test_pom_xml_inserts_version_when_missing():
    src = """<dependency>
  <groupId>g</groupId>
  <artifactId>a</artifactId>
</dependency>"""
    out = _dependency_upgrade_patch(
        src, "pom.xml",
        _autofix("g:a", "1.0.0", ecosystem="Maven"),
    )
    assert out is not None and "<version>1.0.0</version>" in out


# ── Lockfile contract ────────────────────────────────────────────────


def test_lockfiles_are_refused():
    """All lockfile formats must return None — the patcher only edits
    top-level manifests; lockfile regeneration is the installer's job.
    """
    for name in [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "uv.lock",
        "Cargo.lock", "Gemfile.lock", "composer.lock", "go.sum",
    ]:
        out = _dependency_upgrade_patch(
            "anything\n", name, _autofix("x", "1.0"),
        )
        assert out is None, f"{name} should be refused"
