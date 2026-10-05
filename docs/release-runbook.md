# PyPI release runbook

Pencheff publishes two packages from this monorepo:

| Package | Source tree | Current version |
| --- | --- | --- |
| `pencheff` | `plugins/pencheff/` | 0.7.0 |
| `pencheff-sentry` (Phase 3.1, new in v0.7) | `plugins/sentry/` | 0.1.0 |

This runbook walks through publishing both. **Pencheff publishing is
deliberately user-driven** — once a version lands on PyPI it can only
be yanked, never re-published, so the actual `twine upload` step is a
human-in-the-loop call.

## Pre-flight (already done in this branch)

These steps were completed when the branch was prepared:

- ✅ Versions bumped (`plugins/pencheff/pyproject.toml` → 0.7.0)
- ✅ `CHANGELOG.md` entry added at repo root
- ✅ `apps/docs/pages/release-notes.mdx` updated with v0.7.0 section
- ✅ `THIRD_PARTY_NOTICES.md` regenerated (`tools/license_audit.py
  --write-notices`)
- ✅ License audit passes (`tools/license_audit.py`)
- ✅ Wheels + sdists built and verified with `twine check`:
  - `plugins/pencheff/dist/pencheff-0.7.0.tar.gz`
  - `plugins/pencheff/dist/pencheff-0.7.0-py3-none-any.whl`
  - `plugins/sentry/dist/pencheff_sentry-0.1.0.tar.gz`
  - `plugins/sentry/dist/pencheff_sentry-0.1.0-py3-none-any.whl`

If you regenerate them later (e.g. after another commit), rerun:

```bash
# from the repo root
( cd plugins/pencheff && rm -rf dist && python3 -m build --sdist --wheel )
( cd plugins/sentry   && rm -rf dist && python3 -m build --sdist --wheel )
python3 -m twine check plugins/pencheff/dist/* plugins/sentry/dist/*
```

## Tag the release

```bash
git checkout main
git pull --ff-only
git tag -s v0.7.0 -m "v0.7.0 — IP-clean expansion"
git push origin v0.7.0
```

Tagging triggers `.github/workflows/release-sbom.yml` (Phase 1.3)
which generates and signs the per-release SBOM. That workflow runs
in parallel with the PyPI upload; neither blocks the other.

## Publish to TestPyPI first (recommended)

Verify the upload renders correctly in the package description and
the metadata is right before publishing to the real index. TestPyPI
is a separate registry intended for exactly this rehearsal.

```bash
python3 -m twine upload \
    --repository testpypi \
    plugins/pencheff/dist/pencheff-0.7.0* \
    plugins/sentry/dist/pencheff_sentry-0.1.0*
```

You'll be prompted for your TestPyPI API token. Open the resulting
URLs and confirm the package descriptions / classifiers / project
links / changelog look right:

* https://test.pypi.org/project/pencheff/0.7.0/
* https://test.pypi.org/project/pencheff-sentry/0.1.0/

If anything's wrong, **don't fix in place** — re-build with a `.dev1`
suffix on the version and re-upload. PyPI never accepts a re-upload
of the same version, even on TestPyPI.

## Publish to production PyPI

```bash
python3 -m twine upload \
    plugins/pencheff/dist/pencheff-0.7.0* \
    plugins/sentry/dist/pencheff_sentry-0.1.0*
```

You'll be prompted for your PyPI API token. The token must have
**upload** scope for both `pencheff` and `pencheff-sentry`. If
`pencheff-sentry` is brand-new, you'll need a "project-scoped" token
or an "all projects" token.

After upload, verify:

* https://pypi.org/project/pencheff/0.7.0/
* https://pypi.org/project/pencheff-sentry/0.1.0/

## What to do if you need to undo

PyPI **does not** support re-uploading the same version, even after
deletion. If something is wrong with v0.7.0:

1. **Yank** the bad version (`twine yank pencheff 0.7.0` or use the
   web UI at https://pypi.org/manage/project/pencheff/release/0.7.0/).
   Yanked versions stay installable for pinned users but never
   resolve for new installs.
2. Bump to v0.7.1 and publish that.

## Smoke-install from PyPI after upload

```bash
python3 -m venv /tmp/pencheff-smoke
source /tmp/pencheff-smoke/bin/activate
pip install --upgrade pencheff==0.7.0
pencheff --version    # should print: pencheff 0.7.0
pip install pencheff-sentry==0.1.0
pencheff-sentry --help
deactivate
```

## Rollback safety net

The git tag `v0.6.0` (and any earlier release) remains intact and
buildable. Operators on the previous version can stay there
indefinitely; the IP-clean expansion is additive on the database +
config side, but the CodeQL removal is a hard backwards-incompatible
change at the SAST layer (Phase 0.1). The CHANGELOG migration notes
list every operator-visible shift.
