"""GitHub App helpers — JWT minting, installation tokens, repo cloning, PR creation.

Single place for all GitHub API interaction so routers and Celery tasks share
the same auth + retry behaviour. Uses httpx (already a dependency).

Environment:
    GITHUB_APP_ID              — numeric app ID from the GitHub App settings page
    GITHUB_APP_SLUG            — URL slug (used to build the install URL)
    GITHUB_APP_PRIVATE_KEY     — PEM-encoded private key (newlines as \n allowed)
    GITHUB_APP_WEBHOOK_SECRET  — shared secret for webhook HMAC verification
    GITHUB_APP_CLIENT_ID       — optional, for the user-auth flow
"""

from __future__ import annotations

import hmac
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Iterable

import httpx
import jwt


GITHUB_API = "https://api.github.com"
GITHUB_WEB = "https://github.com"


class GitUnavailableError(RuntimeError):
    """Raised when the worker image cannot execute git."""


class GitCloneError(RuntimeError):
    """Raised for sanitized git clone/fetch/checkout failures."""


def _load_private_key() -> str:
    raw = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
    # .env files commonly escape newlines — restore them.
    return raw.replace("\\n", "\n")


def app_id() -> str:
    return os.environ.get("GITHUB_APP_ID", "")


def app_slug() -> str:
    return os.environ.get("GITHUB_APP_SLUG", "pencheff")


def webhook_secret() -> str:
    return os.environ.get("GITHUB_APP_WEBHOOK_SECRET", "")


def is_configured() -> bool:
    return bool(app_id() and _load_private_key())


def install_url(state: str | None = None) -> str:
    base = f"{GITHUB_WEB}/apps/{app_slug()}/installations/new"
    if state:
        return f"{base}?state={state}"
    return base


def generate_jwt() -> str:
    """10-minute JWT signed with the app's private key (GitHub App auth)."""
    now = int(time.time())
    payload = {
        "iat": now - 60,  # backdate 60s to absorb clock skew
        "exp": now + 540,  # 9 minutes; GitHub caps at 10
        "iss": app_id(),
    }
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")


async def get_installation_token(installation_id: int | str) -> str:
    """Exchange the app JWT for a short-lived installation access token."""
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {generate_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    r.raise_for_status()
    return r.json()["token"]


async def get_installation(installation_id: int | str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/app/installations/{installation_id}",
            headers={
                "Authorization": f"Bearer {generate_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    r.raise_for_status()
    return r.json()


async def token_for_repo(owner: str, repo: str) -> str | None:
    """Installation token scoped to ``owner/repo``, or None if the App isn't
    installed there.

    Lets cicd_pipeline Phase B authenticate with the platform's GitHub App
    instead of an operator-supplied PAT — the App is already installed on the
    repos it scans, so live probing works with zero extra credentials.
    """
    if not is_configured():
        return None
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/installation",
            headers={
                "Authorization": f"Bearer {generate_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    if r.status_code == 404:
        return None  # App not installed on this repo
    r.raise_for_status()
    inst_id = r.json().get("id")
    return await get_installation_token(inst_id) if inst_id else None


async def list_installation_repos(token: str) -> list[dict[str, Any]]:
    """Paginate through every repo the installation can see."""
    repos: list[dict[str, Any]] = []
    page = 1
    async with httpx.AsyncClient(timeout=30.0) as c:
        while True:
            r = await c.get(
                f"{GITHUB_API}/installation/repositories",
                params={"per_page": 100, "page": page},
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            r.raise_for_status()
            data = r.json()
            batch = data.get("repositories", [])
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1
    return repos


async def get_repo(token: str, full_name: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/repos/{full_name}",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
        )
    r.raise_for_status()
    return r.json()


async def get_default_branch_sha(token: str, full_name: str, branch: str) -> str:
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/repos/{full_name}/branches/{branch}",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
        )
    r.raise_for_status()
    return r.json()["commit"]["sha"]


def _ensure_git() -> None:
    if shutil.which("git") is None:
        raise GitUnavailableError(
            "git is not installed in the worker image; install git in the "
            "API/worker runtime before running repository scans."
        )


def _run_git(args: list[str], *, env: dict[str, str] | None = None, timeout: int) -> None:
    _ensure_git()
    try:
        subprocess.run(
            args,
            check=True,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        raise GitUnavailableError(
            "git is not installed in the worker image; install git in the "
            "API/worker runtime before running repository scans."
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace").strip()
        msg = stderr.splitlines()[-1] if stderr else "git command failed"
        raise GitCloneError(msg[:500]) from exc


def _token_auth_env(token: str) -> tuple[dict[str, str], str]:
    fd, askpass = tempfile.mkstemp(prefix="pencheff-git-askpass-", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n")
        fh.write("case \"$1\" in\n")
        fh.write("  *Username*) printf '%s\\n' \"$GIT_USERNAME\" ;;\n")
        fh.write("  *Password*) printf '%s\\n' \"$GIT_PASSWORD\" ;;\n")
        fh.write("  *) printf '\\n' ;;\n")
        fh.write("esac\n")
    os.chmod(askpass, 0o700)
    env = {
        **os.environ,
        "GIT_ASKPASS": askpass,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_USERNAME": "x-access-token",
        "GIT_PASSWORD": token,
    }
    return env, askpass


def clone_with_token(token: str, full_name: str, dest: str, sha: str | None = None) -> None:
    """Shallow-clone a repo using the installation token as the password.
    GitHub documents x-access-token:<token> basic auth for app-installation git ops.
    """
    url = f"https://github.com/{full_name}.git"
    env, askpass = _token_auth_env(token)
    try:
        try:
            _run_git(["git", "clone", "--depth", "1", url, dest], env=env, timeout=300)
            if sha:
                # Fetch + checkout the exact commit we were asked about.
                _run_git(
                    ["git", "-C", dest, "fetch", "--depth", "1", "origin", sha],
                    env=env,
                    timeout=120,
                )
                _run_git(["git", "-C", dest, "checkout", sha], env=env, timeout=30)
        except GitCloneError as exc:
            raise GitCloneError(
                "GitHub clone failed; verify PAT/app token repo access and "
                "worker network access."
            ) from exc
    finally:
        try:
            os.remove(askpass)
        except OSError:
            pass


def clone_public(html_url: str, dest: str, sha: str | None = None) -> None:
    """Shallow-clone a public GitHub repo without auth."""
    clone_url = html_url.rstrip("/")
    if not clone_url.endswith(".git"):
        clone_url = f"{clone_url}.git"
    try:
        _run_git(["git", "clone", "--depth", "1", clone_url, dest], timeout=300)
        if sha:
            _run_git(
                ["git", "-C", dest, "fetch", "--depth", "1", "origin", sha],
                timeout=120,
            )
            _run_git(["git", "-C", dest, "checkout", sha], timeout=30)
    except GitCloneError as exc:
        raise GitCloneError(
            "GitHub clone failed; verify repository access and worker network access."
        ) from exc


async def get_public_repo(full_name: str) -> dict[str, Any] | None:
    """Fetch public repo metadata anonymously. Returns ``None`` on 404."""
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/repos/{full_name}",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


async def get_public_default_branch_sha(full_name: str, branch: str) -> str:
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"{GITHUB_API}/repos/{full_name}/branches/{branch}",
            headers={"Accept": "application/vnd.github+json"},
        )
    r.raise_for_status()
    return r.json()["commit"]["sha"]


async def create_branch(token: str, full_name: str, new_branch: str, from_sha: str) -> None:
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(
            f"{GITHUB_API}/repos/{full_name}/git/refs",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"ref": f"refs/heads/{new_branch}", "sha": from_sha},
        )
    if r.status_code == 422:  # already exists
        return
    r.raise_for_status()


async def create_pr(
    token: str,
    full_name: str,
    head: str,
    base: str,
    title: str,
    body: str,
) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.post(
            f"{GITHUB_API}/repos/{full_name}/pulls",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": title, "head": head, "base": base, "body": body},
        )
    r.raise_for_status()
    return r.json()


def verify_webhook_signature(signature_header: str | None, body: bytes) -> bool:
    """GitHub sends `X-Hub-Signature-256: sha256=<hex>`."""
    secret = webhook_secret()
    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)


@dataclass
class RepoSummary:
    provider_repo_id: int
    owner: str
    name: str
    full_name: str
    default_branch: str
    private: bool
    html_url: str
    language: str | None

    @classmethod
    def from_api(cls, r: dict[str, Any]) -> "RepoSummary":
        return cls(
            provider_repo_id=int(r["id"]),
            owner=r["owner"]["login"],
            name=r["name"],
            full_name=r["full_name"],
            default_branch=r.get("default_branch") or "main",
            private=bool(r.get("private", False)),
            html_url=r["html_url"],
            language=r.get("language"),
        )


def summarize_repos(raw: Iterable[dict[str, Any]]) -> list[RepoSummary]:
    return [RepoSummary.from_api(r) for r in raw]
