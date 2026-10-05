"""Native cloud-provider auth for Bedrock / Vertex / Azure OpenAI.

Each provider's wire format is wrapped under a small adapter so the
existing `LlmProbe` can dispatch them uniformly:

  * **Bedrock InvokeModel** — request body uses the OpenAI-Chat shape
    for `meta.*`, `mistral.*`, `cohere.*` (and any future model family
    Bedrock exposes via that surface). SigV4 signs each request via
    botocore.

  * **Vertex GenerateContent** — Google ADC obtains an access token
    (cached for 50 minutes via `google.auth.transport.requests`).
    Body is OpenAI-Chat shape mapped onto Gemini `contents[]`.

  * **Azure OpenAI** — DefaultAzureCredential mints a bearer for the
    cognitive-services scope; the body is plain OpenAI Chat (Azure
    deployments expose the standard chat-completions surface).

These adapters live behind optional imports so a base install
without `boto3`/`google-auth`/`azure-identity` still works for the
rest of the engine. Missing deps surface as ProviderError, never an
import-time crash.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


def _missing(extra: str, dep: str) -> "Exception":
    """Construct a ProviderError telling the user which extra to install."""
    from .engine import ProviderError
    return ProviderError(
        f"{extra} provider requires `pip install pencheff[{extra}]` "
        f"(adds {dep}). Install it or switch to a generic provider."
    )


# ── Bedrock ─────────────────────────────────────────────────────────


@dataclass
class BedrockSigner:
    """SigV4-sign each Bedrock InvokeModel request via botocore."""

    region: str
    profile: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None

    def sign(self, url: str, body: bytes, headers: dict[str, str]) -> dict[str, str]:
        try:
            from botocore.auth import SigV4Auth  # type: ignore[import-not-found]
            from botocore.awsrequest import AWSRequest  # type: ignore[import-not-found]
            from botocore.session import Session  # type: ignore[import-not-found]
        except ImportError as exc:
            raise _missing("bedrock", "boto3") from exc

        # Resolve credentials. Caller can pass explicit keys; otherwise
        # botocore walks env vars / instance profile / SSO.
        if self.access_key_id and self.secret_access_key:
            session = Session()
            session.set_credentials(
                self.access_key_id, self.secret_access_key, self.session_token
            )
        elif self.profile:
            session = Session(profile=self.profile)
        else:
            session = Session()
        creds = session.get_credentials()
        if creds is None:
            from .engine import ProviderError
            raise ProviderError("bedrock provider could not resolve AWS credentials")

        req = AWSRequest(
            method="POST",
            url=url,
            data=body,
            headers={**headers, "Content-Type": "application/json"},
        )
        SigV4Auth(creds.get_frozen_credentials(), "bedrock", self.region).add_auth(req)
        return dict(req.headers.items())


def build_bedrock_request(model_id: str, prompt: str, system: str | None, history: list[dict[str, str]] | None) -> tuple[dict[str, Any], str]:
    """Return (body, response_path) for a Bedrock InvokeModel request.

    The body shape is keyed on the model family. We support OpenAI-shape
    models (`meta.*`, `mistral.*`, `cohere.*`) here; everything else
    falls through to the same OpenAI shape, which most Bedrock models
    accept via the chat-completions adapter."""
    msgs = list(history or [])
    msgs.append({"role": "user", "content": prompt})
    body: dict[str, Any] = {
        "messages": ([{"role": "system", "content": system}] if system else []) + msgs,
        "max_tokens": 1024,
    }
    return body, "$.choices[0].message.content"


# ── Vertex AI / Gemini ───────────────────────────────────────────────


class VertexAuth:
    """Cached Google ADC token for Vertex generateContent."""

    def __init__(self, scopes: list[str] | None = None) -> None:
        self._scopes = scopes or ["https://www.googleapis.com/auth/cloud-platform"]
        self._token: str | None = None
        self._expires: float = 0.0
        self._creds: Any = None

    def access_token(self) -> str:
        try:
            import google.auth  # type: ignore[import-not-found]
            from google.auth.transport.requests import Request  # type: ignore[import-not-found]
        except ImportError as exc:
            raise _missing("vertex", "google-auth") from exc

        now = time.time()
        if self._token and now < self._expires - 60:
            return self._token
        if self._creds is None:
            self._creds, _project = google.auth.default(scopes=self._scopes)
        if not getattr(self._creds, "valid", False):
            self._creds.refresh(Request())
        self._token = str(self._creds.token)
        # google.auth doesn't always populate expiry; fall back to 50 min.
        expiry = getattr(self._creds, "expiry", None)
        if expiry is not None:
            self._expires = expiry.timestamp()
        else:
            self._expires = now + 50 * 60
        return self._token


def build_vertex_request(prompt: str, system: str | None, history: list[dict[str, str]] | None) -> tuple[dict[str, Any], str]:
    """Render an OpenAI-shape conversation as Vertex generateContent body."""
    contents: list[dict[str, Any]] = []
    for msg in history or []:
        role = "user" if msg.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": str(msg.get("content", ""))}]})
    contents.append({"role": "user", "parts": [{"text": prompt}]})
    body: dict[str, Any] = {
        "contents": contents,
        "generationConfig": {"maxOutputTokens": 1024},
    }
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    return body, "$.candidates[0].content.parts[0].text"


# ── Azure OpenAI ─────────────────────────────────────────────────────


class AzureOpenAIAuth:
    """Azure Entra access token cached until the JWT exp."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._expires: float = 0.0
        self._cred: Any = None

    def access_token(self) -> str:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
        except ImportError as exc:
            raise _missing("azure", "azure-identity") from exc

        now = time.time()
        if self._token and now < self._expires - 60:
            return self._token
        if self._cred is None:
            self._cred = DefaultAzureCredential()
        token = self._cred.get_token("https://cognitiveservices.azure.com/.default")
        self._token = str(token.token)
        self._expires = float(token.expires_on)
        return self._token


def build_azure_openai_request(model: str | None, prompt: str, system: str | None, history: list[dict[str, str]] | None) -> tuple[dict[str, Any], str]:
    """Render a standard OpenAI Chat body for Azure deployments."""
    msgs = ([{"role": "system", "content": system}] if system else []) + list(history or [])
    msgs.append({"role": "user", "content": prompt})
    body: dict[str, Any] = {"messages": msgs, "max_tokens": 1024}
    if model:
        body["model"] = model
    return body, "$.choices[0].message.content"
