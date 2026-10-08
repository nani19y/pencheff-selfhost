"""OIDC access-token validation for Keycloak-compatible identity providers."""
from __future__ import annotations

import asyncio
from functools import lru_cache
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, Request, status
from jwt import PyJWKClient

from ..config import get_settings


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


async def _discover_jwks_url(issuer: str) -> str:
    settings = get_settings()
    configured = settings.oidc_jwks_url.strip()
    if configured:
        return configured
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
        response.raise_for_status()
        data = response.json()
    jwks_url = data.get("jwks_uri")
    if not jwks_url:
        raise RuntimeError("OIDC discovery response did not contain jwks_uri")
    return str(jwks_url)


async def validate_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    issuer = settings.oidc_issuer.rstrip("/")
    if not issuer:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "OIDC authentication is not configured.",
        )

    try:
        jwks_url = await _discover_jwks_url(issuer)
        client = _jwks_client(jwks_url)
        signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, token)

        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": bool(settings.oidc_audience),
        }
        kwargs: dict[str, Any] = {"issuer": issuer, "options": options}
        if settings.oidc_audience:
            kwargs["audience"] = settings.oidc_audience

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            **kwargs,
        )
    except (jwt.PyJWTError, httpx.HTTPError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired OIDC access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if not claims.get("sub"):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "OIDC token has no subject.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return claims


async def authenticate_request(request: Request) -> dict[str, Any]:
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Bearer access token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = await validate_access_token(token.strip())
    request.state.oidc_claims = claims
    return claims
