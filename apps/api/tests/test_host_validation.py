# apps/api/tests/test_host_validation.py
"""Unit tests for pencheff_api.services.host_validation.

Covers private-IP classification, DNS resolution success/failure, format
validation, and the orchestrator that classify_host_list exposes to the
routers layer. See spec §"Validation rules" for the design intent.
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from pencheff_api.services.host_validation import (
    HostClassification,
    HostEntry,
    HostResolutionError,
    HostValidationError,
    classify_host_list,
    is_private_host,
    resolve_host,
    validate_host_format,
)


# ── is_private_host ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "addr",
    [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
    ],
)
def test_is_private_host_true_for_private_ranges(addr: str) -> None:
    assert is_private_host(addr) is True


@pytest.mark.parametrize(
    "addr",
    [
        "1.1.1.1",
        "8.8.8.8",
        "203.0.113.1",
        "2606:4700:4700::1111",
    ],
)
def test_is_private_host_false_for_public_addrs(addr: str) -> None:
    assert is_private_host(addr) is False


# ── resolve_host ────────────────────────────────────────────────────────────


def test_resolve_host_returns_first_ip_for_known_fqdn() -> None:
    with patch.object(
        socket,
        "getaddrinfo",
        return_value=[(socket.AF_INET, 0, 0, "", ("203.0.113.10", 0))],
    ):
        assert resolve_host("box.example.com") == "203.0.113.10"


def test_resolve_host_raises_on_failure() -> None:
    with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(HostResolutionError):
            resolve_host("nonexistent.invalid")


def test_resolve_host_returns_ip_unchanged_when_already_an_ip() -> None:
    assert resolve_host("1.2.3.4") == "1.2.3.4"


# ── validate_host_format ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "box.example.com",
        "a.b.c.example.org",
        "1.2.3.4",
        "::1",
        "2606:4700:4700::1111",
        "example.com",
    ],
)
def test_validate_host_format_accepts_valid(host: str) -> None:
    validate_host_format(host)


@pytest.mark.parametrize(
    "host",
    [
        "",
        " ",
        "https://example.com",
        "example.com:443",
        "with space.example",
        "ctrl\x01char.example",
        ".leadingdot.example",
        "trailingdot.example.",
    ],
)
def test_validate_host_format_rejects(host: str) -> None:
    with pytest.raises(HostValidationError):
        validate_host_format(host)


# ── classify_host_list ──────────────────────────────────────────────────────


def test_classify_host_list_dedups_case_insensitive() -> None:
    with patch(
        "pencheff_api.services.host_validation.resolve_host",
        side_effect=lambda h: "203.0.113.10",
    ):
        result = classify_host_list(["Box.Example.com", "box.example.COM"])
    assert len(result.entries) == 1
    assert result.entries[0].input == "Box.Example.com"


def test_classify_host_list_flags_any_private() -> None:
    def fake_resolve(host: str) -> str:
        return {"public.example.com": "1.2.3.4", "internal.example.com": "10.0.0.5"}[host]

    with patch(
        "pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve
    ):
        result = classify_host_list(["public.example.com", "internal.example.com"])
    assert result.any_private is True
    assert [e.is_private for e in result.entries] == [False, True]


def test_classify_host_list_collects_per_host_errors() -> None:
    def fake_resolve(host: str) -> str:
        if host == "valid.example.com":
            return "1.2.3.4"
        raise HostResolutionError(host, "dns failed")

    with patch(
        "pencheff_api.services.host_validation.resolve_host", side_effect=fake_resolve
    ):
        result = classify_host_list(["valid.example.com", "bad.invalid"])
    assert result.entries[0].error is None
    assert result.entries[1].error is not None
    assert result.has_errors is True


def test_classify_host_list_collects_format_errors_before_resolution() -> None:
    result = classify_host_list(["https://nope.example", "1.2.3.4"])
    assert result.entries[0].error is not None
    assert result.entries[0].resolved_ip is None
