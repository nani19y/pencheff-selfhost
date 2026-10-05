"""FallbackResolver walks chains when binaries are missing."""

from __future__ import annotations

from pencheff.core.orchestrator.fallback import FallbackResolver


def test_returns_primary_when_available():
    resolver = FallbackResolver(is_available=lambda name: name == "nmap")
    assert resolver.resolve("nmap") == "nmap"


def test_walks_to_first_available_fallback():
    resolver = FallbackResolver(is_available=lambda name: name == "naabu")
    assert resolver.resolve("nmap") == "naabu"


def test_returns_none_when_nothing_available():
    resolver = FallbackResolver(is_available=lambda _name: False)
    assert resolver.resolve("nmap") is None


def test_chain_includes_primary_first():
    resolver = FallbackResolver(is_available=lambda _name: False)
    chain = resolver.chain("nmap")
    assert chain[0] == "nmap"
    assert "naabu" in chain or "rustscan" in chain or "masscan" in chain
