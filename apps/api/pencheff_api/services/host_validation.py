# apps/api/pencheff_api/services/host_validation.py
"""Host-list validation, DNS resolution, and private-IP classification.

Pure helpers — no DB, no FastAPI. Consumed by routers/targets.py to gate
host-kind Target create/PATCH per the per-Org allow_private_targets policy.
See specs/2026-05-17-host-target-kind-design.md §"Validation rules".
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field


__all__ = [
    "HostClassification",
    "HostEntry",
    "HostResolutionError",
    "HostValidationError",
    "classify_host_list",
    "is_private_host",
    "resolve_host",
    "validate_host_format",
]


class HostValidationError(ValueError):
    """Raised when a host string fails format validation."""


class HostResolutionError(RuntimeError):
    """Raised when a hostname cannot be resolved to an IP address."""

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"could not resolve {host!r}: {reason}")
        self.host = host
        self.reason = reason


_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# RFC 5737 / RFC 3849 documentation-only ranges — not reachable anywhere.
# Python 3.11+ ipaddress.is_private includes these; we exclude them because
# "private" here means "reachable only on an internal network", not "reserved".
_DOCUMENTATION_NETWORKS_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
)
_DOCUMENTATION_NETWORK_V6 = ipaddress.ip_network("2001:db8::/32")

_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def is_private_host(addr: str) -> bool:
    """Return True if ``addr`` is a private-space IPv4 or IPv6 address.

    Covers Python's ipaddress notions of private/loopback/link-local plus an
    explicit CGNAT (100.64.0.0/10) check that the stdlib does not flag.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError as exc:
        raise HostValidationError(f"{addr!r} is not a valid IP address") from exc

    # Exclude documentation-only ranges (RFC 5737/3849) — Python 3.11+ marks
    # these as is_private, but they are not "reachable on an internal network".
    if isinstance(ip, ipaddress.IPv4Address):
        if any(ip in net for net in _DOCUMENTATION_NETWORKS_V4):
            return False
    elif ip in _DOCUMENTATION_NETWORK_V6:
        return False

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_NETWORK:
        return True
    return False


def resolve_host(host: str) -> str:
    """Resolve ``host`` to the first IP returned by getaddrinfo.

    If ``host`` already parses as an IP address, returns it unchanged.
    Raises HostResolutionError when DNS lookup fails.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise HostResolutionError(host, str(exc)) from exc

    if not infos:
        raise HostResolutionError(host, "no addresses returned")

    return infos[0][4][0]


def validate_host_format(host: str) -> None:
    """Raise HostValidationError if ``host`` is not a valid FQDN or IP literal."""
    if not host or host.strip() != host:
        raise HostValidationError("host must be non-empty with no surrounding whitespace")
    if _CONTROL_RE.search(host):
        raise HostValidationError("host contains a control character")
    if "://" in host:
        raise HostValidationError("host must not include a URL scheme (drop e.g. 'https://')")
    if ":" in host and not host.startswith("["):
        try:
            ipaddress.ip_address(host)
            return
        except ValueError:
            raise HostValidationError("host must not include a port number")
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if not _FQDN_RE.match(host):
        raise HostValidationError(f"{host!r} is not a syntactically valid FQDN")


@dataclass(slots=True)
class HostEntry:
    """One row in the classification result."""

    input: str
    resolved_ip: str | None = None
    is_private: bool = False
    error: str | None = None


@dataclass(slots=True)
class HostClassification:
    """Per-list result that the targets router consumes."""

    entries: list[HostEntry] = field(default_factory=list)

    @property
    def any_private(self) -> bool:
        return any(e.is_private for e in self.entries)

    @property
    def has_errors(self) -> bool:
        return any(e.error is not None for e in self.entries)

    @property
    def private_hosts(self) -> list[str]:
        return [e.input for e in self.entries if e.is_private]

    @property
    def error_hosts(self) -> list[tuple[str, str]]:
        return [(e.input, e.error) for e in self.entries if e.error]


def classify_host_list(raw_hosts: list[str]) -> HostClassification:
    """Validate, dedup, resolve, and classify a list of host strings.

    Returns a HostClassification with one HostEntry per (deduped) input,
    populated with resolution + classification or per-host errors. Caller is
    responsible for emitting an HTTP error from ``has_errors``.
    """
    result = HostClassification()
    seen: set[str] = set()
    for raw in raw_hosts:
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)

        entry = HostEntry(input=raw)
        try:
            validate_host_format(raw)
        except HostValidationError as exc:
            entry.error = str(exc)
            result.entries.append(entry)
            continue

        try:
            ip = resolve_host(raw)
            entry.resolved_ip = ip
            entry.is_private = is_private_host(ip)
        except (HostResolutionError, HostValidationError) as exc:
            entry.error = str(exc)

        result.entries.append(entry)

    return result
