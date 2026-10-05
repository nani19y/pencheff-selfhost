"""Small TCP connect scanner for authorized asset discovery.

This is intentionally conservative: it uses normal TCP connections, avoids raw
packets, avoids evasion features, and keeps concurrency bounded.
"""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement, tostring

from pencheff.config import TOP_1000_PORTS


KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 445: "SMB", 500: "IKE", 5353: "mDNS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Management", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB",
}


DEFAULT_PORTS = "top-100"
DEFAULT_TIMEOUT = 1.5
DEFAULT_CONCURRENCY = 100
MAX_CIDR_HOSTS = 4096
MAX_PORTS = 65535
HTTP_PORTS = {80, 3000, 5000, 5173, 8000, 8008, 8080, 8765, 8888}
HTTPS_PORTS = {443, 4443, 8443, 9443}
TOP_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353, 11211]
TIMING_PROFILES = {
    0: {"timeout": 5.0, "concurrency": 5, "delay": 1.0},
    1: {"timeout": 4.0, "concurrency": 10, "delay": 0.5},
    2: {"timeout": 3.0, "concurrency": 25, "delay": 0.1},
    3: {"timeout": 1.5, "concurrency": 100, "delay": 0.0},
    4: {"timeout": 1.0, "concurrency": 250, "delay": 0.0},
    5: {"timeout": 0.5, "concurrency": 500, "delay": 0.0},
}
SERVICE_PROBES: dict[str, bytes] = {
    "HTTP": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "HTTP-Proxy": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "HTTP-Alt": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "Management": b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "Redis": b"PING\r\n",
    "Elasticsearch": b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "SMTP": b"EHLO pencheff.local\r\n",
    "FTP": b"",
    "SSH": b"",
    "MySQL": b"",
    "PostgreSQL": b"",
    "MongoDB": b"",
}
UDP_PROBES: dict[int, bytes] = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    123: b"\x1b" + b"\0" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x65\x6e\x63\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    11211: b"stats\r\n",
}
TOP_TCP_PORTS_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


@dataclass(slots=True)
class PortResult:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    banner: str = ""
    latency_ms: float | None = None
    error: str | None = None
    version: str | None = None
    scripts: dict[str, str] | None = None


@dataclass(slots=True)
class ScanResult:
    targets: list[str]
    ports: list[int]
    open: list[PortResult]
    scanned_count: int
    elapsed_sec: float
    scan_mode: str = "connect"
    udp_ports: list[int] | None = None
    os_guess: dict[str, str] | None = None
    traceroute: dict[str, list[str]] | None = None


def parse_targets(values: Iterable[str]) -> list[str]:
    """Parse hostnames, URLs, IPs, CIDRs, and comma-separated target lists."""
    targets: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        host = host.strip()
        if not host:
            return
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or ""
        if host and host not in seen:
            targets.append(host)
            seen.add(host)

    for value in values:
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                add(raw)
                continue

            hosts = list(net.hosts())
            if net.version == 4 and net.prefixlen == 32:
                hosts = [net.network_address]
            if net.version == 6 and net.prefixlen == 128:
                hosts = [net.network_address]
            if len(hosts) > MAX_CIDR_HOSTS:
                raise ValueError(
                    f"CIDR {raw} expands to {len(hosts)} hosts; limit is {MAX_CIDR_HOSTS}."
                )
            for ip in hosts:
                add(str(ip))

    if not targets:
        raise ValueError("at least one target is required")
    return targets


def parse_ports(value: str) -> list[int]:
    """Parse top-100/top-1000, comma lists, and ranges like 1-1024."""
    value = (value or DEFAULT_PORTS).strip().lower()
    if value == "top-100":
        return TOP_TCP_PORTS_100.copy()
    if value == "top-1000":
        return sorted(set(TOP_1000_PORTS))
    if value in {"all", "full"}:
        return list(range(1, 65536))

    ports: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))

    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"invalid port number(s): {', '.join(map(str, sorted(invalid)[:5]))}")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"too many ports requested: {len(ports)}")
    return sorted(ports)


def parse_udp_ports(value: str | None) -> list[int]:
    if not value or value == "top":
        return TOP_UDP_PORTS.copy()
    return parse_ports(value)


def apply_timing_profile(timing: int, timeout: float, concurrency: int) -> tuple[float, int, float]:
    profile = TIMING_PROFILES.get(timing)
    if not profile:
        raise ValueError("timing must be between 0 and 5")
    effective_timeout = timeout if timeout != DEFAULT_TIMEOUT else profile["timeout"]
    effective_concurrency = concurrency if concurrency != DEFAULT_CONCURRENCY else profile["concurrency"]
    return effective_timeout, effective_concurrency, profile["delay"]


async def scan_targets(
    targets: list[str],
    ports: list[int],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    banners: bool = True,
    version_detection: bool = False,
    script_scan: bool = False,
    os_detection: bool = False,
    traceroute: bool = False,
    scan_mode: str = "connect",
    udp_ports: list[int] | None = None,
    delay: float = 0.0,
) -> ScanResult:
    start = time.monotonic()
    sem = asyncio.Semaphore(max(1, concurrency))
    open_ports: list[PortResult] = []

    async def scan_one(host: str, port: int) -> None:
        async with sem:
            if delay:
                await asyncio.sleep(delay)
            result = await _scan_port(
                host,
                port,
                timeout=timeout,
                banners=banners or version_detection or script_scan or os_detection,
                version_detection=version_detection,
                script_scan=script_scan,
            )
            if result.state == "open":
                open_ports.append(result)

    await asyncio.gather(*(scan_one(host, port) for host in targets for port in ports))
    if udp_ports:
        await asyncio.gather(
            *(scan_udp_one(host, port, sem, timeout, open_ports, delay) for host in targets for port in udp_ports)
        )
    open_ports.sort(key=lambda r: (r.host, r.port))
    elapsed = time.monotonic() - start
    os_guess = _guess_os(open_ports) if os_detection else None
    hops = await _run_traceroutes(targets, timeout=timeout) if traceroute else None
    return ScanResult(
        targets=targets,
        ports=ports,
        open=open_ports,
        scanned_count=(len(targets) * len(ports)) + (len(targets) * len(udp_ports or [])),
        elapsed_sec=elapsed,
        scan_mode=scan_mode,
        udp_ports=udp_ports or None,
        os_guess=os_guess,
        traceroute=hops,
    )


async def _scan_port(
    host: str,
    port: int,
    *,
    timeout: float,
    banners: bool,
    version_detection: bool,
    script_scan: bool,
) -> PortResult:
    service = KNOWN_SERVICES.get(port, "unknown")
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror) as exc:
        return PortResult(
            host=host,
            port=port,
            protocol="tcp",
            state="closed",
            service=service,
            error=type(exc).__name__,
        )

    latency_ms = (time.monotonic() - started) * 1000
    banner = ""
    if banners:
        banner = await _grab_banner(reader, writer, host, port, timeout)

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    version = _extract_version(banner, service, port) if version_detection else None
    scripts = _run_safe_scripts(host, port, service, banner) if script_scan else None
    return PortResult(
        host=host,
        port=port,
        protocol="tcp",
        state="open",
        service=service,
        banner=banner,
        latency_ms=round(latency_ms, 1),
        version=version,
        scripts=scripts or None,
    )


async def scan_udp_one(
    host: str,
    port: int,
    sem: asyncio.Semaphore,
    timeout: float,
    results: list[PortResult],
    delay: float,
) -> None:
    async with sem:
        if delay:
            await asyncio.sleep(delay)
        started = time.monotonic()
        try:
            response = await asyncio.to_thread(_udp_probe, host, port, timeout)
        except Exception as exc:
            if isinstance(exc, ConnectionRefusedError):
                return
            response = None
        if response is None:
            return
        banner = _clean_banner(response) if response else ""
        results.append(PortResult(
            host=host,
            port=port,
            protocol="udp",
            state="open",
            service=KNOWN_SERVICES.get(port, "unknown"),
            banner=banner,
            latency_ms=round((time.monotonic() - started) * 1000, 1),
            scripts={"udp-response": "received response"} if banner else {"udp-response": "port responded"},
        ))


def _udp_probe(host: str, port: int, timeout: float) -> bytes | None:
    payload = UDP_PROBES.get(port, b"\0")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            return data
        except socket.timeout:
            return None


async def _grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    timeout: float,
) -> str:
    """Best-effort banner grab without sending exploit payloads."""
    try:
        service = KNOWN_SERVICES.get(port, "unknown")
        probe = SERVICE_PROBES.get(service)
        if port in HTTP_PORTS:
            writer.write(SERVICE_PROBES["HTTP"].replace(b"{host}", host.encode()))
            await writer.drain()
        elif port in HTTPS_PORTS:
            return await asyncio.to_thread(_tls_head_banner, host, port, timeout)
        elif probe is not None:
            if probe:
                writer.write(probe.replace(b"{host}", host.encode()))
                await writer.drain()
        elif port in {110, 143}:
            pass
        else:
            writer.write(b"\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 2.0))
    except Exception:
        return ""
    return _clean_banner(data)


def _tls_head_banner(host: str, port: int, timeout: float) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.settimeout(timeout)
                ssock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                return _clean_banner(ssock.recv(512))
    except Exception:
        return ""


def _clean_banner(data: bytes) -> str:
    return " ".join(data.decode(errors="replace").replace("\x00", "").split())[:200]


def _extract_version(banner: str, service: str, port: int) -> str | None:
    if not banner:
        return None
    if service == "SSH":
        return banner.split()[0] if banner else None
    if service.startswith("HTTP"):
        server = re.search(r"\bServer:\s*([^\\r\\n]+?)(?:\s+(?:Date|Content-|Connection):|$)", banner)
        if server:
            return server.group(1).strip()
        status = re.match(r"HTTP/\S+\s+\d+\s+[^ ]+", banner)
        return status.group(0) if status else None
    return banner[:80]


def _run_safe_scripts(host: str, port: int, service: str, banner: str) -> dict[str, str]:
    from pencheff.modules.recon.scripts import run_safe_scripts

    return run_safe_scripts(host=host, port=port, service=service, banner=banner)


def _guess_os(rows: list[PortResult]) -> dict[str, str]:
    guesses: dict[str, str] = {}
    by_host: dict[str, list[str]] = {}
    for row in rows:
        by_host.setdefault(row.host, []).append(" ".join(filter(None, [row.banner, row.version or ""])))
    for host, banners in by_host.items():
        text = " ".join(banners).lower()
        if any(x in text for x in ("ubuntu", "debian", "linux", "openssh")):
            guesses[host] = "Linux/Unix-like (passive banner guess)"
        elif any(x in text for x in ("microsoft", "windows", "iis")):
            guesses[host] = "Windows (passive banner guess)"
        elif "freebsd" in text:
            guesses[host] = "FreeBSD (passive banner guess)"
        else:
            guesses[host] = "unknown"
    return guesses


async def _run_traceroutes(targets: list[str], *, timeout: float) -> dict[str, list[str]]:
    cmd = shutil.which("traceroute") or shutil.which("tracepath")
    if not cmd:
        return {target: ["traceroute unavailable on this system"] for target in targets}

    async def one(target: str) -> tuple[str, list[str]]:
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [cmd, target],
                capture_output=True,
                text=True,
                timeout=max(10.0, timeout * 8),
                check=False,
            )
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            return target, lines[:32]
        except Exception as exc:
            return target, [f"traceroute failed: {type(exc).__name__}"]

    pairs = await asyncio.gather(*(one(target) for target in targets))
    return dict(pairs)


def render_result(result: ScanResult, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(
            {
                "targets": result.targets,
                "ports": result.ports,
                "open": [asdict(r) for r in result.open],
                "scanned_count": result.scanned_count,
                "elapsed_sec": round(result.elapsed_sec, 3),
                "scan_mode": result.scan_mode,
                "udp_ports": result.udp_ports or [],
                "os_guess": result.os_guess or {},
                "traceroute": result.traceroute or {},
            },
            indent=2,
        )
    if fmt == "csv":
        return _render_csv(result.open)
    if fmt == "xml":
        return _render_xml(result)
    if fmt == "table":
        return _render_table(result)
    raise ValueError("format must be one of: table, json, csv, xml")


def _render_csv(rows: list[PortResult]) -> str:
    from io import StringIO

    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=["host", "port", "protocol", "state", "service", "latency_ms", "version", "banner"])
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "host": row.host,
            "port": row.port,
            "protocol": row.protocol,
            "state": row.state,
            "service": row.service,
            "latency_ms": row.latency_ms,
            "version": row.version or "",
            "banner": row.banner,
        })
    return out.getvalue().rstrip()


def _render_xml(result: ScanResult) -> str:
    root = Element("pencheff-map", {
        "scan_mode": result.scan_mode,
        "elapsed_sec": f"{result.elapsed_sec:.3f}",
        "scanned_count": str(result.scanned_count),
    })
    for host in result.targets:
        host_el = SubElement(root, "host", {"name": host})
        if result.os_guess and host in result.os_guess:
            SubElement(host_el, "os", {"guess": result.os_guess[host]})
        ports_el = SubElement(host_el, "ports")
        for row in [r for r in result.open if r.host == host]:
            port_el = SubElement(ports_el, "port", {
                "protocol": row.protocol,
                "portid": str(row.port),
                "state": row.state,
                "service": row.service,
            })
            if row.version:
                port_el.set("version", row.version)
            if row.banner:
                SubElement(port_el, "banner").text = row.banner
            for key, value in (row.scripts or {}).items():
                SubElement(port_el, "script", {"id": key, "output": value})
        if result.traceroute and host in result.traceroute:
            trace_el = SubElement(host_el, "trace")
            for hop in result.traceroute[host]:
                SubElement(trace_el, "hop", {"summary": hop})
    return tostring(root, encoding="unicode")


def _render_table(result: ScanResult) -> str:
    lines = [
        f"Scanned {result.scanned_count} host/port combinations in {result.elapsed_sec:.2f}s",
        "",
    ]
    if not result.open:
        lines.append("No open TCP ports found.")
        return "\n".join(lines)

    headers = ("HOST", "PORT", "PROTO", "STATE", "SERVICE", "LATENCY", "VERSION", "BANNER")
    rows = [
        (
            r.host,
            str(r.port),
            r.protocol,
            r.state,
            r.service,
            f"{r.latency_ms:.1f}ms" if r.latency_ms is not None else "",
            r.version or "",
            r.banner,
        )
        for r in result.open
    ]
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = min(max(widths[idx], len(cell)), 60)

    def fit(value: str, width: int) -> str:
        if len(value) > width:
            value = value[: max(0, width - 3)] + "..."
        return value.ljust(width)

    lines.append("  ".join(fit(h, widths[i]) for i, h in enumerate(headers)))
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(fit(cell, widths[i]) for i, cell in enumerate(row)))
    if result.os_guess:
        lines.append("")
        lines.append("OS guesses:")
        for host, guess in result.os_guess.items():
            lines.append(f"  {host}: {guess}")
    if result.traceroute:
        lines.append("")
        lines.append("Traceroute:")
        for host, hops in result.traceroute.items():
            lines.append(f"  {host}:")
            lines.extend(f"    {hop}" for hop in hops)
    return "\n".join(lines)


async def run_cli(args) -> int:
    try:
        targets = parse_targets(args.target)
        ports = parse_ports("all" if getattr(args, "all_ports", False) else args.ports)
        aggressive = getattr(args, "aggressive", False)
        stealth = getattr(args, "stealth_scan", False)
        timeout, concurrency, delay = apply_timing_profile(args.timing, args.timeout, args.concurrency)
        if stealth:
            concurrency = min(concurrency, 25)
        udp_ports = parse_udp_ports(args.udp_ports) if args.udp_scan else None
        result = await scan_targets(
            targets,
            ports,
            timeout=timeout,
            concurrency=concurrency,
            banners=not args.no_banners and not stealth,
            version_detection=args.version_detect or aggressive,
            script_scan=args.script_scan or args.vuln_scan or aggressive,
            os_detection=args.os_detect or aggressive,
            traceroute=args.traceroute or aggressive,
            scan_mode="low-noise-connect" if stealth else "connect",
            udp_ports=udp_ports,
            delay=delay,
        )
        print(render_result(result, args.format))
    except (OSError, ValueError) as exc:
        print(f"pencheff map: {exc}", file=sys.stderr)
        return 2
    return 0
