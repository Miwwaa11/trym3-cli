"""Core logic for netcat-recon: TCP connect scanning & banner grabbing."""

from __future__ import annotations

import socket
from dataclasses import dataclass

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1025, 1111, 1433, 1521, 1723, 2049, 2121, 3000, 3128, 3306, 3389, 4444,
    5000, 5432, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 10000, 1337, 31337,
]

SERVICE_GUESS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 1433: "MSSQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9200: "Elasticsearch", 30303: "Ethereum",
}

BANNER_PORTS = {21, 22, 25, 80, 110, 143, 443, 3306, 6379, 5432, 5900, 8080}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str
    banner: str | None


def scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Attempt a TCP connect to a single port. Returns open/banner info."""
    service = SERVICE_GUESS.get(port, "unknown")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = None
            if port in BANNER_PORTS:
                banner = _grab_banner(host, port, timeout)
            return PortResult(port=port, open=True, service=service,
                              banner=banner)
    except (OSError, socket.timeout):
        return PortResult(port=port, open=False, service=service, banner=None)


def scan_ports(host: str, ports: list[int], timeout: float = 1.0,
               concurrency: int = 64) -> list[PortResult]:
    """Scan many ports with bounded concurrency (thread pool)."""
    if concurrency <= 1 or len(ports) <= 1:
        return [scan_port(host, p, timeout) for p in ports]
    from concurrent.futures import ThreadPoolExecutor
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(scan_port, host, p, timeout) for p in ports]
        for f in futures:
            results.append(f.result())
    return results


def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    """Send a light probe and read a banner line."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 443, 8443):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass
            try:
                data = s.recv(256)
            except socket.timeout:
                return None
            if data:
                text = data.decode("utf-8", errors="replace").strip()
                return text[:120]
    except OSError:
        return None
    return None
