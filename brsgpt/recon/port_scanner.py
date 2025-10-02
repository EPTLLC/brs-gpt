"""Async TCP port scanner with lightweight service probing.

The previous implementation returned synthetic data that implied open
services even when no evidence was collected.  This version performs real
TCP connect checks, optional protocol handshakes and captures minimal
metadata that can later be fed to the AI layer.  The focus is on
verifiable facts: if a service cannot be confirmed, the scanner reports it
with an "unknown" service label and a low confidence flag instead of
inventing banners.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


_DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
    445, 587, 5900, 8080, 8443, 8888, 9000, 9090, 9200,
    993, 995, 3306, 3389, 5432, 6379, 8000, 8001, 8081,
]

_HTTP_PORTS = {80, 8080, 8000, 8001, 8081}
_HTTPS_PORTS = {443, 8443}
_TLS_PORTS = _HTTPS_PORTS | {993, 995}
_SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    9000: "http",
    9200: "elasticsearch",
}


@dataclass
class ScannerSettings:
    """Runtime parameters controlling how the scanner behaves."""

    ports: List[int]
    connect_timeout: float
    read_timeout: float
    concurrent_limit: int

    @classmethod
    def from_dict(cls, settings: Dict[str, Any]) -> "ScannerSettings":
        return cls(
            ports=sorted(set(settings.get("ports") or _DEFAULT_PORTS)),
            connect_timeout=float(settings.get("port_scan_timeout", 3.0)),
            read_timeout=float(settings.get("port_read_timeout", 2.0)),
            concurrent_limit=int(settings.get("concurrent_requests", 32)),
        )


class PortScanner:
    """Perform TCP connect scans with optional protocol-aware probes."""

    def __init__(self, settings: Dict[str, Any]):
        self.config = ScannerSettings.from_dict(settings)

    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan a hostname or IP and return confirmed open ports."""
        ips = await self._resolve_all_ips(target)
        if not ips:
            return []

        results: List[Dict[str, Any]] = []
        for ip in ips:
            host_results = await self._scan_ip(target, ip)
            results.extend(host_results)
        return results

    async def _scan_ip(self, target: str, ip: str) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.config.concurrent_limit)

        async def _worker(port: int) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await self._probe_port(target, ip, port)

        tasks = [_worker(port) for port in self.config.ports]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        confirmed: List[Dict[str, Any]] = []
        for response in responses:
            if isinstance(response, dict):
                confirmed.append(response)
        return confirmed

    async def _probe_port(self, hostname: str, ip: str, port: int) -> Optional[Dict[str, Any]]:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.config.connect_timeout)
        except (asyncio.TimeoutError, OSError):
            return None

        metadata: Dict[str, Any] = {
            "host": hostname,
            "ip": ip,
            "port": port,
            "transport": "tcp",
            "protocol": "tcp",
            "state": "open",
            "service": None,
            "service_confidence": "unknown",
            "collected_at": datetime.utcnow().isoformat(),
            "data_source": "active_scan",
            "evidence": {"connect": True},
        }

        banner = None
        try:
            writer.write(b"\r\n")
            await writer.drain()
            banner_bytes = await asyncio.wait_for(reader.read(160), timeout=self.config.read_timeout)
            if banner_bytes:
                banner = banner_bytes.decode("utf-8", errors="ignore").strip()
                metadata["evidence"]["banner"] = banner
        except asyncio.TimeoutError:
            pass
        except OSError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Service hints based purely on port number are marked as inferred.
        if port in _SERVICE_HINTS:
            metadata["service"] = _SERVICE_HINTS[port]
            metadata["service_confidence"] = "inferred"

        # Optional protocol specific enrichment.
        enrichment = await self._enrich_port(hostname, ip, port)
        if "evidence" in enrichment:
            metadata["evidence"].update(enrichment["evidence"])
            enrichment = {k: v for k, v in enrichment.items() if k != "evidence"}
        metadata.update(enrichment)

        # If enrichment confirmed the service, bump confidence.
        if metadata.get("service") and enrichment.get("service_confidence") == "confirmed":
            metadata["service_confidence"] = "confirmed"

        metadata["security_notes"] = self._security_notes(metadata)
        return metadata

    async def _enrich_port(self, hostname: str, ip: str, port: int) -> Dict[str, Any]:
        if port in _HTTP_PORTS:
            return await self._probe_http(hostname, ip, port, use_ssl=False)
        if port in _HTTPS_PORTS:
            return await self._probe_http(hostname, ip, port, use_ssl=True)
        if port in _TLS_PORTS:
            return await self._probe_tls(hostname, ip, port)
        if port == 22:
            return await self._probe_ssh(ip, port)
        return {}

    async def _probe_http(self, hostname: str, ip: str, port: int, *, use_ssl: bool) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "http": {
                "scheme": "https" if use_ssl else "http",
                "status": None,
                "headers": {},
                "redirect_chain": [],
            }
        }

        host_header = hostname if not self._looks_like_ip(hostname) else ip
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: BRS-GPT Scanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        )

        ssl_ctx: Optional[ssl.SSLContext] = None
        server_hostname: Optional[str] = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            server_hostname = host_header

        reader = writer = None
        ssl_obj = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=server_hostname),
                timeout=self.config.connect_timeout,
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(4096), timeout=self.config.read_timeout)
            if use_ssl and writer:
                ssl_obj = writer.get_extra_info("ssl_object")
        except Exception:
            return result
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        try:
            text = raw.decode("iso-8859-1", errors="ignore")
        except Exception:
            text = ""

        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if lines:
            result["http"]["status"] = lines[0]
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        result["http"]["headers"] = headers

        if "location" in headers:
            result["http"]["redirect_chain"].append(headers["location"])

        if ssl_obj:
            cert = ssl_obj.getpeercert()
            result["tls"] = {
                "protocol": ssl_obj.version(),
                "cipher": ssl_obj.cipher(),
                "alpn": ssl_obj.selected_alpn_protocol(),
                "peercert": cert,
            }

        result["service"] = "https" if use_ssl else "http"
        result["service_confidence"] = "confirmed"
        return result

    async def _probe_tls(self, hostname: str, ip: str, port: int) -> Dict[str, Any]:
        ssl_ctx = ssl.create_default_context()

        def _do_handshake() -> Dict[str, Any]:
            sock = None
            try:
                sock = socket.create_connection((ip, port), timeout=self.config.connect_timeout)
                tls_socket = ssl_ctx.wrap_socket(
                    sock,
                    server_hostname=None if self._looks_like_ip(hostname) else hostname,
                )
                info = {
                    "tls": {
                        "protocol": tls_socket.version(),
                        "cipher": tls_socket.cipher(),
                        "peercert": tls_socket.getpeercert(),
                    }
                }
                hint = _SERVICE_HINTS.get(port)
                if hint:
                    info["service"] = hint
                    info["service_confidence"] = "confirmed"
                tls_socket.close()
                return info
            except Exception:
                if sock:
                    sock.close()
                return {}

        return await asyncio.to_thread(_do_handshake)

    async def _probe_ssh(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.config.connect_timeout,
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=self.config.read_timeout)
            writer.close()
            await writer.wait_closed()
            if banner:
                decoded = banner.decode("utf-8", errors="ignore").strip()
                return {
                    "service": "ssh",
                    "service_confidence": "confirmed",
                    "ssh": {"banner": decoded},
                    "evidence": {"banner": decoded},
                }
        except Exception:
            pass
        return {}

    def _security_notes(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        port = metadata["port"]
        notes: Dict[str, Any] = {
            "risk_level": "low",
            "issues": [],
            "confidence": metadata.get("service_confidence", "unknown"),
        }

        if metadata.get("service_confidence") != "confirmed":
            notes["confidence"] = metadata.get("service_confidence", "unknown")

        high_risk_ports = {21, 22, 23, 25, 3389, 445, 6379}
        if port in high_risk_ports:
            notes["risk_level"] = "high"
        elif port in {80, 8080} and metadata.get("http", {}).get("redirect_chain") == []:
            notes["risk_level"] = "medium"

        return notes

    async def _resolve_all_ips(self, target: str) -> List[str]:
        if self._looks_like_ip(target):
            return [target]
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                target, None, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            return []
        ips = {info[4][0] for info in infos}
        return sorted(ips)

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            socket.inet_aton(value)
            return True
        except OSError:
            return False
