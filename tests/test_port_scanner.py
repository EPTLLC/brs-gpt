import asyncio

import pytest

from brsgpt.recon.port_scanner import PortScanner


@pytest.mark.asyncio
async def test_port_scanner_detects_open_port():
    async def handle(reader, writer):
        # Respond with a short banner then close.
        writer.write(b"Test Service\r\n")
        await writer.drain()
        writer.close()

    try:
        server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
    except PermissionError:
        pytest.skip("Socket operations are not permitted in this environment")

    sockets = server.sockets or []
    if not sockets:
        server.close()
        await server.wait_closed()
        pytest.skip("Server sockets not available in this environment")

    sockname = sockets[0].getsockname()
    if isinstance(sockname, (tuple, list)):
        port = next((item for item in sockname if isinstance(item, int)), None)
    else:
        port = None
    if not isinstance(port, int):
        server.close()
        await server.wait_closed()
        pytest.skip("Could not determine ephemeral port for test server")
    try:
        scanner = PortScanner({
            "ports": [port],
            "port_scan_timeout": 1,
            "port_read_timeout": 1,
            "concurrent_requests": 2,
        })
        results = await scanner.scan("127.0.0.1")
        assert len(results) == 1
        entry = results[0]
        assert entry["port"] == port
        assert entry["state"] == "open"
        assert entry["evidence"].get("connect") is True
        assert entry["service_confidence"] in {"unknown", "inferred", "confirmed"}
        assert entry["data_source"] == "active_scan"
    finally:
        server.close()
        await server.wait_closed()
