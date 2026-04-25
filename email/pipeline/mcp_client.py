"""
pipeline/mcp_client.py — MCP stdio JSON-RPC client for the VirusTotal MCP server.

Architecture:
  • Spawns the VT MCP server as a persistent child process on first use
  • Communicates via JSON-RPC 2.0 over stdin/stdout (MCP stdio transport)
  • One subprocess for the entire app lifetime — NOT spawned per email
  • Performs the MCP initialize → initialized handshake on startup
  • Auto-incrementing request IDs to correlate responses
  • 10-second timeout per call; returns {"error": "timeout"} rather than raising

Usage:
    from pipeline.mcp_client import call_mcp_tool
    result = await call_mcp_tool("scan_url", {"url": "https://evil.com"})
"""

import asyncio
import json
import logging
import os

from config import VIRUSTOTAL_API_KEY, VT_MCP_SERVER_COMMAND, VT_MCP_SERVER_ARGS

logger = logging.getLogger(__name__)

# ── Module-level state (TCP connection) ───────────────────────────────────────
_reader: asyncio.StreamReader | None = None
_writer: asyncio.StreamWriter | None = None
_request_id: int = 0
_initialized: bool = False
_init_lock = asyncio.Lock()
_call_lock = asyncio.Lock()

MCP_TIMEOUT = 10  # seconds per tool call


def _next_id() -> int:
    global _request_id
    _request_id += 1
    return _request_id


async def _send(payload: dict) -> None:
    """Write a JSON-RPC message to the TCP socket (newline-delimited)."""
    line = json.dumps(payload) + "\n"
    _writer.write(line.encode())
    await _writer.drain()


async def _recv() -> dict:
    """Read one newline-delimited JSON-RPC message from the TCP socket."""
    while True:
        line = await _reader.readline()
        if not line:
            raise ConnectionError("MCP server TCP connection closed unexpectedly")
        line = line.strip()
        if not line:
            continue  # skip blank lines / progress output
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # MCP servers sometimes emit progress text on stdout; skip non-JSON
            logger.debug("[MCP] Non-JSON line skipped: %s", line[:120])
            continue


async def _recv_with_id(expected_id: int) -> dict:
    """
    Read responses until we get the one matching expected_id.
    Notifications (no 'id' field) are logged and skipped.
    """
    while True:
        msg = await _recv()
        msg_id = msg.get("id")
        if msg_id == expected_id:
            return msg
        # Log skipped notifications or mismatched responses
        logger.debug("[MCP] Skipping message id=%s (expected %s)", msg_id, expected_id)


async def _start_server() -> None:
    """
    Connect to the VT MCP server running over TCP and perform the MCP handshake.
    Called automatically on the first call to call_mcp_tool().
    """
    global _reader, _writer, _initialized

    if not VIRUSTOTAL_API_KEY:
        raise ValueError(
            "VIRUSTOTAL_API_KEY is not set in .env. "
            "Get a free key at https://www.virustotal.com/gui/join-us"
        )

    logger.info("[MCP] Connecting to VT MCP server over TCP at 127.0.0.1:8081...")

    try:
        _reader, _writer = await asyncio.open_connection("127.0.0.1", 8081)
    except ConnectionRefusedError:
        raise RuntimeError("Could not connect to MCP server. Make sure you are running 'python start_mcp_tcp.py' in a separate terminal!")

    # ── MCP handshake ─────────────────────────────────────────────────────────
    init_id = _next_id()
    await _send({
        "jsonrpc": "2.0",
        "id": init_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "PhishGuard", "version": "2.0.0"},
        },
    })

    try:
        response = await asyncio.wait_for(_recv_with_id(init_id), timeout=30)
    except asyncio.TimeoutError:
        raise RuntimeError("MCP server did not respond to initialize within 30 seconds")

    if "error" in response:
        raise RuntimeError(f"MCP initialize failed: {response['error']}")

    # Send the initialized notification (no response expected)
    await _send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    _initialized = True
    logger.info("[MCP] VirusTotal MCP server initialized successfully")


async def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    """
    Call a VirusTotal MCP tool and return the parsed result dict.

    Args:
        tool_name:  Name of the MCP tool (e.g. "scan_url", "get_domain_report").
        arguments:  Dict of tool arguments.

    Returns:
        Parsed result dict from the MCP tool response.
        On timeout or error, returns {"error": "<reason>"} — never raises.
    """
    global _reader, _writer, _initialized

    # ── Lazy init — connect on first call ─────────────────────────────────────
    async with _init_lock:
        if not _initialized or _reader is None or _writer.is_closing():
            try:
                await _start_server()
            except Exception as exc:
                logger.error("[MCP] Failed to start VT MCP server: %s", exc)
                return {"error": str(exc)}

    req_id = _next_id()
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }

    try:
        async with _call_lock:
            await _send(payload)
            response = await asyncio.wait_for(_recv_with_id(req_id), timeout=MCP_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("[MCP] Tool %s timed out after %ds", tool_name, MCP_TIMEOUT)
        return {"error": "timeout"}
    except Exception as exc:
        logger.error("[MCP] Tool %s failed: %s", tool_name, exc)
        return {"error": str(exc)}

    if "error" in response:
        logger.warning("[MCP] Tool %s returned error: %s", tool_name, response["error"])
        return {"error": str(response["error"])}

    # ── Extract text content from MCP result ──────────────────────────────────
    result = response.get("result", {})
    content = result.get("content", [])
    for item in content:
        if item.get("type") == "text":
            try:
                return json.loads(item["text"])
            except json.JSONDecodeError:
                # Return raw text wrapped in a dict
                return {"raw": item["text"]}

    return result
