"""
syslog_tcp_service.py - Async TCP syslog receiver for TechvSOC XDR Platform.

Accepts RFC 5424 newline-framed messages from the Windows native agent.
Parses JSON payload from MSG field, pushes to Redis stream for processing.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.services.queue_service import push_log_to_queue

logger = logging.getLogger("techvsoc.syslog")

_SEVERITY_MAP = {
    "critical": "critical",
    "error":    "error",
    "warning":  "warning",
    "warn":     "warning",
    "info":     "info",
    "debug":    "debug",
}

_MAX_LINE_BYTES = 70000   # RFC 5424 header (~200) + JSON payload (~65536)
_MAX_CONNECTIONS = 256    # max simultaneous agent connections


def _parse_rfc5424_line(line: str) -> dict[str, Any] | None:
    """
    Parse one RFC 5424 line and return a log dict ready for push_log_to_queue.

    Format: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APPNAME SP PROCID SP MSGID SP SD SP MSG
    C agent always sends: <134>1 TS HOST TECHVSOC-AGENT PID - - {json}

    Returns None if line is malformed or MSG is not valid JSON.
    """
    line = line.strip()
    if not line:
        return None

    # Strip RFC 5424 priority+version prefix: "<NNN>1 "
    if not line.startswith("<"):
        return None
    try:
        pri_end = line.index(">")
    except ValueError:
        return None

    # Skip: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APPNAME SP PROCID SP MSGID SP SD SP
    # That is 7 space-delimited tokens before the MSG
    after_pri = line[pri_end + 1:]   # "1 TS HOST APPNAME PID MSGID SD {json}"
    parts = after_pri.split(" ", 7)  # split into max 8 parts
    if len(parts) < 8:
        return None

    # parts[0]=VERSION, parts[1]=TIMESTAMP, parts[2]=HOSTNAME,
    # parts[3]=APPNAME, parts[4]=PROCID, parts[5]=MSGID, parts[6]=SD, parts[7]=MSG
    timestamp_str = parts[1]
    hostname      = parts[2]
    msg           = parts[7]   # full JSON payload from C agent

    # Parse JSON payload
    try:
        payload = json.loads(msg)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Syslog MSG is not valid JSON (first 200 chars): %s", msg[:200])
        return None

    if not isinstance(payload, dict):
        return None

    # Normalise severity
    raw_sev = str(payload.get("severity", "info")).lower()
    severity = _SEVERITY_MAP.get(raw_sev, "info")

    # Normalise event_timestamp — prefer value from payload, fall back to syslog header
    event_ts = payload.get("event_timestamp") or timestamp_str
    # Ensure it's a valid ISO string; if not, use now
    try:
        datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        event_ts = datetime.now(UTC).isoformat()

    # Build log dict matching queue_service / worker expectations
    log_dict: dict[str, Any] = {
        "source":          payload.get("source") or hostname,
        "event_type":      payload.get("event_type") or "syslog",
        "message":         str(payload.get("message") or "")[:5000],
        "raw_log":         str(payload.get("raw_log") or msg)[:10000],
        "severity":        severity,
        "event_timestamp": event_ts,
        "endpoint_id":     payload.get("endpoint_id"),
        "metadata_json":   payload.get("metadata_json"),
    }

    return log_dict


async def _handle_client(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter,
                          semaphore: asyncio.Semaphore) -> None:
    """Handle one TCP connection from a Windows agent."""
    peer = writer.get_extra_info("peername", ("?", 0))
    logger.info("Syslog TCP connection from %s:%s", peer[0], peer[1])
    received = 0
    pushed = 0

    async with semaphore:
        try:
            while True:
                try:
                    # Read up to one syslog line (newline-terminated)
                    line_bytes = await asyncio.wait_for(
                        reader.readuntil(b"\n"),
                        timeout=300.0,   # 5-minute idle timeout
                    )
                except asyncio.IncompleteReadError:
                    break   # client disconnected
                except asyncio.TimeoutError:
                    logger.debug("Syslog client %s:%s idle timeout", peer[0], peer[1])
                    break
                except Exception as exc:
                    logger.warning("Syslog read error from %s: %s", peer[0], exc)
                    break

                if len(line_bytes) > _MAX_LINE_BYTES:
                    logger.warning("Syslog line too large (%d bytes) from %s — dropped",
                                   len(line_bytes), peer[0])
                    continue

                received += 1
                try:
                    line = line_bytes.decode("utf-8", errors="replace")
                except Exception:
                    continue

                log_dict = _parse_rfc5424_line(line)
                if log_dict is None:
                    continue

                try:
                    push_log_to_queue(log_dict)
                    pushed += 1
                except Exception as exc:
                    logger.warning("Failed to push syslog log to queue: %s", exc)

        finally:
            logger.info("Syslog client %s:%s disconnected — received=%d pushed=%d",
                        peer[0], peer[1], received, pushed)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def run_syslog_server(host: str, port: int) -> None:
    """
    Start the TCP syslog server. Runs until cancelled.
    Call from lifespan as an asyncio task.
    """
    semaphore = asyncio.Semaphore(_MAX_CONNECTIONS)

    async def client_cb(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        await _handle_client(reader, writer, semaphore)

    server = await asyncio.start_server(client_cb, host, port)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("Syslog TCP server listening on %s", addrs)

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        logger.info("Syslog TCP server shutting down")
        raise
