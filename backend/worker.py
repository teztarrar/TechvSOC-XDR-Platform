#!/usr/bin/env python3
"""TechvSOC XDR Platform - Redis Stream Worker.

Processes logs from Redis Streams, enriches with threat intel,
stores to PostgreSQL, and triggers detections.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import UTC
from datetime import datetime

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.enums import LogLevel
from app.models.log_entry import LogEntry
from app.services.detection_service import run_detection_cycle
from app.services.log_parser import _coerce_severity
from app.services.queue_service import ack_message
from app.services.queue_service import ensure_consumer_group
from app.services.queue_service import read_from_queue
from app.services.threat_intel_service import batch_enrich_ips

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("techvsoc.worker")


def _parse_log_payload(payload: dict) -> LogEntry:
    data = json.loads(payload.get("payload", "{}"))
    event_timestamp_str = data.get("event_timestamp")
    event_timestamp = datetime.fromisoformat(event_timestamp_str.replace("Z", "+00:00")) if event_timestamp_str else datetime.now(UTC)

    return LogEntry(
        source=data.get("source", "unknown"),
        event_type=data.get("event_type", "unknown"),
        message=data.get("message", ""),
        raw_log=data.get("raw_log", ""),
        severity=_coerce_severity(data.get("severity", "info")),
        event_timestamp=event_timestamp,
        endpoint_id=data.get("endpoint_id"),
        metadata_json=data.get("metadata_json"),
    )


def process_batch(db, entries: list[tuple[str, dict]]) -> int:
    if not entries:
        return 0

    logs = []
    message_ids = []
    ip_addresses = []

    for message_id, fields in entries:
        try:
            log = _parse_log_payload(fields)
            logs.append(log)
            message_ids.append(message_id)
            if log.metadata_json:
                ip = log.metadata_json.get("ip_address") or log.metadata_json.get("source_ip")
                if ip:
                    ip_addresses.append(ip)
        except Exception as exc:
            logger.warning("Failed to parse log entry %s: %s", message_id, exc)
            ack_message(message_id)

    if not logs:
        return 0

    db.add_all(logs)
    db.commit()

    # Enrich IPs with threat intel
    if ip_addresses:
        try:
            batch_enrich_ips(db, ip_addresses)
            logger.info("Enriched %s unique IPs with threat intel", len(set(ip_addresses)))
        except Exception as exc:
            logger.warning("Threat intel enrichment failed: %s", exc)

    # Acknowledge all processed messages
    for message_id in message_ids:
        try:
            ack_message(message_id)
        except Exception as exc:
            logger.warning("Failed to ack message %s: %s", message_id, exc)

    logger.info("Processed and stored %s logs from queue", len(logs))
    return len(logs)


def main() -> None:
    logger.info("TechvSOC Worker starting...")
    logger.info("Redis URL: %s", settings.redis_url)

    try:
        ensure_consumer_group()
    except Exception as exc:
        logger.error("Failed to ensure consumer group: %s", exc)
        sys.exit(1)

    consecutive_empty = 0

    while True:
        db = SessionLocal()
        try:
            entries = read_from_queue(count=100, block_ms=5000)
            if entries:
                process_batch(db, entries)
                consecutive_empty = 0
            else:
                consecutive_empty += 1
                # Run detections every ~30 seconds when idle
                if consecutive_empty >= 6:
                    try:
                        alerts, rules_evaluated, logs_scanned, window_start, window_end = run_detection_cycle(
                            db, hours=1
                        )
                        if alerts:
                            logger.info(
                                "Auto-detection cycle created %s alerts from %s logs",
                                len(alerts),
                                logs_scanned,
                            )
                    except Exception as exc:
                        logger.warning("Auto-detection cycle failed: %s", exc)
                    consecutive_empty = 0
        except Exception as exc:
            logger.exception("Worker loop error: %s", exc)
        finally:
            db.close()

        time.sleep(2)


if __name__ == "__main__":
    main()

