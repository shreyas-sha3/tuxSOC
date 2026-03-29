"""
layer2_es_orchestrator.py
--------------------------
Layer-2 Elasticsearch-native Detection Orchestrator.

Pipeline (per poll cycle):
  1. Poll Elasticsearch for new events
  2. Run 20 detection rules
  3. Run UEBA behavioral analysis
  4. Correlate detections (time-machine queries)
  5. Merge related detections into incident clusters
  6. Calculate risk scores
  7. Build structured incidents
  8. Dispatch incidents to Layer-3 AI (POST /analyze)

Runs as a continuous polling loop or can be invoked once for testing.
"""

import json
import logging
import time
import threading
from datetime import datetime, timezone

import urllib.request
import urllib.error

from layer_2_detection_es.config import (
    POLL_INTERVAL_SECONDS,
    POLL_LOOKBACK_MINUTES,
    LAYER3_ENDPOINT,
    LAYER3_TIMEOUT,
    LOG_LEVEL,
)
from layer_2_detection_es.elastic_client import get_client
from layer_2_detection_es.baseline_engine import compute_baselines, baselines_ready
from layer_2_detection_es.rules_engine import run_all_rules
from layer_2_detection_es.ueba_engine import run_ueba
from layer_2_detection_es.es_correlator import correlate_all
from layer_2_detection_es.incident_merger import merge_detections
from layer_2_detection_es.incident_builder import build_all_incidents

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("layer2_es_orchestrator")

_running = False
_lock    = threading.Lock()


# ── Layer-3 dispatch ───────────────────────────────────────────────────────

def _dispatch_to_layer3(incident: dict) -> bool:
    """
    POST incident to Layer-3 AI analysis endpoint.
    Returns True on success, False on failure.
    """
    try:
        payload = json.dumps(incident, default=str).encode("utf-8")
        req = urllib.request.Request(
            LAYER3_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=LAYER3_TIMEOUT) as resp:
            status = resp.getcode()
            logger.info(
                "Dispatched incident %s to Layer-3 — HTTP %d",
                incident.get("incident_id"), status
            )
            return status == 200
    except urllib.error.URLError as exc:
        logger.warning(
            "Layer-3 dispatch failed for %s: %s",
            incident.get("incident_id"), exc
        )
        return False
    except Exception as exc:
        logger.error("Unexpected dispatch error: %s", exc)
        return False


# ── Single detection cycle ─────────────────────────────────────────────────

def run_once(lookback_minutes: int = POLL_LOOKBACK_MINUTES) -> list[dict]:
    """
    Execute one full detection cycle.

    Returns the list of incidents generated.
    """
    cycle_start = datetime.now(timezone.utc)
    logger.info("=== Detection cycle started at %s ===", cycle_start.isoformat())

    # ── Step 1: Verify ES connectivity ────────────────────────────────
    es = get_client()
    if not es.ping():
        logger.warning("Elasticsearch unreachable — skipping cycle")
        return []

    # ── Step 2: Compute baselines (first run or stale) ─────────────────
    if not baselines_ready():
        logger.info("Computing behavioral baselines...")
        compute_baselines()

    # ── Step 3: Run detection rules ────────────────────────────────────
    logger.info("Running detection rules (lookback=%dm)...", lookback_minutes)
    detections = run_all_rules(lookback_minutes=lookback_minutes)
    logger.info("Rules engine: %d raw detection(s)", len(detections))

    if not detections:
        logger.info("No detections — cycle complete")
        return []

    # ── Step 4: Run UEBA ───────────────────────────────────────────────
    logger.info("Running UEBA analysis...")
    ueba_result = run_ueba(lookback_minutes=lookback_minutes)
    logger.info(
        "UEBA: %d flag(s), anomaly_score=%.3f, flagged=%s",
        len(ueba_result.get("ueba_flags", [])),
        ueba_result.get("anomaly_score", 0.0),
        ueba_result.get("anomaly_flagged", False),
    )

    # ── Step 5: Correlate detections ───────────────────────────────────
    logger.info("Correlating %d detection(s)...", len(detections))
    enriched = correlate_all(detections)

    # ── Step 6: Merge into incident clusters ───────────────────────────
    clusters = merge_detections(enriched)
    logger.info("Incident merger: %d cluster(s)", len(clusters))

    # ── Step 7: Build incidents ────────────────────────────────────────
    incidents = build_all_incidents(clusters, ueba_result)
    logger.info("Built %d incident(s)", len(incidents))

    # ── Step 8: Dispatch to Layer-3 ────────────────────────────────────
    dispatched = 0
    for incident in incidents:
        if _dispatch_to_layer3(incident):
            dispatched += 1

    cycle_end = datetime.now(timezone.utc)
    elapsed   = (cycle_end - cycle_start).total_seconds()

    logger.info(
        "=== Cycle complete: %d incident(s), %d dispatched, %.1fs elapsed ===",
        len(incidents), dispatched, elapsed
    )

    return incidents


# ── Continuous polling loop ────────────────────────────────────────────────

def start_polling(interval_seconds: int = POLL_INTERVAL_SECONDS):
    """
    Start the continuous polling loop in the current thread.
    Blocks indefinitely. Use start_polling_async() for background operation.
    """
    global _running
    with _lock:
        _running = True

    logger.info(
        "Layer-2 ES orchestrator starting — poll interval=%ds",
        interval_seconds
    )

    while _running:
        try:
            run_once()
        except Exception as exc:
            logger.error("Unhandled error in detection cycle: %s", exc)
        time.sleep(interval_seconds)


def start_polling_async(interval_seconds: int = POLL_INTERVAL_SECONDS) -> threading.Thread:
    """Start the polling loop in a background daemon thread."""
    t = threading.Thread(
        target=start_polling,
        args=(interval_seconds,),
        daemon=True,
        name="layer2-es-poller",
    )
    t.start()
    logger.info("Layer-2 ES orchestrator started in background thread")
    return t


def stop_polling():
    """Signal the polling loop to stop after the current cycle."""
    global _running
    with _lock:
        _running = False
    logger.info("Layer-2 ES orchestrator stop requested")


# ── CLI entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="tuxSOC Layer-2 ES Detection Engine")
    parser.add_argument("--once",    action="store_true", help="Run one detection cycle and exit")
    parser.add_argument("--replay",  action="store_true", help="Run in replay mode")
    parser.add_argument("--start",   type=str, help="Replay start time (ISO8601)")
    parser.add_argument("--end",     type=str, help="Replay end time (ISO8601)")
    parser.add_argument("--rules",   type=str, help="Comma-separated rule IDs for replay")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL_SECONDS,
                        help="Poll interval in seconds")
    args = parser.parse_args()

    if args.replay:
        from layer_2_detection_es.replay_engine import run_detection_replay
        start = datetime.fromisoformat(args.start) if args.start else \
                datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
        end   = datetime.fromisoformat(args.end) if args.end else datetime.now(timezone.utc)
        rules = args.rules.split(",") if args.rules else None
        incidents = run_detection_replay(start, end, rule_ids=rules)
        print(json.dumps(incidents, indent=2, default=str))

    elif args.once:
        incidents = run_once()
        print(json.dumps(incidents, indent=2, default=str))

    else:
        start_polling(interval_seconds=args.interval)
