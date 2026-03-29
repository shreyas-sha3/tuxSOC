# detection_orchestrator.py
# Location: layer_2_detection/detection_orchestrator.py
# ═════════════════════════════════════════════════════════════════
# Layer 2: Detection & Correlation Engine — Master Orchestrator
#
# A stateless FastAPI microservice backed entirely by Elasticsearch.
# Continuously polls ES indices for attack signatures, runs UEBA
# behavioral analytics, correlates related events, and dispatches
# enriched incident payloads to Layer 3 (AI Analysis).
#
# Architecture:
#   ┌──────────────────────────────────────────────────────┐
#   │                  Detection Orchestrator              │
#   │                   (FastAPI @ :8002)                   │
#   │                                                      │
#   │  ┌────────────┐ ┌────────────┐ ┌──────────────────┐  │
#   │  │ Rules Eng. │ │ Anomaly    │ │ Threat Intel     │  │
#   │  │ (20 rules) │ │ UEBA+PyOD │ │ IOC+MITRE       │  │
#   │  └─────┬──────┘ └─────┬──────┘ └───────┬──────────┘  │
#   │        │              │                │             │
#   │        └──────┬───────┘                │             │
#   │               ▼                        │             │
#   │  ┌──────────────────────┐              │             │
#   │  │ Correlation Engine   │◀─────────────┘             │
#   │  │ (5-min time-machine) │                            │
#   │  └──────────┬───────────┘                            │
#   │             ▼                                        │
#   │  ┌──────────────────────┐                            │
#   │  │ Dispatcher           │─────► Layer 3 @ :8001      │
#   │  │ (JSON packaging)     │                            │
#   │  └──────────────────────┘                            │
#   └──────────────────────────────────────────────────────┘
# ═════════════════════════════════════════════════════════════════

from __future__ import annotations

import os
import sys
import uuid
import asyncio
import requests
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.text import Text
import threading
import time

console = Console()

class UIState:
    def __init__(self):
        self.total_cycles = 0
        self.clean_cycles = 0
        self.threats_detected = 0
        self.last_threat_time = "N/A"
        self.recent_threats = []
        self.status = "Initializing..."
        self.duplicates_suppressed = 0

ui_state = UIState()

def generate_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    
    header = Panel(Text("tuxSOC - Layer 2: Detection & Correlation Engine", justify="center", style="bold cyan"))
    layout["header"].update(header)
    
    layout["main"].split_row(
        Layout(name="stats", ratio=1),
        Layout(name="threats", ratio=2)
    )
    
    stats = Table.grid(padding=1)
    stats.add_column(style="cyan", justify="left")
    stats.add_column(style="white", justify="right")
    stats.add_row("Status:", ui_state.status)
    stats.add_row("Poll Cycles:", str(ui_state.total_cycles))
    stats.add_row("Clean Cycles:", f"[green]{ui_state.clean_cycles}[/green]")
    stats.add_row("Threats Det.:", f"[bold red]{ui_state.threats_detected}[/bold red]")
    stats.add_row("Duplicates Suppr.:", f"[dim]{ui_state.duplicates_suppressed}[/dim]")
    stats.add_row("Last Threat:", ui_state.last_threat_time)
    
    layout["stats"].update(Panel(stats, title="Engine Statistics", border_style="cyan"))
    
    t_table = Table(show_header=True, header_style="bold red", expand=True)
    t_table.add_column("Time")
    t_table.add_column("Rule ID")
    t_table.add_column("Pivot")
    
    for t in ui_state.recent_threats[-15:]:
        t_table.add_row(t['time'], t['rule'], t['pivot'])
        
    layout["threats"].update(Panel(t_table, title="🚨 Recent Detections", border_style="red"))
    return layout

def _live_updater():
    with Live(generate_layout(), refresh_per_second=4, screen=True) as live:
        while True:
            live.update(generate_layout())
            time.sleep(0.25)

threading.Thread(target=_live_updater, daemon=True).start()

from fastapi import FastAPI, HTTPException
from elasticsearch import Elasticsearch

# ── Internal Engine Imports ───────────────────────────────────
from layer_2_detection.rules_engine import run_all_rules
from layer_2_detection.engine_1_anomaly.anomaly_orchestrator import build_anomaly_block
from layer_2_detection.engine_2_threat_intel.intel_orchestrator import enrich_threat_intel
from layer_2_detection.engine_3_correlation.correlation_orchestrator import build_correlation_block


# ═════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASSWORD", "changeme")
ES_API_KEY = os.getenv("ES_API_KEY", None)

LAYER_3_URL = os.getenv("LAYER_3_URL", "http://localhost:8003/analyze")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL", "30"))

# ── Deduplication window (in-memory, stateless per process restart)
_seen_detection_keys: set[str] = set()
_MAX_SEEN = 10_000  # Evict oldest after this threshold


# ═════════════════════════════════════════════════════════════════
# ELASTICSEARCH CLIENT FACTORY
# ═════════════════════════════════════════════════════════════════

def _build_es_client() -> Elasticsearch:
    """
    Creates an Elasticsearch client using env vars.
    Supports basic auth or API key authentication.
    """
    kwargs = {
        "hosts": [ES_HOST],
        "request_timeout": 15,
        "max_retries": 2,
        "retry_on_timeout": True,
    }

    if ES_API_KEY:
        kwargs["api_key"] = ES_API_KEY
    else:
        kwargs["basic_auth"] = (ES_USER, ES_PASS)

    # Disable SSL verification for dev (change for prod)
    if ES_HOST.startswith("https"):
        kwargs["verify_certs"] = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return Elasticsearch(**kwargs)


def _check_es_health(es: Elasticsearch) -> dict:
    """Quick ES cluster health check."""
    try:
        info = es.info()
        health = es.cluster.health()
        return {
            "connected": True,
            "cluster_name": info.get("cluster_name", "unknown"),
            "version": info.get("version", {}).get("number", "unknown"),
            "status": health.get("status", "unknown"),
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


# ═════════════════════════════════════════════════════════════════
# RAW EVENT NORMALISATION
# ═════════════════════════════════════════════════════════════════

def _normalise_raw_event(detection: dict, correlated_events: list[dict] | None = None) -> dict:
    """
    Extracts a normalised raw_event from a detection's raw_hits or
    correlated event cluster. If no raw hit exists (aggregation-only
    rules like AUTH_BRUTEFORCE), builds a synthetic raw_event from
    pivot metadata.
    """
    raw_hits = detection.get("raw_hits", [])

    if raw_hits:
        hit = raw_hits[0]
        raw = hit.get("raw_event", hit)  # Support both nested & flat schemas
        return {
            "source_ip":      raw.get("source_ip") or hit.get("source", {}).get("ip", detection.get("pivot_ip", "")),
            "destination_ip":  raw.get("destination_ip") or hit.get("destination", {}).get("ip", ""),
            "affected_user":   raw.get("affected_user") or hit.get("user", {}).get("name", detection.get("pivot_user", "")),
            "affected_host":   raw.get("affected_host") or hit.get("host", {}).get("name", ""),
            "port":            raw.get("port") or hit.get("destination", {}).get("port"),
            "protocol":        raw.get("protocol") or hit.get("network", {}).get("transport", ""),
            "action":          raw.get("action") or detection.get("detail", ""),
            "timestamp":       raw.get("timestamp") or hit.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        }

    # Synthetic raw_event for aggregation-only rules
    return {
        "source_ip":      detection.get("pivot_ip", ""),
        "destination_ip":  "",
        "affected_user":   detection.get("pivot_user", ""),
        "affected_host":   "",
        "port":            None,
        "protocol":        "",
        "action":          detection.get("detail", ""),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════════
# DEDUPLICATION
# ═════════════════════════════════════════════════════════════════

def _dedup_key(detection: dict) -> str:
    """Unique key per rule+pivot to prevent rapid re-dispatch."""
    return f"{detection['rule_id']}::{detection.get('pivot_ip', '')}::{detection.get('pivot_user', '')}"


def _is_duplicate(key: str) -> bool:
    global _seen_detection_keys
    if key in _seen_detection_keys:
        return True
    if len(_seen_detection_keys) > _MAX_SEEN:
        _seen_detection_keys = set()  # Simple eviction
    _seen_detection_keys.add(key)
    return False


# ═════════════════════════════════════════════════════════════════
# INCIDENT ASSEMBLY & DISPATCH
# ═════════════════════════════════════════════════════════════════

def assemble_incident(
    detection: dict,
    es: Elasticsearch,
) -> dict:
    """
    Takes a single detection from the Rules Engine and produces a
    fully-enriched incident dict matching Layer 3's expected schema.

    Pipeline:
      Detection → Anomaly Scoring → Threat Intel → Correlation → JSON
    """
    rule_id = detection["rule_id"]
    pivot_ip = detection.get("pivot_ip")
    pivot_user = detection.get("pivot_user")

    # ── 1. Anomaly block (Engine 1) ───────────────────────
    anomaly_block = build_anomaly_block(
        rule_id=rule_id,
        es=es,
        user=pivot_user,
        extra_ueba_flags=detection.get("ueba_flags"),
    )

    # ── 2. Raw event normalisation ────────────────────────
    raw_event = _normalise_raw_event(detection)

    # ── 3. Threat intel enrichment (Engine 2) ─────────────
    threat_intel_block = enrich_threat_intel(
        raw_event=raw_event,
        rule_id=rule_id,
        es_client=es,
    )

    # ── 4. Correlation + Timeline (Engine 3) ──────────────
    # Extract additional pivots from the raw event for broader correlation
    pivot_host = raw_event.get("affected_host") or None
    pivot_dest_ip = raw_event.get("destination_ip") or None

    correlation_block = build_correlation_block(
        es=es,
        pivot_ip=pivot_ip,
        pivot_user=pivot_user,
        pivot_host=pivot_host,
        pivot_dest_ip=pivot_dest_ip,
    )

    # Pull correlated_evidence out for the top-level payload
    correlated_evidence = correlation_block.pop("correlated_evidence", [])

    # ── 5. Assemble final schema ──────────────────────────
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y-%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    return {
        "incident_id":           incident_id,
        "timestamp":             raw_event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "log_type":              detection["log_type"],
        "detection_rule":        rule_id,
        "raw_event":             raw_event,
        "correlated_evidence":   correlated_evidence,
        "engine_1_anomaly":      anomaly_block,
        "engine_2_threat_intel": threat_intel_block,
        "engine_3_correlation":  correlation_block,
    }


def dispatch_to_layer3(incidents: list[dict]) -> dict:
    """
    POST the assembled incident list to Layer 3 (AI Analysis).
    Returns the response or an error dict.
    """
    if not incidents:
        return {"status": "no_incidents", "count": 0}

    try:
        ui_state.status = f"[bold blue]Dispatching {len(incidents)} to Layer 3...[/bold blue]"
        resp = requests.post(LAYER_3_URL, json=incidents, timeout=10)
        if resp.status_code in (200, 202):
            ui_state.status = f"[bold green]✓ Dispatched {len(incidents)} to L3[/bold green]"
            return {"status": "dispatched", "count": len(incidents), "response": resp.json()}
        else:
            ui_state.status = f"[bold yellow]⚠️ L3 returned {resp.status_code}[/bold yellow]"
            return {"status": "error", "http_status": resp.status_code, "body": resp.text}
    except requests.exceptions.ConnectionError:
        ui_state.status = f"[bold red]❌ Cannot reach L3[/bold red]"
        return {"status": "connection_error", "url": LAYER_3_URL}
    except Exception as e:
        ui_state.status = f"[bold red]❌ Dispatch failed: {e}[/bold red]"
        return {"status": "error", "detail": str(e)}


# ═════════════════════════════════════════════════════════════════
# POLL CYCLE  (runs in background asyncio task)
# ═════════════════════════════════════════════════════════════════

async def _poll_cycle(es: Elasticsearch):
    """
    One full detection cycle:
      1. Run all rules against ES
      2. Deduplicate
      3. Assemble each detection into a Layer 3 incident
      4. Batch-dispatch to Layer 3
    """
    ui_state.total_cycles += 1
    ui_state.status = "[cyan]Running Detection Rules...[/cyan]"

    detections = run_all_rules(es)
    if not detections:
        ui_state.clean_cycles += 1
        ui_state.status = "[dim]Monitoring background traffic...[/dim]"
        return

    # Deduplicate
    fresh: list[dict] = []
    duplicate_count = 0  
    
    for d in detections:
        key = _dedup_key(d)
        if not _is_duplicate(key):
            fresh.append(d)
        else:
            duplicate_count += 1  

    ui_state.duplicates_suppressed += duplicate_count

    if not fresh:
        ui_state.clean_cycles += 1
        ui_state.status = f"[dim]Suppressed {duplicate_count} duplicates...[/dim]"
        return

    ui_state.threats_detected += len(fresh)
    ui_state.last_threat_time = datetime.now().strftime("%H:%M:%S")

    # Assemble
    incidents: list[dict] = []
    for d in fresh:
        ui_state.recent_threats.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "rule": d['rule_id'],
            "pivot": d.get('pivot_ip', '') or d.get('pivot_user', '')
        })
        try:
            inc = assemble_incident(d, es)
            incidents.append(inc)
        except Exception as e:
            ui_state.status = f"[bold red]❌ Assembly failed: {e}[/bold red]"

    # Dispatch
    dispatch_to_layer3(incidents)


async def _background_poller(es: Elasticsearch):
    """Infinite polling loop running as a background asyncio task."""
    ui_state.status = f"[dim]Poller started ({POLL_INTERVAL_SECONDS}s)[/dim]"
    while True:
        try:
            await _poll_cycle(es)
        except Exception as e:
            ui_state.status = f"[bold red]Poll crashed: {e}[/bold red]"
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


# ═════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═════════════════════════════════════════════════════════════════

# Shared ES client (created on startup)
_es_client: Optional[Elasticsearch] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    global _es_client
    
    _es_client = _build_es_client()
    health = _check_es_health(_es_client)

    if health["connected"]:
        ui_state.status = f"[green]Connected to ES {health['cluster_name']}[/green]"
        task = asyncio.create_task(_background_poller(_es_client))
    else:
        ui_state.status = f"[bold red]ES Offline: {health.get('error')}[/bold red]"
        task = None

    yield

    if task:
        task.cancel()
    if _es_client:
        _es_client.close()


app = FastAPI(
    title="tuxSOC Layer 2: Detection & Correlation Engine",
    description=(
        "Stateless, ES-backed detection engine. "
        "Polls Elasticsearch for attack signatures across web, auth, endpoint, "
        "and network indices. Correlates events and dispatches enriched incidents to Layer 3."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Health ────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    if _es_client:
        es_health = _check_es_health(_es_client)
    else:
        es_health = {"connected": False, "error": "Client not initialised"}
    return {
        "status": "healthy",
        "service": "Layer 2: Detection & Correlation",
        "elasticsearch": es_health,
    }


# ── Manual Scan Trigger ──────────────────────────────────────
@app.post("/api/v1/scan")
async def manual_scan():
    """
    Manually trigger a full detection cycle (useful for demos & testing).
    """
    if not _es_client:
        raise HTTPException(status_code=503, detail="Elasticsearch client not available")

    es_health = _check_es_health(_es_client)
    if not es_health["connected"]:
        raise HTTPException(status_code=503, detail=f"Elasticsearch unreachable: {es_health.get('error')}")

    await _poll_cycle(_es_client)
    return {"status": "scan_complete", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Simulate Detection (for testing without ES) ──────────────
@app.post("/api/v1/simulate")
async def simulate_detection(detections: list[dict]):
    """
    Accepts a list of pre-formed detection dicts (same format as
    rules_engine output) and runs them through the assembly +
    dispatch pipeline. Useful for integration testing without ES.
    """
    if not _es_client:
        raise HTTPException(status_code=503, detail="Elasticsearch client not available")

    incidents = []
    for d in detections:
        try:
            inc = assemble_incident(d, _es_client)
            incidents.append(inc)
        except Exception as e:
            print(f"[L2-DETECT] ERROR: Simulation assembly failed: {e}")

    result = dispatch_to_layer3(incidents)
    return {"assembled": len(incidents), "dispatch": result}


# ── Status / Metrics ─────────────────────────────────────────
@app.get("/api/v1/status")
async def status():
    return {
        "dedup_cache_size": len(_seen_detection_keys),
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "layer_3_url": LAYER_3_URL,
        "es_host": ES_HOST,
    }


# ═════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    # Suppress access logs and standard logging to stop uvicorn from printing over the Live layout
    import logging
    log = logging.getLogger("uvicorn")
    log.setLevel(logging.ERROR)
    log = logging.getLogger("uvicorn.access")
    log.setLevel(logging.ERROR)
    
    uvicorn.run(app, host="0.0.0.0", port=8002, access_log=False)
