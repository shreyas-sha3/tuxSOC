import sys
import os
import requests
import json
import logging
from fastapi import FastAPI, HTTPException, Body
from typing import List, Dict, Any

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("layer_0_ingestion")

app = FastAPI(
    title="Barclays SOC — Layer 0 Ingestion",
    description="Receives raw telemetry and routes to appropriate analysis layers.",
    version="1.0.0"
)

LAYER_3_URL = os.environ.get("LAYER_3_URL", "http://localhost:8003/analyze")

@app.post("/api/v1/ingest/benchmark")
async def ingest_benchmark(data: List[Dict[str, Any]] = Body(...)):
    """
    Ingests a benchmark sequence (array of raw logs), aggregates them, 
    and sends them directly to Layer 3 for playbook generation.
    """
    logger.info(f"Received benchmark sequence containing {len(data)} events. Routing directly to Layer 3.")
    
    if not data:
        raise HTTPException(status_code=400, detail="Empty benchmark array provided.")

    # Generate a deterministic but pseudo-unique ID based on the first log or timestamp
    first_log = data[0]
    log_id_base = first_log.get("log_id", first_log.get("@timestamp", "UNKNOWN"))
    incident_id = f"BENCHMARK-{log_id_base}"

    # Wrap the raw array into a Layer 3 compatible payload
    # Layer 3 expects {"incident_id": ..., "correlated_evidence": [...]} or a list of dicts.
    # We add `is_benchmark_sequence` to bypass DORA and standard anomaly detection.
    payload = {
        "incident_id": incident_id,
        "correlated_evidence": data, # Layer 3 prompt builder extracts this
        "is_benchmark_sequence": True,
        # Adding dummy observables so `_extract_observables` in Layer 3 doesn't fail
        "raw_event": {
            "source_ip": first_log.get("IpAddress") or first_log.get("ClientIP") or "Unknown",
            "affected_user": first_log.get("UserPrincipalName") or first_log.get("UserId") or "Unknown",
        "action": first_log.get("OperationName") or first_log.get("Operation") or "Unknown Benchmark Sequence",
        "is_direct_l3": True,
        "source_layer": "layer_0"
    }
    }

    try:
        response = requests.post(LAYER_3_URL, json=payload, timeout=10)
        response.raise_for_status()
        
        return {
            "status": "success", 
            "message": f"Routed benchmark sequence {incident_id} to Layer 3.",
            "layer_3_response": response.json()
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to route benchmark to Layer 3: {e}")
        raise HTTPException(status_code=502, detail=f"Layer 3 connection failed: {str(e)}")

@app.get("/health")
def health():
    return {"status": "online"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
