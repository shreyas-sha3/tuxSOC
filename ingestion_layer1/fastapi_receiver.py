"""
Single /ingest_file endpoint for bank‑style SOC.

Input:  file upload → any log format
Output: enriched ECS‑style logs through feature_orchestrator.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.responses import JSONResponse
import tempfile
import os
import sys
from typing import Dict, Any, List

# Add feature engineering to path
sys.path.append("layer_1_feature_engineering")
from feature_orchestrator import run_feature_engineering
from log_normalizer import normalize_parsed_log, backfill_time_aliases
from engine_1_temporal.temporal_orchestrator import run_temporal

app = FastAPI(
    title="SOC Log Ingestion API",
    description="Ingests any log file → normalizes to ECS → runs feature engineering pipeline"
)

@app.post("/ingest_file")
async def ingest_log_file(file: UploadFile = File(...)):
    """
    Upload log file -> parse -> normalize -> run feature_orchestrator.
    Returns:
        status, file, total_processed, and sample enriched logs.
    """
    try:
        # Write to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Parse the file
        import log_parsers
        parsed_logs = log_parsers.file_to_parsed_list(tmp_path)

        # Normalize → temporal → backfill time aliases → full feature engineering
        enriched_logs: List[Dict[str, Any]] = []
        for parsed_log in parsed_logs:

            # Step 1: Normalize to ECS + flat keys
            ecs_log = normalize_parsed_log(parsed_log)

            # Step 2: Run temporal engine first so time_windows exists
            ecs_log = run_temporal(ecs_log)

            # Step 3: Back-fill flat time aliases behavioral engine needs
            ecs_log = backfill_time_aliases(ecs_log)

            # Step 4: Run full feature engineering pipeline
            # (temporal will re-run harmlessly, then behavioral/statistical/family engines)
            enriched = run_feature_engineering(ecs_log)
            enriched_logs.append(enriched)

        os.unlink(tmp_path)  # Cleanup

        return {
            "status": "success",
            "file": file.filename,
            "format_detected": parsed_logs[0].get("format") if parsed_logs else None,
            "total_processed": len(enriched_logs),
            "sample_enriched": enriched_logs[:3]
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File ingestion failed: {str(e)}"
        )

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SOC Ingestion Layer"}