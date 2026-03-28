import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi.responses import JSONResponse
from pydantic import BaseModel
# Added Union here!
from typing import Optional, List, Any, Union 
from ai_orchestrator import run_ai_analysis

from fastapi import FastAPI, HTTPException, Body, BackgroundTasks

# ─────────────────────────────────────────
# RESPONSE MODELS (Swagger UI visibility)
# ─────────────────────────────────────────

class CvssVector(BaseModel):
    AV: str; AC: str; PR: str; UI: str
    S: str;  C: str;  I: str;  A: str

class AiAnalysis(BaseModel):
    intent:              Optional[str]
    severity:            Optional[str]
    cvss_vector:         Optional[CvssVector]
    narrative:           Optional[str]
    recommended_actions: Optional[List[str]]
    ai_failed:           bool
    cis_violations:      Optional[List[dict]] = []

class CriterionEval(BaseModel):
    triggered: Optional[bool]
    rationale: Optional[str]

class Article18(BaseModel):
    is_major_incident:   Optional[bool] = None
    criteria_triggered:  Optional[List[str]] = None
    criteria_evaluation: Optional[dict] = None

class Article19(BaseModel):
    notification_type:      Optional[str] = None
    regulation:             Optional[str] = None
    reporting_standard:     Optional[str] = None
    incident_id:            Optional[str] = None
    lei:                    Optional[str] = None
    incident_timestamp:     Optional[str] = None
    classification_time:    Optional[str] = None
    affected_services:      Optional[List[str]] = None
    initial_description:    Optional[str] = None
    c1_to_c6_triggers:      Optional[List[str]] = None
    containment_status:     Optional[str] = None
    cross_border_impact:    Optional[bool] = None
    escalated_to_regulator: Optional[bool] = None

class DoraCompliance(BaseModel):
    article_18_classification:       Optional[Article18] = None
    article_19_initial_notification: Optional[Article19] = None

class AnalysisResponse(BaseModel):
    incident_id:     Optional[str]
    threat_summary:  Optional[str]
    observables:     Optional[dict]
    ai_analysis:     Optional[AiAnalysis]
    dora_compliance: Optional[DoraCompliance]

app = FastAPI(
    title="Barclays SOC — Layer 3 AI Analyst",
    description=(
        "Autonomous cyber incident analysis engine. "
        "Produces a 5-key SOC report, structured observables, "
        "and a DORA Article 18/19 T+4h Initial Notification (ITS 2025/302)."
    ),
    version="2.0.0"
)

# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "online", "engine": "llama3.2-3b-optimized"}


# ─────────────────────────────────────────
# MAIN ANALYSIS ENDPOINT
# ─────────────────────────────────────────

@app.post("/analyze")
async def analyze(background_tasks: BackgroundTasks, data: Union[dict, list] = Body(...)):
    """
    HIGH THROUGHPUT ASYNC ENDPOINT
    1. Accepts the payload (single dict or list of dicts).
    2. Immediately returns a '202 Accepted' status to the caller.
    3. Queues the heavy AI analysis to run in the background.
    """
    try:
        # ── NEW: Unwrap Layer 2 Envelope if it exists ──
        if isinstance(data, dict) and "detections" in data:
            data = data["detections"]

        # Handle list vs dict input for the initial response
        if isinstance(data, list):
            incident_id = data[0].get("incident_id") or data[0].get("event_id") or "BATCH_INCIDENT"
            count = len(data)
            # Queue each incident in the list separately for the background worker
            for incident in data:
                background_tasks.add_task(run_ai_analysis, incident)
        else:
            incident_id = data.get("incident_id") or data.get("event_id") or "UNKNOWN"
            count = 1
            background_tasks.add_task(run_ai_analysis, data)

        # Return immediately so the test script/Layer 2 doesn't timeout
        return JSONResponse(
            status_code=202,
            content={
                "status": "accepted",
                "message": f"Queued {count} incident(s) for background AI analysis.",
                "primary_incident_id": incident_id,
                "note": "Results will be pushed to Layer 4 automatically upon completion."
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue incidents: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    import logging
    
    log = logging.getLogger("uvicorn")
    log.setLevel(logging.ERROR)
    log = logging.getLogger("uvicorn.access")
    log.setLevel(logging.ERROR)
    
    uvicorn.run(app, host="0.0.0.0", port=8001, access_log=False)