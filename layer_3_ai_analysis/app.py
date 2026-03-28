import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Any
from ai_orchestrator import run_ai_analysis


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

class CriterionEval(BaseModel):
    triggered: Optional[bool]
    rationale: Optional[str]

class Article18(BaseModel):
    is_major_incident:   Optional[bool]
    criteria_triggered:  Optional[List[str]]
    criteria_evaluation: Optional[dict]

class Article19(BaseModel):
    notification_type:      Optional[str]
    regulation:             Optional[str]
    reporting_standard:     Optional[str]
    incident_id:            Optional[str]
    lei:                    Optional[str]
    incident_timestamp:     Optional[str]
    classification_time:    Optional[str]
    affected_services:      Optional[List[str]]
    initial_description:    Optional[str]
    c1_to_c6_triggers:      Optional[List[str]]
    containment_status:     Optional[str]
    cross_border_impact:    Optional[bool]
    escalated_to_regulator: Optional[bool]

class DoraCompliance(BaseModel):
    article_18_classification:      Optional[Article18]
    article_19_initial_notification: Optional[Article19]

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

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(data: dict = Body(...)):
    """
    Accepts a raw incident JSON payload (dict or list).

    Returns a complete package containing:
    - **observables**: Code-extracted technical facts (IPs, ports, MITRE technique)
    - **ai_analysis**: 5-key SOC report (intent, severity, cvss_vector, narrative, actions)
    - **dora_compliance**: DORA Article 18 classification + Article 19 T+4h Initial Notification (ITS 2025/302)
    """
    try:
        result = run_ai_analysis(data)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis engine failed: {str(e)}"
        )

    ai = result.get("ai_analysis", {})
    if ai.get("ai_failed"):
        return JSONResponse(
            status_code=500,
            content={
                "error":         "Analysis failed",
                "reason":        ai.get("ai_failure_reason", "Unknown error"),
                "incident_id":   result.get("incident_id"),
                "observables":   result.get("observables"),
                "dora_compliance": result.get("dora_compliance")
            }
        )

    return result


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    # Port 8001 — avoids clash with teammate's Scoring Layer on 8000
    # host 0.0.0.0 — visible to all laptops on the same Wi-Fi
    uvicorn.run(app, host="0.0.0.0", port=8001)
