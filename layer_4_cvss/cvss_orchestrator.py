from fastapi import FastAPI, HTTPException
from shared.schemas import LLMIncidentInput, ScoredIncidentOutput
from layer_4_cvss.engine_1_scorer.scorer_orchestrator import score_incident
from layer_4_cvss.engine_2_classifier.classifier_orchestrator import classify_incident

app = FastAPI(
    title="tuxSOC Layer 4: CVSS Scoring Service",
    description="Stateless CVSS scoring microservice receiving CIS violations directly in the payload.",
    version="3.0.0"
)


@app.post("/api/v1/score", response_model=ScoredIncidentOutput)
async def score_incident_endpoint(incident: LLMIncidentInput):
    """
    Receives incident data from Layer 3 (AI Analysis) and returns a scored output for Layer 5.
    Purely stateless: CIS violations are expected in the payload.
    """
    try:
        # Unwrap nested models
        ai_analysis = incident.ai_analysis
        cvss_metrics = ai_analysis.cvss_vector
        cis_violations = [v.model_dump() for v in ai_analysis.cis_violations]

        # Engine 1: Scoring (penalties + vector + base score)
        score_result = score_incident(
            metrics=cvss_metrics,
            cis_violations=cis_violations,
        )

        # Engine 2: Classification (severity + priority)
        classification = classify_incident(
            base_score=score_result["base_score"],
            cis_violation_count=len(score_result["cis_violations"]),
            cis_penalty_applied=score_result["cis_penalty_applied"],
        )

        severity = classification["severity"]
        requires_auto_block = (
            severity == "CRITICAL"
            or (severity == "HIGH" and score_result["cis_penalty_applied"])
        )

        return ScoredIncidentOutput(
            event_id=incident.event_id,
            base_score=score_result["base_score"],
            severity=severity,
            requires_auto_block=requires_auto_block,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(e)}")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "layer_4_cvss"}


def process_incident(incident_data: LLMIncidentInput) -> ScoredIncidentOutput:
    """
    Compatibility shim used by tests and direct callers.
    """
    # Simply wrap the logic (or call the endpoint logic directly if it wasn't async)
    # For simplicity, we re-implement the logic here as it's standard scoring.
    ai_analysis = incident_data.ai_analysis
    cvss_metrics = ai_analysis.cvss_vector
    cis_violations = [v.model_dump() for v in ai_analysis.cis_violations]

    score_result = score_incident(cvss_metrics, cis_violations)
    classification = classify_incident(
        base_score=score_result["base_score"],
        cis_violation_count=len(score_result["cis_violations"]),
        cis_penalty_applied=score_result["cis_penalty_applied"],
    )

    severity = classification["severity"]
    requires_auto_block = (
        severity == "CRITICAL"
        or (severity == "HIGH" and score_result["cis_penalty_applied"])
    )

    return ScoredIncidentOutput(
        event_id=incident_data.event_id,
        base_score=score_result["base_score"],
        severity=severity,
        requires_auto_block=requires_auto_block,
    )
if __name__ == "__main__":
    import uvicorn
    # Run Layer 4 on port 8004
    uvicorn.run(app, host="0.0.0.0", port=8004)

