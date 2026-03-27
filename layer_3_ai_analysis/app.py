import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.responses import JSONResponse
from ai_orchestrator import run_ai_analysis

app = FastAPI(
    title="Barclays SOC — Layer 3 AI Analyst",
    description="Autonomous cyber incident analysis engine. Accepts raw telemetry, returns 5-key SOC report.",
    version="1.0.0"
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
async def analyze(data: dict = Body(...)): # Change this line
    """
    Accepts a JSON incident payload. 
    Returns the full AI analysis.
    """
    # You no longer need 'data = await request.json()' 
    # FastAPI handles it for you now!

    try:
        result = run_ai_analysis(data)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis engine failed: {str(e)}"
        )

    # Surface a clean 500 if the orchestrator itself flagged a failure
    ai = result.get("ai_analysis", {})
    if ai.get("ai_failed"):
        return JSONResponse(
            status_code=500,
            content={
                "error":  "Analysis failed",
                "reason": ai.get("ai_failure_reason", "Unknown error"),
                "event_id": result.get("event_id")
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
