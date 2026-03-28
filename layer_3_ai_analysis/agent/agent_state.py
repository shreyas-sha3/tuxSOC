from typing import TypedDict, Optional


class AgentState(TypedDict):
    # ── Input ─────────────────────────────
    incident_data: dict
    event_id: Optional[str]

    # ── Canonical AI Outputs (5 required keys) ──
    intent: Optional[str]
    severity: Optional[str]
    cvss_vector: Optional[dict]
    narrative: Optional[str]
    recommended_actions: Optional[list]

    # ── Legacy aliases (LLM may return these names) ──
    attack_intent: Optional[str]
    severity_recommendation: Optional[str]
    cvss: Optional[dict]

    # ── Control & Assembly ────────────────
    ai_analysis: Optional[dict]
    retry_count: int
    validation_passed: bool
    ai_failed: bool
    ai_failure_reason: Optional[str]
    error: Optional[str]
