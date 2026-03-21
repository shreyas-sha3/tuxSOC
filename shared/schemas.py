from pydantic import BaseModel
from typing import Dict, Optional

# What LLM will send you
class LLMIncidentInput(BaseModel):
    incident_id: str
    cvss: Dict[str, str]
    threat_summary: Optional[str] = "No summary provided"

# send to the Response Layer
class ScoredIncidentOutput(BaseModel):
    incident_id: str
    cvss_vector: str
    base_score: float
    severity: str
