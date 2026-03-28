from pydantic import BaseModel, Field
from typing import Dict, List, Optional

class CVSSImpact(BaseModel):
    metric: str
    escalate_to: str

class CISViolation(BaseModel):
    rule_id: str
    cvss_impact: CVSSImpact

class AIAnalysis(BaseModel):
    intent: str
    severity: str
    cvss_vector: Dict[str, str]
    narrative: str
    recommended_actions: List[str]
    ai_failed: bool
    cis_violations: List[CISViolation] = Field(default_factory=list)

class LLMIncidentInput(BaseModel):
    event_id: str
    ai_analysis: AIAnalysis

class ScoredIncidentOutput(BaseModel):
    event_id: str
    base_score: float
    severity: str
    requires_auto_block: bool

class Layer5Input(BaseModel):
    event_id: str
    base_score: float
    severity: str
    requires_auto_block: bool
    attacker_ip: str = "Unknown"
    affected_entity: str = "Unknown"
    intent: str = "Unknown Threat"