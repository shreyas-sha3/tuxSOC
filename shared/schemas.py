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
    kibana_query: Optional[str] = None
    recommended_actions: List[str]
    ai_failed: bool
    cis_violations: List[CISViolation] = Field(default_factory=list)
    playbook_raw: Optional[str] = None

class LLMIncidentInput(BaseModel):
    event_id: str
    ai_analysis: AIAnalysis
    observables: Optional[dict] = None
    related_logs: Optional[list] = []
    dora_compliance: Optional[dict] = None

class ScoredIncidentOutput(BaseModel):
    event_id: str
    base_score: float
    severity: str
    requires_auto_block: bool
    dora_compliance: Optional[dict] = None

class Layer5Input(BaseModel):
    event_id: str
    base_score: float
    severity: str
    requires_auto_block: bool
    attacker_ip: Optional[str] = "Unknown"
    affected_entity: Optional[str] = "Unknown"
    intent: Optional[str] = "Unknown Threat"
    kibana_query: Optional[str] = None
    related_logs: Optional[list] = []
    dora_compliance: Optional[dict] = None
    playbook_raw: Optional[str] = None