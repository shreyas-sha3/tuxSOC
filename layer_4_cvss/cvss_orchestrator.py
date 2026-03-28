from shared.schemas import LLMIncidentInput, ScoredIncidentOutput
from layer_4_cvss.engine_1_scorer.vector_builder import build_vector_string
from layer_4_cvss.engine_1_scorer.cvss_calculator import calculate_base_score

def process_incident(incident_data: LLMIncidentInput) -> ScoredIncidentOutput:
    # 1. Extract the metrics dict
    metrics_dict = incident_data.cvss

    # 2. Build the vector string
    vector_string = build_vector_string(metrics_dict)

    # 3. Calculate the math
    score = calculate_base_score(vector_string)

    # 4. Quick severity assignment (You will expand this later in Engine 2)
    if score >= 9.0:
        severity = "CRITICAL"
    elif score >= 7.0:
        severity = "HIGH"
    elif score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # 5. Return the finalized object
    return ScoredIncidentOutput(
        incident_id=incident_data.incident_id,
        cvss_vector=vector_string,
        base_score=score,
        severity=severity
    )
