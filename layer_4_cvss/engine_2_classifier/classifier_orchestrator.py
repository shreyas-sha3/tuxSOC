from layer_4_cvss.engine_2_classifier.severity_classifier import classify_severity
from layer_4_cvss.engine_2_classifier.priority_assigner import assign_priority


def classify_incident(
    base_score: float,
    cis_violation_count: int,
    cis_penalty_applied: bool,
) -> dict:
    """
    Full classification pipeline:
    1. Classify severity from base score + CIS context
    2. Assign operational priority and urgency
    
    Returns a dict with severity, priority, and response_urgency.
    """
    severity = classify_severity(base_score, cis_violation_count)
    priority_info = assign_priority(severity, cis_penalty_applied)

    return {
        "severity": severity,
        "priority": priority_info["priority"],
        "response_urgency": priority_info["urgency"],
    }
