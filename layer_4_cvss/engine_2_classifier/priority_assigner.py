from shared.config import PRIORITY_MAP


def assign_priority(severity: str, cis_penalty_applied: bool) -> dict:
    """
    Maps a severity label + CIS context into operational priority and urgency.
    
    Returns:
        {
            "priority": "P1" | "P2" | "P3" | "P4",
            "urgency":  "IMMEDIATE" | "HIGH" | "STANDARD" | "MONITOR"
        }
    """
    key = (severity, cis_penalty_applied)
    result = PRIORITY_MAP.get(key)

    if result is None:
        return {"priority": "P4", "urgency": "MONITOR"}

    return result.copy()
