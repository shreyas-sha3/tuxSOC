from shared.config import SEVERITY_THRESHOLDS, CIS_ESCALATION_THRESHOLD

# Ordered from most to least severe for escalation logic
_SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


def classify_severity(base_score: float, cis_violation_count: int = 0) -> str:
    """
    Converts a CVSS base score (0.0–10.0) into a severity label.
    
    If the number of CIS violations meets or exceeds CIS_ESCALATION_THRESHOLD,
    the severity is bumped up by one level (e.g., MEDIUM → HIGH).
    """
    # Determine base severity from score
    severity = "NONE"
    for level in _SEVERITY_LEVELS:
        if base_score >= SEVERITY_THRESHOLDS[level]:
            severity = level
            break

    # CIS escalation: bump severity if enough violations
    if cis_violation_count >= CIS_ESCALATION_THRESHOLD:
        current_idx = _SEVERITY_LEVELS.index(severity)
        if current_idx > 0:  # Can't escalate past CRITICAL
            severity = _SEVERITY_LEVELS[current_idx - 1]

    return severity
