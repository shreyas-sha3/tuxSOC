from shared.config import CVSS_METRIC_SEVERITY_ORDER
from layer_4_cvss.engine_1_scorer.vector_builder import build_vector_string
from layer_4_cvss.engine_1_scorer.cvss_calculator import calculate_base_score


def _is_escalation(metric: str, current_val: str, new_val: str) -> bool:
    """Check if new_val is a worse (higher severity) value than current_val."""
    order = CVSS_METRIC_SEVERITY_ORDER.get(metric, [])
    if current_val not in order or new_val not in order:
        return False
    return order.index(new_val) > order.index(current_val)


def apply_cis_penalties(metrics: dict, cis_violations: list[dict]) -> tuple[dict, bool]:
    """
    Worsens CVSS metrics based on confirmed CIS violations for the asset.
    Only escalates (makes worse), never downgrades.

    Returns: (adjusted_metrics, penalty_was_applied)
    """
    if not cis_violations:
        return metrics, False

    adjusted = metrics.copy()
    penalty_applied = False

    for violation in cis_violations:
        impact = violation.get("cvss_impact", {})
        metric = impact.get("metric")
        escalate_to = impact.get("escalate_to")

        if not metric or not escalate_to:
            continue

        current = adjusted.get(metric, "")
        if _is_escalation(metric, current, escalate_to):
            adjusted[metric] = escalate_to
            penalty_applied = True

    return adjusted, penalty_applied


def score_incident(metrics: dict, cis_violations: list[dict]) -> dict:
    """
    Full scoring pipeline (Stateless):
    1. Apply CIS penalties to CVSS metrics (only escalates, never downgrades)
    2. Build the CVSS vector string
    3. Calculate the numerical base score

    Returns a dict with all scoring internals.
    """
    adjusted_metrics, penalty_applied = apply_cis_penalties(metrics, cis_violations)

    vector_string = build_vector_string(adjusted_metrics)
    base_score = calculate_base_score(vector_string)

    return {
        "cvss_vector": vector_string,
        "base_score": base_score,
        "cis_violations": cis_violations,
        "cis_penalty_applied": penalty_applied,
    }

