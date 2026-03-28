# pyod_detector.py
# Location: layer_2_detection/engine_1_anomaly/pyod_detector.py
# ─────────────────────────────────────────────────────────────────
# Lightweight anomaly scoring shim.
#
# In production you would run a trained PyOD IsolationForest / LOF
# model against feature vectors. For the Layer 2 ES-backed pipeline
# we derive a heuristic `pyod_score` from the ES-side detection
# metadata (rule severity, event count, UEBA flags) so the
# downstream schema stays identical to what Layer 3 expects.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations

# ── Severity → Base Score mapping ────────────────────────────────
_RULE_SEVERITY: dict[str, float] = {
    # Web
    "WEB_SQLI":        0.92,
    "WEB_CMDI":        0.94,
    "WEB_LFI":         0.85,
    "WEB_XSS":         0.78,
    "WEB_SCANNER":     0.60,
    "WEB_SSRF":        0.88,
    # Auth
    "AUTH_BRUTEFORCE":  0.90,
    "AUTH_SPRAY":       0.88,
    "AUTH_MFA_FATIGUE": 0.85,
    "AUTH_PRIV_ABUSE":  0.82,
    # Endpoint
    "EP_RANSOMWARE":    0.99,
    "EP_LOLBIN":        0.88,
    "EP_CREDENTIAL_DUMP": 0.95,
    "EP_DEF_EVASION":   0.93,
    "EP_PERSISTENCE":   0.80,
    # Network
    "NET_PORTSCAN":     0.75,
    "NET_C2_BEACON":    0.90,
    "NET_DNS_TUNNEL":   0.92,
    "NET_EXFIL":        0.93,
    "NET_LATERAL":      0.85,
}


def compute_anomaly_score(
    rule_id: str,
    ueba_flags: list[str] | None = None,
) -> dict:
    """
    Produces the `engine_1_anomaly` block used by the Layer 3 schema.

    Returns
    -------
    dict
        {
            "pyod_score":      float,   # 0.0 – 1.0
            "is_outlier":      bool,
            "ueba_flags":      [...],
            "anomaly_score":   float,
            "anomaly_flagged": bool,
        }
    """
    base = _RULE_SEVERITY.get(rule_id, 0.70)
    flags = ueba_flags or []

    # Boost by 0.03 per UEBA flag (capped at 1.0)
    boosted = min(base + 0.03 * len(flags), 1.0)

    return {
        "pyod_score":      round(boosted, 4),
        "is_outlier":      boosted >= 0.70,
        "ueba_flags":      flags,
        "anomaly_score":   round(boosted, 4),
        "anomaly_flagged": boosted >= 0.60,
    }
