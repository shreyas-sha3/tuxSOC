from typing import List, Dict

def get_recommendations(severity: str, intent: str) -> List[str]:
    """
    Generates contextual response recommendations based on incident severity and intent.

    Args:
        severity (str): The CVSS severity level (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN).
        intent (str): The interpreted attacker intent from AI analysis.

    Returns:
        List[str]: A list of recommended next steps for SOC analysts.
    """
    recommendations = []

    # Normalize inputs for case-insensitive matching
    severity_lower = severity.lower()
    intent_lower = intent.lower()

    # Base recommendations by severity
    if severity_lower == "critical":
        recommendations.extend([
            "🚨 Isolate affected systems immediately",
            "📞 Initiate emergency incident response procedure",
            "👥 Notify senior management and legal team",
            "🔍 Preserve all logs and volatile memory for forensics"
        ])
    elif severity_lower == "high":
        recommendations.extend([
            "⚠️ Quarantine affected systems within 30 minutes",
            "📊 Increase monitoring on related systems",
            "📋 Document all observed activities",
            "🔒 Review and strengthen access controls"
        ])
    elif severity_lower == "medium":
        recommendations.extend([
            "🔍 Investigate root cause within 4 business hours",
            "📈 Trend analysis of similar events",
            "🛡️ Consider preventive control enhancements"
        ])
    else:  # LOW or UNKNOWN
        recommendations.extend([
            "📝 Log incident for trend analysis",
            "🔍 Verify no false positive",
            "📊 Include in regular security reporting"
        ])

    # Intent-specific recommendations
    if "brute force" in intent_lower or "credential" in intent_lower:
        recommendations.extend([
            "🔑 Force password reset for affected entity",
            "📋 Audit Active Directory login logs",
            "🔒 Enable account lockout policies if not active",
            "👥 Review privileged access for compromised accounts"
        ])
    elif "malware" in intent_lower or "ransomware" in intent_lower:
        recommendations.extend([
            "💻 Disconnect affected endpoints from network",
            "🧫 Run full anti-malware scan on affected systems",
            "💾 Verify integrity of recent backups",
            "📱 Check for lateral movement indicators"
        ])
    elif "data exfiltration" in intent_lower or "unauthorized access" in intent_lower:
        recommendations.extend([
            "📊 Review DLP logs for data movement",
            "🌐 Check firewall egress traffic for anomalies",
            "🔐 Review database access logs",
            "📋 Determine scope of potentially accessed data"
        ])
    elif "privilege escalation" in intent_lower:
        recommendations.extend([
            "👥 Review recent privilege assignments",
            "🔍 Check for unusual admin activity",
            "📋 Audit sudo and access token usage",
            "🔒 Review service account permissions"
        ])
    elif "lateral movement" in intent_lower:
        recommendations.extend([
            "🌐 Map recent internal network connections",
            "🔍 Check for pass-the-hash or ticket abuse",
            "📋 Review lateral movement detection rules",
            "💻 Isolate suspicious workstations"
        ])
    else:
        # Generic fallback for unknown/threat intent
        recommendations.extend([
            "🔍 Conduct thorough log analysis",
            "📊 Correlate with threat intelligence feeds",
            "🛡️ Review relevant security control effectiveness"
        ])

    # Deduplicate while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)

    return unique_recommendations