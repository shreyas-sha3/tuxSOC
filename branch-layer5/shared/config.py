"""
Global configuration for the tuxSOC platform.
"""

# ── Layer 4: CVSS Scoring ────────────────────────────────────────────

# CVSS v3.1 severity thresholds (official spec)
SEVERITY_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 0.1,
    "NONE": 0.0,
}

# How many CIS violations bump severity up by one level
CIS_ESCALATION_THRESHOLD = 2

# Priority mapping: (severity, cis_penalty_applied) -> priority
PRIORITY_MAP = {
    ("CRITICAL", True):  {"priority": "P1", "urgency": "IMMEDIATE"},
    ("CRITICAL", False): {"priority": "P1", "urgency": "IMMEDIATE"},
    ("HIGH", True):      {"priority": "P1", "urgency": "IMMEDIATE"},
    ("HIGH", False):     {"priority": "P2", "urgency": "HIGH"},
    ("MEDIUM", True):    {"priority": "P2", "urgency": "HIGH"},
    ("MEDIUM", False):   {"priority": "P3", "urgency": "STANDARD"},
    ("LOW", True):       {"priority": "P3", "urgency": "STANDARD"},
    ("LOW", False):      {"priority": "P4", "urgency": "MONITOR"},
    ("NONE", True):      {"priority": "P4", "urgency": "MONITOR"},
    ("NONE", False):     {"priority": "P4", "urgency": "MONITOR"},
}

# Metric escalation severity order (used to check if CIS actually worsens a metric)
CVSS_METRIC_SEVERITY_ORDER = {
    "AV": ["P", "L", "A", "N"],       # Physical < Local < Adjacent < Network
    "AC": ["H", "L"],                  # High < Low (lower complexity = easier attack)
    "PR": ["H", "L", "N"],             # High < Low < None
    "UI": ["R", "N"],                  # Required < None
    "S":  ["U", "C"],                  # Unchanged < Changed
    "C":  ["N", "L", "H"],             # None < Low < High
    "I":  ["N", "L", "H"],             # None < Low < High
    "A":  ["N", "L", "H"],             # None < Low < High
}
