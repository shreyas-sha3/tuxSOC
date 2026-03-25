# prompt_builder.py
# Location: layer_3_ai_analysis/prompt_builder.py

import json

SYSTEM_CONTEXT = """You are a Senior Lead Analyst at the Barclays SOC.
Analyze the security telemetry below and produce ONE high-fidelity incident report.

### ⚠️ CRITICAL OVERRIDE — EVALUATE THESE BEFORE ANY OTHER RULE:
These conditions VOID all Baseline & Maintenance rules. If ANY of these are true, you MUST
classify as malicious regardless of the user account name or transfer type:

1. External Threat Priority: If destination.ip does NOT start with "10.", "172.16.", or
   "192.168." (i.e., it is a public/external IP), the Baseline Maintenance rules are VOID.
   Classify as "high" or "critical" based on the tactic.

2. Blacklist Match: If threat_intel.ioc_matches is non-empty OR any field contains
   "blacklist", "malicious", "threat_hit", or "blocked", the activity is MALICIOUS.
   severity MUST be "critical". No exceptions.

3. Strict Account Check: Only accounts whose username starts with "svc_" or "backup_"
   qualify for Authorized Maintenance. Accounts like "jdoe_contractor", "admin", or any
   human/contractor account do NOT qualify — even if the action looks like a backup.

4. Context Contradiction Rule: If the telemetry simultaneously shows a "Blacklist Match"
   AND the destination looks like a backup target, the Blacklist Match ALWAYS wins.
   Classify as "critical" exfiltration, not maintenance.

### BASELINE & MAINTENANCE RULES (only apply if CRITICAL OVERRIDE conditions are all false):
1. Authorized Backups: If the source.user or affected_user starts with "svc_" or "backup_",
   AND the destination IP, host name, or event detail mentions "Vault", "Backup", or "Sync",
   AND the destination is an internal IP (10.x.x.x / 172.16.x.x / 192.168.x.x),
   classify as:
     intent: "Authorized Maintenance: Scheduled Backup" | severity: "informational"
   A high anomaly_score for a known service account doing its primary job is NOT a threat.
2. Internal Trust: If BOTH source and destination IPs are internal AND the activity matches
   a maintenance flag or scheduled window, cap severity at "low".
3. Anomaly Score ≠ Malice: High pyod_score alone does NOT justify escalation for known
   service accounts performing their normal function.

### CVSS v3.1 DERIVATION RULES:
1. AV (Attack Vector):
   - source.ip starts with "10.", "172.16.", or "192.168." → AV="A" (Adjacent)
   - Any other source IP (external/public) → AV="N" (Network)
   - Authorized maintenance with no network exposure → AV="L" (Local)
2. PR (Privileges Required):
   - Brute Force / no credentials → PR="N"
   - Authenticated service account → PR="L"
3. Impact (C/I/A):
   - Credential Access tactic → C="H", I="H", A="N"
   - Data Exfiltration to external → C="H", I="N", A="N"
   - Authorized internal transfer → C="N", I="N", A="N"

### SEVERITY ANCHORING:
- critical:       External exfiltration, blacklisted destination, or Core Banking compromise.
- high:           External brute force OR internal lateral movement by unknown user.
- medium:         Internal anomaly with no confirmed exfiltration.
- low:            Authorized internal activity by known users (scans, syncs).
- informational:  Scheduled jobs, verified service accounts (svc_*, backup_*).

### FEW-SHOT EXAMPLES:

EXAMPLE A — EXTERNAL BRUTE FORCE:
  source.ip: "185.192.69.5" | mitre_attack.tactic: "Credential Access"
  → intent: "External Brute Force — Credential Access" | severity: "high" | AV: "N" | C: "H"

EXAMPLE B — INTERNAL LATERAL MOVEMENT:
  source.ip: "10.0.3.18" | destination.ip: "10.50.1.5" | mitre_attack.tactic: "Lateral Movement"
  → intent: "Internal Lateral Movement via SSH" | severity: "high" | AV: "A"

EXAMPLE C — AUTHORIZED SCAN:
  source.user: "scanner_service" | correlation_hints.signal: "scheduled_scan"
  → intent: "Authorized Vulnerability Scan" | severity: "informational" | AV: "N"

EXAMPLE D — FALSE POSITIVE (Authorized Backup):
  source.user: "svc_backup_admin" | action: "High Volume Transfer" | detail: "rsync to BACKUP-VAULT"
  destination.ip: "10.10.5.20" (internal) | ioc_matches: []
  → intent: "Authorized Maintenance: Scheduled Backup"
  → severity: "informational"
  → cvss_vector: {"AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
  → narrative: "Service account svc_backup_admin performed a scheduled rsync to internal BACKUP-VAULT.
     This is legitimate maintenance activity verified by service account context and internal destination."

EXAMPLE E — TRUE POSITIVE (Exfiltration to Blacklisted IP):
  source.user: "jdoe_contractor" | destination.ip: "194.5.6.7" (external, blacklisted)
  ioc_matches: ["blacklist_hit"] | mitre_attack.tactic: "Exfiltration"
  → intent: "Data Exfiltration to Malicious External IP"
  → severity: "critical"
  → cvss_vector: {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"}
  → narrative: "High-risk exfiltration detected to known blacklisted destination 194.5.6.7 by
     non-service contractor account jdoe_contractor. Blacklist match overrides all maintenance context."
"""


def build_batch_analysis_prompt(batch_data: dict) -> str:
    """
    Builds the lean prompt for the new mitre_attack schema.
    No CIS violations, no legacy engine blocks — fast and focused.
    """
    events_summary = json.dumps(batch_data, indent=2)

    return f"""{SYSTEM_CONTEXT}

### TELEMETRY DATA:
{events_summary}

### REQUIRED OUTPUT — JSON ONLY, exactly these 5 keys:
{{
    "intent": "One-line title of the incident (e.g., External Brute Force — Credential Access)",
    "severity": "critical | high | medium | low | informational",
    "cvss_vector": {{
        "AV": "N or A or L or P",
        "AC": "L or H",
        "PR": "N or L or H",
        "UI": "N or R",
        "S":  "U or C",
        "C":  "N or L or H",
        "I":  "N or L or H",
        "A":  "N or L or H"
    }},
    "narrative": "2-sentence professional SOC summary referencing source IP and MITRE tactic.",
    "recommended_actions": ["Action 1", "Action 2", "Action 3"]
}}

RULES:
- Start with '{{' and end with '}}'.
- No markdown, no code fences, no extra keys.
- Derive AV from source IP: internal 10.x/172.16.x/192.168.x → AV="A", else AV="N"."""


#NOT NECESSARY:

'''

# ─────────────────────────────────────────
# NODE 1 — ANOMALY ANALYSIS PROMPT
# ─────────────────────────────────────────

def build_anomaly_prompt(incident_data: dict) -> str:

    anomaly_data = incident_data.get("engine_1_anomaly", {})
    raw_event    = incident_data.get("raw_event", {})
    behavioral   = incident_data.get("behavioral_features", {})
    temporal     = incident_data.get("time_windows", {})

    return f"""{SYSTEM_CONTEXT}

## ANOMALY DETECTION DATA
Anomaly Score (0.0-1.0): {anomaly_data.get('anomaly_score', 'N/A')}
PyOD Score: {anomaly_data.get('pyod_score', 'N/A')}
Is Outlier: {anomaly_data.get('is_outlier', 'N/A')}
UEBA Flags: {json.dumps(anomaly_data.get('ueba_flags', []))}
UEBA Risk Boost: {anomaly_data.get('ueba_risk_boost', 'N/A')}
Anomaly Flagged: {anomaly_data.get('anomaly_flagged', 'N/A')}

## RAW EVENT
Source IP: {raw_event.get('source_ip', 'N/A')}
Destination IP: {raw_event.get('destination_ip', 'N/A')}
Affected User: {raw_event.get('affected_user', 'N/A')}
Affected Host: {raw_event.get('affected_host', 'N/A')}
Port: {raw_event.get('port', 'N/A')}
Failed Attempts: {raw_event.get('failed_attempts', 'N/A')}
Process: {raw_event.get('process', 'N/A')}
Parent Process: {raw_event.get('parent_process', 'N/A')}

## BEHAVIORAL CONTEXT
Deviation Score: {behavioral.get('deviation_score', 'N/A')}
Is New IP For User: {behavioral.get('is_new_ip_for_user', 'N/A')}
Excessive Failed Logins: {behavioral.get('excessive_failed_logins', 'N/A')}
Is Off Hours: {temporal.get('is_off_hours', 'N/A')}
Time Of Day: {temporal.get('time_of_day', 'N/A')}

## YOUR TASK
You are performing anomaly-based threat reasoning.

Carefully analyze:
- Statistical anomaly scores (PyOD, anomaly_score)
- Behavioral signals (UEBA flags, deviation_score)
- Contextual indicators (off-hours activity, new IP usage)

DETERMINE:

1. ATTACK INTENT
- Failed logins + port 22 → SSH brute force / credential access
- Suspicious process chain → execution attempt
- Off-hours + new IP → unauthorized access attempt

2. CONFIDENCE LEVEL (STRICT RULES)
- HIGH:
  anomaly_score >= 0.85 AND (is_outlier == True OR UEBA flags present)
- MEDIUM:
  anomaly_score between 0.6 and 0.85
- LOW:
  anomaly_score < 0.6

3. REASONING
- One sentence ONLY
- Must reference anomaly signals

CONSTRAINTS:
- Do NOT guess
- Use ONLY provided data

Respond in this exact JSON format:
{{
    "attack_intent": "clear description",
    "confidence": "must be exactly one of: high, medium, low (lowercase only)",
    "reasoning": "one sentence tied to anomaly data"
}}"""


# ─────────────────────────────────────────
# NODE 2 — THREAT INTEL ANALYSIS PROMPT
# ─────────────────────────────────────────

def build_threat_intel_prompt(
        incident_data: dict,
        anomaly_analysis: dict
) -> str:

    threat_data = incident_data.get("engine_2_threat_intel", {})
    raw_event   = incident_data.get("raw_event", {})

    return f"""{SYSTEM_CONTEXT}

## ANOMALY ANALYSIS
Attack Intent: {anomaly_analysis.get('attack_intent', 'N/A')}
Confidence: {anomaly_analysis.get('confidence', 'N/A')}
Reasoning: {anomaly_analysis.get('reasoning', 'N/A')}

## THREAT INTELLIGENCE DATA
IOC Matches: {json.dumps(threat_data.get('ioc_matches', []))}
Threat Intel Match: {threat_data.get('threat_intel_match', False)}
MITRE Tactic: {threat_data.get('mitre_tactic', 'N/A')}
CIS Violations: {json.dumps(threat_data.get('cis_violations', []))}

## AFFECTED ASSETS CONTEXT
Source IP: {raw_event.get('source_ip', 'N/A')}
Affected User: {raw_event.get('affected_user', 'N/A')}
Affected Host: {raw_event.get('affected_host', 'N/A')}

## YOUR TASK
You are performing threat intelligence correlation.

DETERMINE:

1. ATTACK STAGE
- Use MITRE tactic + anomaly intent
- Multi-stage allowed → "Credential Access -> Execution"

2. KILL CHAIN POSITION (STRICT MAPPING)
- Credential Access → Stage 3 of 7 — Credential Access
- Execution → Stage 4 of 7 — Execution
- Privilege Escalation → Stage 5 of 7 — Privilege Escalation

RULES:

- If attack_stage contains multiple stages (e.g. "Credential Access -> Execution"):
    → kill_chain_position MUST reflect ONLY the FINAL stage
    → Example:
        "Credential Access -> Execution" → "Stage 4 of 7 — Execution"

- If attack_stage contains a single stage:
    → map directly using:
        Credential Access → Stage 3 of 7 — Credential Access
        Execution → Stage 4 of 7 — Execution
        Privilege Escalation → Stage 5 of 7 — Privilege Escalation

- attack_stage and kill_chain_position MUST NOT contradict each other

- Do NOT invent new stages
- Do NOT mix unrelated stages

3. AFFECTED ASSETS
Format:
- "user:name"
- "host:name"
- "ip:address"

Respond in this exact JSON format:
{{
    "attack_stage": "...",
    "kill_chain_position": "Stage X of 7 — exact stage name",
    "affected_assets": ["user:name", "host:name", "ip:address"]
}}"""


# ─────────────────────────────────────────
# NODE 3 — CORRELATION (UNCHANGED)
# ─────────────────────────────────────────

def build_correlation_prompt(
        incident_data: dict,
        anomaly_analysis: dict,
        threat_analysis: dict
) -> str:

    correlation_data = incident_data.get("engine_3_correlation", {})
    timeline         = correlation_data.get("attack_timeline", [])
    linked_events    = correlation_data.get("linked_events", [])

    return f"""{SYSTEM_CONTEXT}

## ANOMALY ANALYSIS
Attack Intent: {anomaly_analysis.get('attack_intent', 'N/A')}
Confidence: {anomaly_analysis.get('confidence', 'N/A')}

## THREAT ANALYSIS
Attack Stage: {threat_analysis.get('attack_stage', 'N/A')}
Kill Chain Position: {threat_analysis.get('kill_chain_position', 'N/A')}
Affected Assets: {json.dumps(threat_analysis.get('affected_assets', []))}

## CORRELATION DATA
Linked Events Count: {correlation_data.get('event_count', 0)}
Linked Events:
{json.dumps(linked_events, indent=2)}

## ATTACK TIMELINE
{json.dumps(timeline, indent=2)}

## YOUR TASK
Analyze correlation and timeline.

Respond in JSON:
{{
    "attack_sequence": "...",
    "scope": "...",
    "is_multi_stage": true or false
}}"""


# ─────────────────────────────────────────
# NODE 4 — NARRATIVE (UNCHANGED)
# ─────────────────────────────────────────

def build_narrative_prompt(
        incident_data: dict,
        anomaly_analysis: dict,
        threat_analysis: dict,
        correlation_analysis: dict
) -> str:

    raw_event = incident_data.get("raw_event", {})

    return f"""{SYSTEM_CONTEXT}

## COMPLETE ANALYSIS SUMMARY

Attack Intent: {anomaly_analysis.get('attack_intent', 'N/A')}
Confidence: {anomaly_analysis.get('confidence', 'N/A')}
Reasoning: {anomaly_analysis.get('reasoning', 'N/A')}

Attack Stage: {threat_analysis.get('attack_stage', 'N/A')}
Kill Chain Position: {threat_analysis.get('kill_chain_position', 'N/A')}
Affected Assets: {json.dumps(threat_analysis.get('affected_assets', []))}

Attack Sequence: {correlation_analysis.get('attack_sequence', 'N/A')}
Scope: {correlation_analysis.get('scope', 'N/A')}
Is Multi Stage: {correlation_analysis.get('is_multi_stage', 'N/A')}

## RAW EVENT CONTEXT
Source IP: {raw_event.get('source_ip', 'N/A')}
Affected User: {raw_event.get('affected_user', 'N/A')}
Affected Host: {raw_event.get('affected_host', 'N/A')}
Process: {raw_event.get('process', 'N/A')}
Parent Process: {raw_event.get('parent_process', 'N/A')}

## YOUR TASK

Write a complete SOC incident narrative.

REQUIREMENTS:
- 2 to 4 sentences
- Must explain what happened, who was affected, and why it is suspicious
- Must align with attack_stage and anomaly signals
- No assumptions beyond provided data

CRITICAL OUTPUT RULES:
- Output MUST be valid JSON
- Output ONLY the JSON object
- Do NOT include explanations, headers, or extra text
- Do NOT use markdown or code blocks

Respond in this exact JSON format:
{{
    "narrative": "complete 2-4 sentence incident narrative"
}}"""

# ─────────────────────────────────────────
# NODE 5 — RECOMMENDATIONS (FIXED)
# ─────────────────────────────────────────

def build_recommendations_prompt(
        incident_data: dict,
        narrative: str,
        threat_analysis: dict
) -> str:

    anomaly_data  = incident_data.get("engine_1_anomaly", {})
    anomaly_score = anomaly_data.get("anomaly_score", 0)
    raw_event     = incident_data.get("raw_event", {})

    return f"""{SYSTEM_CONTEXT}

## INCIDENT NARRATIVE
{narrative}

## THREAT CONTEXT
Attack Stage: {threat_analysis.get('attack_stage')}
Affected Assets: {json.dumps(threat_analysis.get('affected_assets', []))}

## YOUR TASK
Generate EXACTLY 4 SOC actions:

1. Containment (block IP / isolate host)
2. Account security (lock user)
3. Investigation (review logs)
4. Monitoring

RULES:
- Must include real asset names
- Must be executable
- NO generic actions

ESCALATION:
- anomaly_score >= 0.8 → true

id="fixrec1"
Respond in this exact JSON format:

{{
    "recommended_actions": [
        "Block IP 192.168.1.105 at firewall immediately",
        "Lock account john.doe and reset credentials",
        "Review authentication logs on host CORP-PC-042 for last 24 hours",
        "Enable monitoring alerts for repeated login attempts from 192.168.1.105"
    ],
    "escalate": true or false
}}

CRITICAL:
- Each item MUST be a STRING
- DO NOT return objects, dictionaries, or structured data
- DO NOT use keys like action_type
"""
def build_master_analysis_prompt(incident_data: dict) -> str:
    return f"""SYSTEM: You are a Tier-3 Cyber Security Architect for Barclays. 
TASK: Analyze the incident telemetry and return a CRITICAL VULNERABILITY REPORT in JSON.

DATA INPUT:
- Incident ID: {incident_data.get('incident_id')}
- Anomaly Score: {incident_data.get('engine_1_anomaly', {}).get('anomaly_score')}
- Evidence: {incident_data.get('raw_event')}
- Timeline: {incident_data.get('engine_3_correlation', {}).get('attack_timeline')}

REQUIRED OUTPUT FORMAT (JSON ONLY):
{{
    "attack_intent": "Specify the exact technique (e.g., C&C via PowerShell)",
    "attack_stage": "Describe the movement (e.g., Lateral movement detected)",
    "severity_recommendation": "critical/high/medium/low",
    "confidence": "high/medium/low",
    "cvss": {{
        "AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"
    }},
    "threat_summary": "Summarize logs (e.g., 500+ failed SSH attempts)",
    "cis_failed_rules": ["CIS-AUTH-001", "CIS-AUTH-003"],
    "narrative": "A 2-sentence professional SOC summary.",
    "recommended_actions": [
        "Action 1 with specific hostnames",
        "Action 2 with specific IPs"
    ],
    "escalate": true
}}

IMPORTANT: 
1. Calculate the CVSS vector based on the attack impact.
2. If anomaly_score > 0.7, severity must be 'critical'.
3. Return ONLY the JSON. No conversational text."""
'''