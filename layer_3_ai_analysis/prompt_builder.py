# prompt_builder.py
# Location: layer_3_ai_analysis/prompt_builder.py

import json

SYSTEM_CONTEXT = """You are a Senior Tier 3 SOC Analyst at Barclays.
Analyze the provided security telemetry, which includes the triggering alert and raw correlated logs. Determine if this is a true threat or a false positive.

CRITICAL RULES:
1. False Positive Checks:
   - If activity occurs on internal IPs (10.*, 172.16.*, 192.168.*) and involves users like "svc_*" or "backup_*", it is likely authorized.
   - If anomaly_score < 0.6 and there are no threat_intel matches, default to benign/informational.
2. Threat Checks:
   - Any external destination (not 10.*, 172.16.*, 192.168.*) with "exfiltration" or blacklisted IPs is a CRITICAL threat.
   - Multiple correlated events (e.g. brute force followed by success) indicate real compromise.
3. Professionalism & Citations:
   - Write like a professional incident responder. Do NOT use emojis. Do NOT use overly dramatic language.
   - You MUST cite specific log timestamps (e.g. "[T10:00:05.000]") in your narrative to prove your conclusion.

Respond ONLY in valid JSON format with NO markdown, preamble, or explanations.
"""

def extract_log_summary(evidence: list) -> str:
    """Takes raw ES logs and boils them down to a tight, token-efficient string."""
    if not evidence:
        return "None"
    
    lines = []
    # Cap at 25 events to save tokens
    for i, doc in enumerate(evidence[:25]):
        ts = doc.get("@timestamp", "")[-14:-1]  # Just HH:MM:SS.mmm
        raw = doc.get("raw_event", doc)
        action = raw.get("action", doc.get("event", {}).get("action", "unknown"))
        src = raw.get("source_ip", doc.get("source", {}).get("ip", ""))
        dst = raw.get("destination_ip", doc.get("destination", {}).get("ip", ""))
        user = raw.get("affected_user", doc.get("user", {}).get("name", ""))
        
        detail = []
        if action: detail.append(action)
        if src or dst: detail.append(f"{src}->{dst}")
        if user: detail.append(f"user:{user}")
        
        lines.append(f"[{ts}] {' '.join(detail)}")
        
    if len(evidence) > 25:
        lines.append(f"... and {len(evidence) - 25} more events.")
        
    return "\n".join(lines)


def build_batch_analysis_prompt(incident: dict) -> str:
    """
    Optimized prompt that feeds the LLM exactly what it needs to judge false positives vs true threats,
    using minimal tokens.
    """
    # Extract correlated evidence
    evidence = incident.get("correlated_evidence", [])
    log_summary = extract_log_summary(evidence)
    
    # Prune the main incident dict of the heavy raw evidence before dumping
    clean_incident = {k: v for k, v in incident.items() if k != "correlated_evidence"}
    # Remove timelines as they are redundant with the raw evidence summary
    if "engine_3_correlation" in clean_incident and "attack_timeline" in clean_incident["engine_3_correlation"]:
        del clean_incident["engine_3_correlation"]["attack_timeline"]

    telemetry = json.dumps(clean_incident, indent=2)

    return f"""{SYSTEM_CONTEXT}

### TRIGGERING TELEMETRY:
{telemetry}

### CORRELATED EVIDENCE (Raw Logs from a 5-min window):
{log_summary}

### REQUIRED OUTPUT (JSON ONLY):
{{
    "intent": "One of: WEB.SQLI | WEB.CMDI | WEB.LFI | WEB.XSS | WEB.SCANNER | WEB.SSRF | AUTH.BRUTE_FORCE | AUTH.PASSWORD_SPRAY | AUTH.MFA_FATIGUE | AUTH.PRIV_ABUSE | ENDPOINT.RANSOMWARE | ENDPOINT.LOLBIN | ENDPOINT.CRED_DUMP | ENDPOINT.DEF_EVASION | ENDPOINT.PERSISTENCE | NETWORK.PORT_SCAN | NETWORK.C2 | NETWORK.DNS_TUNNEL | NETWORK.EXFIL | NETWORK.LATERAL",
    "intent_label": "Human-readable description (e.g., 'SQL Injection', 'Brute Force (>20 fails)', 'C2 Beaconing')",
    "severity": "critical | high | medium | low | informational",
    "cvss_vector": {{
        "AV": "N/A/L/P (Attack Vector)", 
        "AC": "L/H (Attack Complexity)", 
        "PR": "N/L/H (Privileges Required)", 
        "UI": "N/R (User Interaction)", 
        "S": "U/C (Scope)", 
        "C": "H/L/N (CRITICAL: Must be H or L for actual threats)", 
        "I": "H/L/N (CRITICAL: Must be H or L for actual threats)", 
        "A": "H/L/N (CRITICAL: Must be H or L for actual threats)"
    }},
    "narrative": "A highly professional, multi-sentence executive summary. You MUST cite the exact log timestamps (e.g. [T10:05:01.000]) that support your conclusion.",
    "kibana_query": "An explicit Elasticsearch/KQL query string a human analyst can copy/paste to view these exact logs.",
    "recommended_actions": ["Action 1", "Action 2"]
}}"""


DORA_SYSTEM_CONTEXT = """You are a DORA Compliance Officer at Barclays.
Evaluate the incident against Article 18 criteria (C1-C6) and produce an Article 19 T+4h Initial Notification.
Output ALWAYS in pure JSON, no markdown.
"""

def build_dora_classification_prompt(incident_id: str, observables: dict, ai_analysis: dict, incident_data: dict) -> str:
    """Leaner prompt for DORA compliance."""
    context = {
        "incident_id": incident_id,
        "observables": observables,
        "ai_analysis": {
            "intent": ai_analysis.get("intent"),
            "severity": ai_analysis.get("severity")
        }
    }
    
    return f"""{DORA_SYSTEM_CONTEXT}
### CONTEXT:
{json.dumps(context, indent=2)}

### REQUIRED OUPUT (JSON ONLY):
{{
    "article_18_classification": {{
        "is_major_incident": true/false,
        "criteria_triggered": ["C1", "C3", "C4"],
        "criteria_evaluation": {{
            "C1_clients_affected": {{"triggered": true/false, "rationale": "..."}},
            "C2_duration": {{"triggered": true/false, "rationale": "..."}},
            "C3_data_loss": {{"triggered": true/false, "rationale": "..."}},
            "C4_criticality": {{"triggered": true/false, "rationale": "..."}},
            "C5_financial_loss": {{"triggered": true/false, "rationale": "..."}},
            "C6_geographical_spread": {{"triggered": true/false, "rationale": "..."}}
        }}
    }},
    "article_19_initial_notification": {{
        "notification_type": "T+4h Initial Notification",
        "incident_id": "{incident_id}",
        "lei": "BARCLAYS-LEI-213800LBQA1Y9L22JB70",
        "affected_services": ["..."],
        "initial_description": "...",
        "containment_status": "In Progress"
    }}
}}"""

def build_benchmark_analysis_prompt(incident: dict) -> str:
    """
    Prompt designed exclusively for complete methodology analysis and perfect counter-playbook generation,
    following the specific 4-Phase forensic structure.
    """
    evidence = incident.get("correlated_evidence", [])
    telemetry = json.dumps(evidence, indent=2)

    return f"""Role: You are a Senior Incident Response Handler and SOC Lead.

Task: Perform a deep forensic methodology analysis and generate a 4-Phase Incident Response Playbook based on the provided JSON logs.

Log Data:
{telemetry}


### EXPECTED STRUCTURE:

## 🚨 Incident Overview: [High-Level Threat Name]
* **Target User:** [UserPrincipalName or UserId]
* **Threat Actor IP:** [Suspicious IP Address]
* **Critical Actions:** [3-4 top defining factors/actions identified from the JSON]

---

## 🛠️ Phase 1: Preparation & Identification
*Detailed bullet points on how the breach was scoped and identified using the logs.*

## 🛡️ Phase 2: Containment
*Immediate actions to stop the attacker (e.g., account disabling, token revocation, firewall rules).*

## 🔍 Phase 3: Investigation & Eradication
*Deep dive into log audit, lateral movement checks, and cleaning the environment.*

## 📈 Phase 4: Recovery & Post-Incident
*Post-mortem steps, policy changes, and preventative training.*

### CRITICAL REQUIREMENTS:
*   NO Generic fluff.
*   NO CVSS scores or methodology metrics.
*   Mention the most critical defining factors of the attack EXPLICITLY derived from the JSON.
*   The response MUST be a highly professional, ready-to-use Markdown forensic report."""

def build_direct_l0_analysis_prompt(incident: dict) -> str:
    """
    Prompt for direct ingestion from Layer 0, bypassing intermediate processing.
    Focuses on raw log triage and rapid intent identification.
    """
    evidence = incident.get("correlated_evidence", [])
    log_summary = extract_log_summary(evidence)
    telemetry = json.dumps(incident, indent=2)

    return f"""You are a Tier 1/2 Triage Analyst receiving raw telemetry directly from ingestion.
Perform a rapid assessment of the provided logs to determine if immediate escalation is required.

### RAW TELEMETRY:
{telemetry}

### LOG SUMMARY:
{log_summary}

### REQUIRED OUTPUT (JSON ONLY):
{{
    "intent": "Rapid intent classification",
    "severity": "critical | high | medium | low",
    "narrative": "Brief summary of the raw findings and why this was flagged.",
    "is_immediate_escalation": true/false
}}"""