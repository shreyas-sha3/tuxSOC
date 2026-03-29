import os
import datetime
from typing import Dict, List

def generate_markdown_playbook(incident_data: Dict, recommendations: List[str]) -> str:
    """
    Generates a Markdown playbook file for the incident.

    Args:
        incident_data (dict): The incident data from Layer 5 input.
        recommendations (list): List of recommended next steps from action_recommender.

    Returns:
        str: The file path of the generated playbook.
    """
    # Create shared/playbooks directory if it doesn't exist
    playbooks_dir = os.path.join(os.path.dirname(__file__), 'shared', 'playbooks')
    os.makedirs(playbooks_dir, exist_ok=True)

    # Extract relevant data from incident_data
    event_id = incident_data.get("event_id", "unknown")
    base_score = incident_data.get("base_score", 0.0)
    severity = incident_data.get("severity", "UNKNOWN")
    intent = incident_data.get("intent", "Unknown Threat")
    attacker_ip = incident_data.get("attacker_ip", "Unknown")
    affected_entity = incident_data.get("affected_entity", "Unknown")

    # Severity badge mapping
    severity_badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "UNKNOWN": "⚪ UNKNOWN"
    }
    severity_badge = severity_badges.get(severity.upper(), "⚪ UNKNOWN")

    # Generate playbook ID and timestamp
    timestamp = datetime.datetime.now().isoformat()
    playbook_id = f"PLAY-{event_id}"

    # Define the file path
    file_name = f"{playbook_id}.md"
    file_path = os.path.join(playbooks_dir, file_name)
    
    kibana_query = incident_data.get("kibana_query", f'\"{attacker_ip}\"')
    import urllib.parse
    kibana_link = f"http://localhost:5601/app/discover#/?_g=(time:(from:now-15m,to:now))&_a=(query:(language:kuery,query:'{urllib.parse.quote(kibana_query)}'))"

    # Check if this is a benchmark sequence with a raw playbook
    playbook_raw = incident_data.get("playbook_raw")
    is_benchmark = (intent in ["BENCHMARK_SIMULATION", "BENCHMARK_METHODOLOGY_STUDY"]) or playbook_raw is not None

    # Generate the markdown content
    if is_benchmark and playbook_raw:
        markdown_content = f"""# TUXSOC BENCHMARK FORENSIC REPORT
        
## INCIDENT HEADER
- **Playbook ID:** {playbook_id}
- **Event ID:** {event_id}
- **Timestamp:** {timestamp}
- **Status:** Benchmark Methodology Analysis Complete

{playbook_raw}

---
"""
    else:
        markdown_content = f"""# TUXSOC INCIDENT RESPONSE PLAYBOOK

## INCIDENT HEADER
- **Playbook ID:** {playbook_id}
- **Event ID:** {event_id}
- **Timestamp:** {timestamp}
- **Severity:** [{severity}]
- **CVSS Score:** {base_score}/10.0

## THREAT INTENT
**{intent}**

## AFFECTED ASSETS & TELEMETRY
- **Attacker IP:** {attacker_ip}
- **Affected Entity:** {affected_entity}

[>>> View in Kibana Dashboard <<<]({kibana_link})
"""

    related_logs = incident_data.get("related_logs", [])
    if related_logs:
        import json
        markdown_content += "\n### Associated Telemetry Logs (Raw Evidence)\n```json\n"
        markdown_content += json.dumps(related_logs[:3], indent=2)
        markdown_content += "\n```\n"

    markdown_content += """

"""

    dora_compliance = incident_data.get("dora_compliance")
    if dora_compliance:
        article_18 = dora_compliance.get("article_18_classification", {})
        article_19 = dora_compliance.get("article_19_initial_notification", {})
        is_major = article_18.get("is_major_incident")
        notif_type = article_19.get("notification_type", "Unknown")
        
        markdown_content += f"""
## EU DORA REGULATORY STATUS
- **Article 18 Status:** Major Incident: {is_major}
- **Article 19 Notification Type:** {notif_type}
"""

    if not is_benchmark:
        markdown_content += """
## RECOMMENDED ANALYST STEPS
"""

        # Add recommendations with checkboxes
        for i, rec in enumerate(recommendations, 1):
            markdown_content += f"{i}. [ ] {rec}\n"

        markdown_content += f"""
## AUTOMATED ACTIONS EXECUTED
*(This section will be populated by the orchestration layer with actions taken)*
"""

    # Write the playbook to a Markdown file
    with open(file_path, 'w') as f:
        f.write(markdown_content)

    print(f"[L5-RESPONSE] Playbook generated: {file_path}")
    return file_path