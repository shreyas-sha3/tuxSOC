import time
from typing import Dict

def execute_firewall_block(ip_address: str) -> Dict:
    """
    Simulates blocking an IP address on a firewall (Palo Alto/Fortinet).

    Args:
        ip_address (str): The IP address to block.

    Returns:
        dict: A dictionary containing the action details, target IP, status, and timestamp.
    """
    # Check for invalid IP
    if ip_address in ["Unknown", "0.0.0.0"]:
        print(f"🚫 Invalid IP address: {ip_address}. Skipping firewall block.")
        return {
            "action": "firewall_block",
            "target_ip": ip_address,
            "status": "FAILED",
            "reason": "Invalid IP address",
            "timestamp": time.time()
        }

    # Simulate API call delay
    print(f"🛡️ Initiating API call to firewall to block IP: {ip_address}...")
    time.sleep(1)  # Simulate network delay

    # Simulate success (in a real scenario, this would be the actual API response)
    print(f"🛑 SUCCESS: IP {ip_address} blocked on firewall.")
    return {
        "action": "firewall_block",
        "target_ip": ip_address,
        "status": "SUCCESS",
        "timestamp": time.time()
    }

def send_soc_alert(event_id: str, severity: str) -> Dict:
    """
    Simulates sending a critical alert to a SOC notification system (Slack/Discord webhook).

    Args:
        event_id (str): The unique identifier for the security event.
        severity (str): The severity level of the incident.

    Returns:
        dict: A dictionary containing the alert details and status.
    """
    # Map severity to emoji and urgency
    severity_config = {
        "CRITICAL": ("🔴", "CRITICAL"),
        "HIGH": ("🟠", "HIGH"),
        "MEDIUM": ("🟡", "MEDIUM"),
        "LOW": ("🟢", "LOW"),
        "UNKNOWN": ("⚪", "UNKNOWN")
    }

    emoji, level = severity_config.get(severity.upper(), ("⚪", "UNKNOWN"))

    print(f"\n{emoji} {'='*50}")
    print(f"{emoji} URGENT SOC ALERT: {event_id}")
    print(f"{emoji} Severity: {level}")
    print(f"{emoji} Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{emoji} {'='*50}\n")

    # Simulate API call delay
    time.sleep(0.5)  # Simulate network latency for webhook

    print(f"📢 Alert successfully sent to SOC notification channels!")

    return {
        "action": "soc_alert",
        "event_id": event_id,
        "severity": severity,
        "status": "SENT",
        "timestamp": time.time()
    }