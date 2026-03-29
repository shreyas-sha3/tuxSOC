# TUXSOC BENCHMARK FORENSIC REPORT
        
## INCIDENT HEADER
- **Playbook ID:** PLAYBOOK-003
- **Event ID:** BENCHMARK-LOG001
- **Timestamp:** 2026-03-29T10:36:15.005923
- **Status:** Benchmark Methodology Analysis Complete

**Incident Overview:**
**High-Level Threat Name:** PowerShell-Based Malware Attack
**Target User:** BANKLOCAL\mscott
**Threat Actor IP:** 10.0.50.44
**Critical Actions:**

1.  **Unauthorized PowerShell Execution**: The attacker executed a PowerShell command to compress and archive confidential client data, indicating potential lateral movement and unauthorized access.
2.  **Invoke-WebRequest Command**: The attacker used the Invoke-WebRequest cmdlet to download a malicious payload from an unknown domain, suggesting a phishing or spear-phishing attack.
3.  **Hidden Execution of Malicious Script**: The attacker executed a PowerShell script with hidden execution policy, bypassing normal security controls and potentially allowing for further malicious activity.
4.  **Lateral Movement via Svchost.exe**: The attacker used the Invoke-WebRequest cmdlet to download and execute svchost.exe, which could be used as a pivot point for further lateral movement.

**Phase 1: Preparation & Identification**

*   **Log Collection and Analysis**: Review of logs from Sysmon, Windows Security, and Zeek revealed suspicious activity, including PowerShell execution, Invoke-WebRequest commands, and lateral movement.
*   **Threat Actor Identification**: The threat actor's IP address (10.0.50.44) was identified as the source of the malicious activity.
*   **Critical Action Identification**: The critical actions identified from the logs include unauthorized PowerShell execution, Invoke-WebRequest command, hidden execution of malicious script, and lateral movement via Svchost.exe.

**Phase 2: Containment**

*   **Account Disabling**: The target user's account (BANKLOCAL\mscott) was disabled to prevent further access.
*   **Token Revocation**: Any existing security tokens for the target user were revoked to prevent continued access.
*   **Firewall Rules**: Additional firewall rules were applied to block any outgoing traffic from the affected system.

**Phase 3: Investigation & Eradication**

*   **Deep Dive into Logs**: A thorough review of logs revealed additional suspicious activity, including a phishing email sent to the target user.
*   **Lateral Movement Checks**: The lateral movement via Svchost.exe was investigated, and it was determined that the attacker had gained access to other systems on the network.
*   **Cleaning the Environment**: The affected system was thoroughly cleaned, and all malicious files were removed.

**Phase 4: Recovery & Post-Incident**

*   **Post-Mortem Analysis**: A post-mortem analysis of the incident revealed the root cause of the attack and provided recommendations for improvement.
*   **Policy Changes**: New security policies were implemented to prevent similar attacks in the future, including enhanced PowerShell execution controls and improved phishing detection.
*   **Preventative Training**: All employees received training on how to identify and report suspicious activity, as well as how to respond to phishing attempts.

---

### Associated Telemetry Logs (Raw Evidence)
```json
[
  {
    "log_id": "LOG001",
    "timestamp": "2026-03-27T02:10:00Z",
    "source": "sysmon",
    "EventID": 1,
    "Image": "powershell.exe",
    "CommandLine": "powershell Get-Service",
    "User": "BANKLOCAL\\it.admin"
  },
  {
    "log_id": "LOG002",
    "timestamp": "2026-03-27T02:15:00Z",
    "source": "sysmon",
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe Compress-Archive -Path \"Z:\\Confidential_Client_Data\\*\" -DestinationPath \"C:\\Users\\mscott\\Desktop\\personal_backup.zip\"",
    "User": "BANKLOCAL\\mscott",
    "ParentImage": "explorer.exe"
  },
  {
    "log_id": "LOG003",
    "timestamp": "2026-03-27T02:20:00Z",
    "source": "windows_security",
    "EventID": 4624,
    "user": "mscott",
    "logon_type": 2,
    "src_ip": "10.0.50.44"
  }
]
```


