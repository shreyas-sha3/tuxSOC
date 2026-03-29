# TUXSOC BENCHMARK FORENSIC REPORT
        
## INCIDENT HEADER
- **Playbook ID:** PLAYBOOK-007
- **Event ID:** BENCHMARK-LOG001
- **Timestamp:** 2026-03-29T10:36:28.019048
- **Status:** Benchmark Methodology Analysis Complete

**Incident Overview:**
High-Level Threat Name: **PowerShell Malware Attack**

* Target User: it.admin
* Threat Actor IP: 10.0.20.10
* Critical Actions:
    * PowerShell execution with elevated privileges (BANKLOCAL\svc_jenkins)
    * VSSAdmin.exe deletion of oldest shadows (BANKLOCAL\svc_jenkins)
    * Unusual network activity via Zeek (dest_ip: 52.216.146.19, dest_port: 443)

**Phase 1: Preparation & Identification**

* The breach was scoped and identified using the logs by analyzing the PowerShell execution with elevated privileges, VSSAdmin.exe deletion of oldest shadows, and unusual network activity via Zeek.
* The logs revealed a suspicious user (BANKLOCAL\svc_jenkins) executing PowerShell scripts with elevated privileges, indicating potential lateral movement.
* The VSSAdmin.exe deletion of oldest shadows suggests an attempt to wipe or destroy data.

**Phase 2: Containment**

* Immediate actions to stop the attacker:
    * Disable the suspicious user account (it.admin)
    * Revoke any tokens or credentials associated with the suspicious user
    * Block outgoing network traffic on ports 443 and other potentially affected ports
    * Run a full system scan using antivirus software

**Phase 3: Investigation & Eradication**

* Deep dive into log audit:
    + Analyze PowerShell execution logs to identify any suspicious commands or scripts
    + Investigate the VSSAdmin.exe deletion of oldest shadows to determine if it was used for data wiping or destruction
    + Examine Zeek network activity logs to understand the scope and impact of the attack
* Lateral movement checks:
    + Identify any other users or systems that may have been compromised by the attacker
    + Verify if any sensitive data has been accessed or exfiltrated
* Cleaning the environment:
    + Remove any suspicious files, scripts, or executables from the system
    + Update and patch all affected systems to prevent similar attacks in the future

**Phase 4: Recovery & Post-Incident**

* Post-mortem steps:
    + Conduct a thorough review of the incident response plan and identify areas for improvement
    + Document lessons learned and implement changes to prevent similar incidents
* Policy changes:
    + Update user account management policies to ensure proper access control and monitoring
    + Implement additional security measures, such as multi-factor authentication and network segmentation
* Preventative training:
    + Provide training to users on safe PowerShell practices and the importance of reporting suspicious activity
    + Conduct regular security awareness training for all employees

---

### Associated Telemetry Logs (Raw Evidence)
```json
[
  {
    "log_id": "LOG001",
    "timestamp": "2026-03-27T01:55:00Z",
    "source": "windows_security",
    "EventID": 4624,
    "user": "it.admin",
    "logon_type": 2,
    "src_ip": "10.0.20.10"
  },
  {
    "log_id": "LOG002",
    "timestamp": "2026-03-27T02:00:15Z",
    "source": "sysmon",
    "EventID": 1,
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\\\IT_Ops\\\\Scripts\\\\Nightly-CloudBackup.ps1",
    "User": "BANKLOCAL\\\\svc_jenkins",
    "ParentImage": "C:\\\\Program Files\\\\Jenkins\\\\jenkins.exe"
  },
  {
    "log_id": "LOG003",
    "timestamp": "2026-03-27T02:02:00Z",
    "source": "sysmon",
    "EventID": 1,
    "Image": "powershell.exe",
    "CommandLine": "powershell Get-Date",
    "User": "BANKLOCAL\\\\svc_jenkins"
  }
]
```


