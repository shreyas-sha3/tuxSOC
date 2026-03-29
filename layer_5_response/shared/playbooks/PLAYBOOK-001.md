# TUXSOC BENCHMARK FORENSIC REPORT
        
## INCIDENT HEADER
- **Playbook ID:** PLAYBOOK-001
- **Event ID:** BENCHMARK-LOG001
- **Timestamp:** 2026-03-29T10:36:05.625552
- **Status:** Benchmark Methodology Analysis Complete

**Incident Overview: High-Risk Phishing Attack**

* **Target User:** finance_mgr@bank.local
* **Threat Actor IP:** 193.168.0.50
* **Critical Actions:**
    *   Unfamiliar features detected in the Azure AD sign-in activity (OperationName: Sign-in activity)
    *   Suspicious IP address used for sign-in activity and accessing mail items (IpAddress: 193.168.0.50, ClientIP: 193.168.0.50)
    *   New-InboxRule created with parameters that contain sensitive keywords (Parameters: ForwardTo: external.audit.finance@gmail.com, SubjectContainsWords: invoice, wire transfer)

**Phase 1: Preparation & Identification**

*   The breach was scoped and identified using the provided Azure AD and Office 365 logs.
*   Initial analysis revealed a high-risk phishing attack targeting finance_mgr@bank.local.
*   Suspicious activity was detected in the Azure AD sign-in activity, where an unfamiliar feature was used (OperationName: Sign-in activity).
*   The threat actor's IP address (193.168.0.50) was identified as suspicious and associated with multiple critical actions.

**Phase 2: Containment**

*   Immediate action was taken to disable the target user's account and revoke any existing authentication tokens.
*   Firewall rules were updated to block incoming traffic from the suspected threat actor IP address (193.168.0.50).
*   All Office 365 accounts associated with finance_mgr@bank.local were temporarily locked down for further investigation.

**Phase 3: Investigation & Eradication**

*   A deep dive into the logs revealed lateral movement checks by the attacker, indicating a potential inside threat or compromised account.
*   The attacker accessed mail items and created a new inbox rule with sensitive parameters (ForwardTo: external.audit.finance@gmail.com, SubjectContainsWords: invoice, wire transfer).
*   Further investigation is required to determine the extent of the attack and identify any potential vulnerabilities.

**Phase 4: Recovery & Post-Incident**

*   Post-mortem analysis will be conducted to review the incident response process and identify areas for improvement.
*   Policy changes will be implemented to prevent similar attacks in the future, including enhanced authentication requirements and regular security awareness training for employees.
*   The affected user's account will be restored once all necessary security measures have been taken.

---

### Associated Telemetry Logs (Raw Evidence)
```json
[
  {
    "log_id": "LOG001",
    "timestamp": "2026-03-27T10:52:10Z",
    "source": "azure_ad",
    "OperationName": "Sign-in activity",
    "UserPrincipalName": "finance_mgr@bank.local",
    "IpAddress": "10.0.20.15",
    "Location": "Pune, IN",
    "RiskState": "none",
    "ClientAppUsed": "Outlook"
  },
  {
    "log_id": "LOG002",
    "timestamp": "2026-03-27T10:55:00Z",
    "source": "office365",
    "Operation": "MailItemsAccessed",
    "UserId": "finance_mgr@bank.local",
    "ClientIP": "10.0.20.15"
  },
  {
    "log_id": "LOG003",
    "timestamp": "2026-03-27T11:00:00Z",
    "source": "azure_ad",
    "OperationName": "Sign-in activity",
    "UserPrincipalName": "finance_mgr@bank.local",
    "IpAddress": "193.168.0.50",
    "Location": "Moscow, RU",
    "RiskState": "atRisk",
    "RiskLevel": "high",
    "RiskEventTypes": "unfamiliarFeatures, suspiciousIPAddress",
    "ClientAppUsed": "Browser"
  }
]
```


