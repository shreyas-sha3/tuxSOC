import requests
import json
import time

# 1. The Mock Input from Ingestion/Detection (Layer 2)
raw_incident = [
  {
    "incident_id": "INC-2026-0328-SOC-001-FP-BACKUP",
    "timestamp": "2026-03-28T02:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.1.50",
      "destination_ip": "10.0.5.100",
      "affected_user": "svc_backup_admin",
      "affected_host": "BACKUP-VAULT-01",
      "port": 22,
      "protocol": "ssh",
      "action": "High Volume Transfer (rsync) - 500GB",
      "timestamp": "2026-03-28T02:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9812,
      "is_outlier": True,
      "ueba_flags": ["unusual_volume", "off_hours_activity"],
      "anomaly_score": 0.9500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Collection",
      "mitre_technique": "T1119",
      "mitre_technique_name": "Automated Collection"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": [
        {"timestamp": "2026-03-28T02:00:00Z", "event": "anomaly_detected", "detail": "Massive internal data movement detected."}
      ]
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-002-TP-EXFIL",
    "timestamp": "2026-03-28T14:15:22Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.50.10.5",
      "destination_ip": "194.5.6.7",
      "affected_user": "jdoe_contractor",
      "affected_host": "FIN-WORKSTATION-05",
      "port": 443,
      "protocol": "https",
      "action": "Continuous outbound stream to unknown external IP",
      "timestamp": "2026-03-28T14:15:22Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8900,
      "is_outlier": True,
      "ueba_flags": ["first_time_destination"],
      "anomaly_score": 0.8900,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": ["blacklist_hit_194.5.6.7"],
      "threat_intel_match": True,
      "mitre_tactic": "Exfiltration",
      "mitre_technique": "T1048",
      "mitre_technique_name": "Exfiltration Over Alternative Protocol"
    },
    "engine_3_correlation": {
      "event_count": 2,
      "attack_timeline": [
        {"timestamp": "2026-03-28T14:15:00Z", "event": "threat_intel_match", "detail": "Connection to known malicious IP."}
      ]
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-003-FP-SCANNER",
    "timestamp": "2026-03-28T04:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.99.5",
      "destination_ip": "10.0.1.0/24",
      "affected_user": "scanner_service",
      "affected_host": "QUALYS-SCANNER",
      "port": 0,
      "protocol": "tcp",
      "action": "TCP SYN Port Sweep across 254 hosts",
      "timestamp": "2026-03-28T04:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9999,
      "is_outlier": True,
      "ueba_flags": ["high_connection_rate"],
      "anomaly_score": 0.9500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Discovery",
      "mitre_technique": "T1046",
      "mitre_technique_name": "Network Service Discovery"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-004-TP-LATMOV",
    "timestamp": "2026-03-28T09:22:11Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.3.15",
      "destination_ip": "10.0.5.22",
      "affected_user": "admin",
      "affected_host": "CORP-DC-01",
      "port": 3389,
      "protocol": "rdp",
      "action": "Successful RDP login from non-admin subnet",
      "timestamp": "2026-03-28T09:22:11Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8122,
      "is_outlier": True,
      "ueba_flags": ["new_host_for_user", "lateral_movement_pattern"],
      "anomaly_score": 0.8200,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Lateral Movement",
      "mitre_technique": "T1021.001",
      "mitre_technique_name": "Remote Desktop Protocol"
    },
    "engine_3_correlation": {
      "event_count": 3,
      "attack_timeline": [
        {"timestamp": "2026-03-28T09:20:00Z", "event": "auth_failure", "detail": "Failed RDP attempt on DC-01"},
        {"timestamp": "2026-03-28T09:22:11Z", "event": "auth_success", "detail": "Successful RDP login"}
      ]
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-005-TP-LOLBIN",
    "timestamp": "2026-03-28T11:05:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.4.55",
      "destination_ip": "10.0.4.55",
      "affected_user": "r.kim",
      "affected_host": "laptop-rkim",
      "port": None,
      "protocol": "local",
      "action": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz...",
      "timestamp": "2026-03-28T11:05:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8800,
      "is_outlier": True,
      "ueba_flags": ["suspicious_process_arguments"],
      "anomaly_score": 0.8800,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Execution",
      "mitre_technique": "T1059.001",
      "mitre_technique_name": "PowerShell"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-006-DORA-SWIFT",
    "timestamp": "2026-03-28T01:30:00Z",
    "log_type": "database",
    "raw_event": {
      "source_ip": "10.10.1.5",
      "destination_ip": "10.50.10.10",
      "affected_user": "db_admin",
      "affected_host": "SWIFT-GATEWAY-DB",
      "port": 1521,
      "protocol": "sql",
      "action": "Massive DROP TABLE and DELETE queries out of hours",
      "timestamp": "2026-03-28T01:30:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9200,
      "is_outlier": True,
      "ueba_flags": ["destructive_action", "off_hours_activity"],
      "anomaly_score": 0.9500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1485",
      "mitre_technique_name": "Data Destruction"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-007-FP-SCCM",
    "timestamp": "2026-03-28T03:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.1.20",
      "destination_ip": "10.0.2.0/24",
      "affected_user": "SYSTEM",
      "affected_host": "SCCM-SERVER",
      "port": 445,
      "protocol": "smb",
      "action": "Concurrent SMB connections to 200 hosts pushing .msi packages",
      "timestamp": "2026-03-28T03:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8500,
      "is_outlier": False,
      "ueba_flags": ["high_volume_transfer"],
      "anomaly_score": 0.8000,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Lateral Movement",
      "mitre_technique": "T1021.002",
      "mitre_technique_name": "SMB/Windows Admin Shares"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-008-TP-STUFFING",
    "timestamp": "2026-03-28T16:20:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "185.192.69.5",
      "destination_ip": "10.0.1.10",
      "affected_user": "multiple_users",
      "affected_host": "VPN-GATEWAY",
      "port": 443,
      "protocol": "https",
      "action": "15,000 failed login attempts across 500 accounts in 10 minutes",
      "timestamp": "2026-03-28T16:20:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9900,
      "is_outlier": True,
      "ueba_flags": ["credential_stuffing_pattern"],
      "anomaly_score": 0.9900,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": ["blacklist_hit_185.192.69.5"],
      "threat_intel_match": True,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110.004",
      "mitre_technique_name": "Credential Stuffing"
    },
    "engine_3_correlation": {
      "event_count": 15000,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-009-EDGE-TRAVEL",
    "timestamp": "2026-03-28T10:00:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "114.114.114.114",
      "destination_ip": "10.0.1.10",
      "affected_user": "ceo_smith",
      "affected_host": "O365-SSO",
      "port": 443,
      "protocol": "https",
      "action": "Successful login from China 1 hour after successful login from USA",
      "timestamp": "2026-03-28T10:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8500,
      "is_outlier": True,
      "ueba_flags": ["impossible_travel", "new_country"],
      "anomaly_score": 0.8500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1078",
      "mitre_technique_name": "Valid Accounts"
    },
    "engine_3_correlation": {
      "event_count": 2,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-010-TP-RANSOMWARE",
    "timestamp": "2026-03-28T18:45:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.4.12",
      "destination_ip": "10.0.4.12",
      "affected_user": "t.jones",
      "affected_host": "laptop-tjones",
      "port": None,
      "protocol": "local",
      "action": "Rapid file modification and extension change (.encrypted) across 5000 files",
      "timestamp": "2026-03-28T18:45:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9999,
      "is_outlier": True,
      "ueba_flags": ["mass_file_modification", "ransomware_behavior"],
      "anomaly_score": 0.9900,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1486",
      "mitre_technique_name": "Data Encrypted for Impact"
    },
    "engine_3_correlation": {
      "event_count": 5000,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-011-EDGE-FAILED",
    "timestamp": "2026-03-28T20:00:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "45.45.45.45",
      "destination_ip": "10.0.1.15",
      "affected_user": "root",
      "affected_host": "DMZ-WEB",
      "port": 22,
      "protocol": "ssh",
      "action": "5 failed SSH logins from external IP. All blocked by fail2ban.",
      "timestamp": "2026-03-28T20:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.4000,
      "is_outlier": False,
      "ueba_flags": [],
      "anomaly_score": 0.4000,
      "anomaly_flagged": False
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "mitre_technique_name": "Brute Force"
    },
    "engine_3_correlation": {
      "event_count": 5,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-012-TP-DNSTUNNEL",
    "timestamp": "2026-03-28T11:11:11Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.3.50",
      "destination_ip": "8.8.8.8",
      "affected_user": "unknown",
      "affected_host": "laptop-099",
      "port": 53,
      "protocol": "dns",
      "action": "Continuous outbound DNS TXT records with high entropy payload",
      "timestamp": "2026-03-28T11:11:11Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9500,
      "is_outlier": True,
      "ueba_flags": ["dns_tunneling_pattern"],
      "anomaly_score": 0.9500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Command and Control",
      "mitre_technique": "T1071.004",
      "mitre_technique_name": "DNS"
    },
    "engine_3_correlation": {
      "event_count": 500,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-013-FP-MAINTENANCE",
    "timestamp": "2026-03-28T23:55:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.1.5",
      "destination_ip": "10.50.1.10",
      "affected_user": "svc_db_maint",
      "affected_host": "CORE-DB-01",
      "port": 1433,
      "protocol": "sql",
      "action": "Service account interactive login to Core Banking DB off-hours",
      "timestamp": "2026-03-28T23:55:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.7000,
      "is_outlier": False,
      "ueba_flags": ["off_hours_activity"],
      "anomaly_score": 0.7000,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1078",
      "mitre_technique_name": "Valid Accounts"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-014-TP-WEBSHELL",
    "timestamp": "2026-03-28T05:45:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.2.10",
      "destination_ip": "10.0.2.10",
      "affected_user": "www-data",
      "affected_host": "EXT-WEB-SRV",
      "port": None,
      "protocol": "local",
      "action": "Process spawning cmd.exe from IIS worker process w3wp.exe",
      "timestamp": "2026-03-28T05:45:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9800,
      "is_outlier": True,
      "ueba_flags": ["suspicious_process_tree"],
      "anomaly_score": 0.9800,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Persistence",
      "mitre_technique": "T1505.003",
      "mitre_technique_name": "Web Shell"
    },
    "engine_3_correlation": {
      "event_count": 2,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-015-FP-PROXY",
    "timestamp": "2026-03-28T12:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.1.254",
      "destination_ip": "8.8.8.8",
      "affected_user": "unknown",
      "affected_host": "WEB-PROXY-01",
      "port": 443,
      "protocol": "https",
      "action": "Massive outbound traffic from single internal IP",
      "timestamp": "2026-03-28T12:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.6500,
      "is_outlier": False,
      "ueba_flags": ["high_volume_outbound"],
      "anomaly_score": 0.6500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Exfiltration",
      "mitre_technique": "T1048",
      "mitre_technique_name": "Exfiltration Over Alternative Protocol"
    },
    "engine_3_correlation": {
      "event_count": 10000,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-016-TP-DOMAINADMIN",
    "timestamp": "2026-03-28T15:30:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.4.15",
      "destination_ip": "10.0.1.5",
      "affected_user": "domain_admin",
      "affected_host": "CORP-DC-01",
      "port": 389,
      "protocol": "ldap",
      "action": "50 failed logins for domain_admin from non-IT workstation",
      "timestamp": "2026-03-28T15:30:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8500,
      "is_outlier": True,
      "ueba_flags": ["privileged_account_abuse", "unusual_source"],
      "anomaly_score": 0.8800,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "mitre_technique_name": "Brute Force"
    },
    "engine_3_correlation": {
      "event_count": 50,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-017-FP-MISCONFIG",
    "timestamp": "2026-03-28T10:15:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.2.55",
      "destination_ip": "10.0.1.15",
      "affected_user": "svc_app_reader",
      "affected_host": "INTERNAL-API",
      "port": 443,
      "protocol": "https",
      "action": "5000 failed logins. Account locked. Password expired.",
      "timestamp": "2026-03-28T10:15:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9500,
      "is_outlier": True,
      "ueba_flags": ["high_failure_rate"],
      "anomaly_score": 0.9500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1110",
      "mitre_technique_name": "Brute Force"
    },
    "engine_3_correlation": {
      "event_count": 5000,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-018-TP-CRYPTOMINER",
    "timestamp": "2026-03-28T01:00:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.3.33",
      "destination_ip": "10.0.3.33",
      "affected_user": "SYSTEM",
      "affected_host": "DEV-SERVER-02",
      "port": None,
      "protocol": "local",
      "action": "Process xmrig.exe utilizing 100% CPU for 4 hours",
      "timestamp": "2026-03-28T01:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8900,
      "is_outlier": True,
      "ueba_flags": ["resource_exhaustion", "known_malware_name"],
      "anomaly_score": 0.8900,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1496",
      "mitre_technique_name": "Resource Hijacking"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-019-FP-PENTEST",
    "timestamp": "2026-03-28T14:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.99.100",
      "destination_ip": "10.50.10.10",
      "affected_user": "unknown",
      "affected_host": "CORE-BANKING-APP",
      "port": 443,
      "protocol": "https",
      "action": "SQL Injection payload detected in URI parameter",
      "timestamp": "2026-03-28T14:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8000,
      "is_outlier": True,
      "ueba_flags": ["sqli_pattern"],
      "anomaly_score": 0.8000,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1190",
      "mitre_technique_name": "Exploit Public-Facing Application",
      "cis_violations": [{"rule_id": "PENTEST-AUTHORIZED", "cvss_impact": {"metric": "C", "escalate_to": "N"}}]
    },
    "engine_3_correlation": {
      "event_count": 50,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-020-TP-KERBEROAST",
    "timestamp": "2026-03-28T10:45:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.4.15",
      "destination_ip": "10.0.1.5",
      "affected_user": "j.smith",
      "affected_host": "CORP-DC-01",
      "port": 88,
      "protocol": "kerberos",
      "action": "Multiple TGS tickets requested for SPNs within 5 seconds",
      "timestamp": "2026-03-28T10:45:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9100,
      "is_outlier": True,
      "ueba_flags": ["kerberoasting_pattern"],
      "anomaly_score": 0.9100,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1558.003",
      "mitre_technique_name": "Kerberoasting"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-021-TP-WEIRD-OUTBOUND",
    "timestamp": "2026-03-28T02:15:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.2.10",
      "destination_ip": "203.0.113.50",
      "affected_user": "unknown",
      "affected_host": "WEB-SERVER-02",
      "port": 22,
      "protocol": "ssh",
      "action": "Outbound SSH connection from internal web server to external IP",
      "timestamp": "2026-03-28T02:15:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8600,
      "is_outlier": True,
      "ueba_flags": ["outbound_ssh", "server_initiating_connection"],
      "anomaly_score": 0.8600,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Command and Control",
      "mitre_technique": "T1090",
      "mitre_technique_name": "Proxy"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-022-TP-CRONJOB",
    "timestamp": "2026-03-28T04:30:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.3.30",
      "destination_ip": "10.0.3.30",
      "affected_user": "root",
      "affected_host": "DB-REPLICA-02",
      "port": None,
      "protocol": "local",
      "action": "Cron job created to execute /tmp/update.sh every minute",
      "timestamp": "2026-03-28T04:30:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.7800,
      "is_outlier": True,
      "ueba_flags": ["suspicious_cron", "tmp_execution"],
      "anomaly_score": 0.7800,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Persistence",
      "mitre_technique": "T1053.003",
      "mitre_technique_name": "Cron"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-023-TP-PHISHING",
    "timestamp": "2026-03-28T09:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.4.18",
      "destination_ip": "10.0.1.25",
      "affected_user": "s.williams",
      "affected_host": "laptop-swilliams",
      "port": 25,
      "protocol": "smtp",
      "action": "User workstation acting as open relay, sending 500 emails/min",
      "timestamp": "2026-03-28T09:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9300,
      "is_outlier": True,
      "ueba_flags": ["unauthorized_smtp"],
      "anomaly_score": 0.9300,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Impact",
      "mitre_technique": "T1498",
      "mitre_technique_name": "Network Denial of Service"
    },
    "engine_3_correlation": {
      "event_count": 500,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-024-TP-LOGCLEAR",
    "timestamp": "2026-03-28T03:33:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.0.5.10",
      "destination_ip": "10.0.5.10",
      "affected_user": "SYSTEM",
      "affected_host": "PAYMENT-GW-01",
      "port": None,
      "protocol": "local",
      "action": "wevtutil.exe cl Security (Security Event Log Cleared)",
      "timestamp": "2026-03-28T03:33:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9900,
      "is_outlier": True,
      "ueba_flags": ["defense_evasion", "log_clearing"],
      "anomaly_score": 0.9900,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Defense Evasion",
      "mitre_technique": "T1070.001",
      "mitre_technique_name": "Clear Windows Event Logs"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-025-EDGE-WEIRDTIME",
    "timestamp": "2026-03-28T04:15:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.4.50",
      "destination_ip": "10.0.1.10",
      "affected_user": "k.lee",
      "affected_host": "VPN-GATEWAY",
      "port": 443,
      "protocol": "https",
      "action": "Successful login at 4:15 AM local time",
      "timestamp": "2026-03-28T04:15:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.6500,
      "is_outlier": True,
      "ueba_flags": ["off_hours_activity"],
      "anomaly_score": 0.6500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1078",
      "mitre_technique_name": "Valid Accounts"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-026-TP-BEACONING",
    "timestamp": "2026-03-28T12:00:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.4.18",
      "destination_ip": "45.33.22.11",
      "affected_user": "unknown",
      "affected_host": "laptop-008",
      "port": 443,
      "protocol": "https",
      "action": "HTTPS POST request exactly every 3600 seconds",
      "timestamp": "2026-03-28T12:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9000,
      "is_outlier": True,
      "ueba_flags": ["periodic_beaconing"],
      "anomaly_score": 0.9000,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Command and Control",
      "mitre_technique": "T1071.001",
      "mitre_technique_name": "Web Protocols"
    },
    "engine_3_correlation": {
      "event_count": 24,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-027-TP-SVC-INTERACTIVE",
    "timestamp": "2026-03-28T10:30:00Z",
    "log_type": "auth",
    "raw_event": {
      "source_ip": "10.0.3.15",
      "destination_ip": "10.0.5.20",
      "affected_user": "svc_iis_worker",
      "affected_host": "INT-WEB-02",
      "port": 3389,
      "protocol": "rdp",
      "action": "Interactive RDP login using Web Service account",
      "timestamp": "2026-03-28T10:30:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9400,
      "is_outlier": True,
      "ueba_flags": ["service_account_interactive"],
      "anomaly_score": 0.9400,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Lateral Movement",
      "mitre_technique": "T1078.002",
      "mitre_technique_name": "Domain Accounts"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-028-TP-INTERNAL-SCAN",
    "timestamp": "2026-03-28T13:45:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.4.99",
      "destination_ip": "10.0.1.0/24",
      "affected_user": "unknown",
      "affected_host": "laptop-guest",
      "port": 445,
      "protocol": "tcp",
      "action": "SMB scanning across internal subnet from guest Wi-Fi",
      "timestamp": "2026-03-28T13:45:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8800,
      "is_outlier": True,
      "ueba_flags": ["internal_scanning", "guest_network_violation"],
      "anomaly_score": 0.8800,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Discovery",
      "mitre_technique": "T1046",
      "mitre_technique_name": "Network Service Discovery"
    },
    "engine_3_correlation": {
      "event_count": 254,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-029-TP-STAGING",
    "timestamp": "2026-03-28T16:00:00Z",
    "log_type": "endpoint",
    "raw_event": {
      "source_ip": "10.50.10.5",
      "destination_ip": "10.50.10.5",
      "affected_user": "m.scott",
      "affected_host": "FIN-WORKSTATION-05",
      "port": None,
      "protocol": "local",
      "action": "7zip used to compress 50GB of Excel files into C:\\PerfLogs\\dump.zip",
      "timestamp": "2026-03-28T16:00:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.8500,
      "is_outlier": True,
      "ueba_flags": ["data_staging", "unusual_directory"],
      "anomaly_score": 0.8500,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Collection",
      "mitre_technique": "T1074.001",
      "mitre_technique_name": "Local Data Staging"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": []
    }
  },
  {
    "incident_id": "INC-2026-0328-SOC-030-TP-WMI",
    "timestamp": "2026-03-28T17:30:00Z",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.3.15",
      "destination_ip": "10.0.5.100",
      "affected_user": "admin",
      "affected_host": "CORP-SERVER-02",
      "port": 135,
      "protocol": "rpc",
      "action": "WMI remote execution triggered (WmiPrvSE.exe spawned cmd.exe)",
      "timestamp": "2026-03-28T17:30:00Z"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.9200,
      "is_outlier": True,
      "ueba_flags": ["wmi_remote_execution"],
      "anomaly_score": 0.9200,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": [],
      "threat_intel_match": False,
      "mitre_tactic": "Execution",
      "mitre_technique": "T1047",
      "mitre_technique_name": "Windows Management Instrumentation"
    },
    "engine_3_correlation": {
      "event_count": 2,
      "attack_timeline": []
    }
  }
]

print("🚀 [TEST] Firing Simulated Incident into Layer 3 (AI Analysis)...")

try:
    # 2. Hit Layer 3 (Send the whole list!)
    l3_response = requests.post("http://localhost:8001/analyze", json=raw_incident)
    
    # SAFETY NET: Check for 202 ACCEPTED (not 200)
    if l3_response.status_code == 202:
        l3_data = l3_response.json()
        print(f"✅ [LAYER 3 SUCCESS] {l3_data.get('message')}")
        print("\n🔥 PIPELINE IS ACTIVE! The GPU is now processing the batch.")
        print("👀 Watch the other terminal windows to see Layer 4 and Layer 5 execute in real-time.")
    else:
        print(f"❌ [LAYER 3 FAILED] Status {l3_response.status_code}: {l3_response.text}")
        
except requests.exceptions.ConnectionError as e:
    print(f"\n❌ [CONNECTION ERROR] Are all your servers running?")
    print("Ensure you have 3 terminals running:")
    print("1. python -m layer_3_ai_analysis.ai_orchestrator (Port 8001)")
    print("2. python -m layer_4_cvss.cvss_orchestrator (Port 8004)")
    print("3. python -m layer_5_response.response_orchestrator (Port 8005)")
except Exception as e:
    print(f"\n❌ [ERROR] An unexpected error occurred: {e}")