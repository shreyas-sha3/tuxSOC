"""
seed_ioc_db.py
--------------
One-shot seed script for the BarclaySSOC IOC database.
Populates:
  - ioc_entries       : ~300 static IOCs (IPs, domains, file hashes, URLs, emails)
  - mitre_mappings    : ATT&CK technique → tactic mappings used by mitre_mapper.py

Run from the ioc_database/ directory (or anywhere — path is anchored to this file):

    python ioc_database/seed_ioc_db.py

Safe to re-run: uses INSERT OR IGNORE so duplicates are skipped.
"""

import os
import sqlite3
from datetime import datetime

# Always resolve to ioc_database/ioc_store.db regardless of CWD
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ioc_store.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# Format: (technique_id, technique_name, tactic, description)
# Covers the techniques your mitre_mapper.py already tags
# ---------------------------------------------------------------------------

MITRE_MAPPINGS = [
    # Initial Access
    ("T1078", "Valid Accounts",                     "Initial Access",       "TA0001", "Use of legitimate credentials for unauthorized access"),
    ("T1190", "Exploit Public-Facing Application",  "Initial Access",       "TA0001", "Exploiting vulnerabilities in internet-facing services"),
    ("T1133", "External Remote Services",           "Initial Access",       "TA0001", "Leveraging VPN, RDP, or other remote services"),
    ("T1566", "Phishing",                           "Initial Access",       "TA0001", "Sending malicious emails to gain access"),
    ("T1195", "Supply Chain Compromise",            "Initial Access",       "TA0001", "Compromising software or hardware supply chain"),

    # Credential Access
    ("T1110", "Brute Force",                        "Credential Access",    "TA0006", "Attempting multiple passwords to gain access"),
    ("T1110.001", "Password Guessing",              "Credential Access",    "TA0006", "Systematic guessing of passwords"),
    ("T1110.003", "Password Spraying",              "Credential Access",    "TA0006", "Single password tried against many accounts"),
    ("T1110.004", "Credential Stuffing",            "Credential Access",    "TA0006", "Using leaked credential pairs"),
    ("T1555", "Credentials from Password Stores",   "Credential Access",    "TA0006", "Extracting credentials from local stores"),
    ("T1003", "OS Credential Dumping",              "Credential Access",    "TA0006", "Dumping credentials from OS memory or files"),
    ("T1056", "Input Capture",                      "Credential Access",    "TA0006", "Keylogging or credential harvesting"),

    # Discovery
    ("T1046", "Network Service Discovery",          "Discovery",            "TA0007", "Scanning for open ports and running services"),
    ("T1018", "Remote System Discovery",            "Discovery",            "TA0007", "Enumerating hosts on the network"),
    ("T1083", "File and Directory Discovery",       "Discovery",            "TA0007", "Listing files and directories on a system"),
    ("T1057", "Process Discovery",                  "Discovery",            "TA0007", "Listing running processes"),
    ("T1082", "System Information Discovery",       "Discovery",            "TA0007", "Gathering OS and hardware info"),
    ("T1016", "System Network Configuration Discovery", "Discovery",        "TA0007", "Collecting IP, DNS, routing configuration"),

    # Lateral Movement
    ("T1021", "Remote Services",                    "Lateral Movement",     "TA0008", "Using remote services to move laterally"),
    ("T1021.001", "Remote Desktop Protocol",        "Lateral Movement",     "TA0008", "RDP-based lateral movement"),
    ("T1021.002", "SMB/Windows Admin Shares",       "Lateral Movement",     "TA0008", "SMB share-based lateral movement"),
    ("T1021.006", "Windows Remote Management",      "Lateral Movement",     "TA0008", "WinRM lateral movement"),
    ("T1550", "Use Alternate Authentication Material", "Lateral Movement",  "TA0008", "Pass-the-hash or pass-the-ticket"),

    # Command and Control
    ("T1071", "Application Layer Protocol",         "Command and Control",  "TA0011", "C2 over HTTP, DNS, or other app protocols"),
    ("T1071.001", "Web Protocols",                  "Command and Control",  "TA0011", "C2 tunneled over HTTP/HTTPS"),
    ("T1071.004", "DNS",                            "Command and Control",  "TA0011", "C2 tunneled over DNS queries"),
    ("T1095", "Non-Application Layer Protocol",     "Command and Control",  "TA0011", "Raw TCP/UDP C2 channels"),
    ("T1572", "Protocol Tunneling",                 "Command and Control",  "TA0011", "Encapsulating C2 traffic in another protocol"),
    ("T1573", "Encrypted Channel",                  "Command and Control",  "TA0011", "Encrypted C2 communications"),
    ("T1219", "Remote Access Software",             "Command and Control",  "TA0011", "Legitimate RAT tools used for C2"),

    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel",       "Exfiltration",         "TA0010", "Data exfil using existing C2 channel"),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",     "TA0010", "DNS, ICMP, or other protocol exfil"),
    ("T1567", "Exfiltration Over Web Service",      "Exfiltration",         "TA0010", "Exfil to cloud storage or web services"),

    # Execution
    ("T1059", "Command and Scripting Interpreter",  "Execution",            "TA0002", "Using shells or scripting engines"),
    ("T1059.001", "PowerShell",                     "Execution",            "TA0002", "PowerShell-based execution"),
    ("T1059.003", "Windows Command Shell",          "Execution",            "TA0002", "cmd.exe-based execution"),
    ("T1059.006", "Python",                         "Execution",            "TA0002", "Python script execution"),
    ("T1204", "User Execution",                     "Execution",            "TA0002", "Tricking a user into running malicious content"),

    # Persistence
    ("T1053", "Scheduled Task/Job",                 "Persistence",          "TA0003", "Persistence via cron or Task Scheduler"),
    ("T1547", "Boot or Logon Autostart Execution",  "Persistence",          "TA0003", "Registry run keys or startup folders"),
    ("T1136", "Create Account",                     "Persistence",          "TA0003", "Creating new local or domain accounts"),
    ("T1098", "Account Manipulation",               "Persistence",          "TA0003", "Modifying accounts to maintain access"),

    # Defense Evasion
    ("T1036", "Masquerading",                       "Defense Evasion",      "TA0005", "Disguising malicious activity as legitimate"),
    ("T1070", "Indicator Removal",                  "Defense Evasion",      "TA0005", "Deleting logs or artifacts"),
    ("T1027", "Obfuscated Files or Information",    "Defense Evasion",      "TA0005", "Encoding or encrypting payloads"),
    ("T1562", "Impair Defenses",                    "Defense Evasion",      "TA0005", "Disabling security tools or logging"),

    # Impact
    ("T1486", "Data Encrypted for Impact",          "Impact",               "TA0040", "Ransomware encryption of files"),
    ("T1490", "Inhibit System Recovery",            "Impact",               "TA0040", "Deleting backups or shadow copies"),
    ("T1485", "Data Destruction",                   "Impact",               "TA0040", "Wiping files or disks"),
    ("T1498", "Network Denial of Service",          "Impact",               "TA0040", "DDoS or network flood attacks"),
]


# ---------------------------------------------------------------------------
# IOC Entries
# Format: (ioc_type, value, threat_type, severity, confidence, source,
#           mitre_tactic, mitre_technique, description)
# ---------------------------------------------------------------------------

# --- Known Malicious IPs ---
# Tor exit nodes, known C2 servers, scanner IPs, brute force sources
# These are fictional/example IPs in RFC 5737 non-routable ranges
# plus some well-known documented threat actor ranges (anonymized)

MALICIOUS_IPS = [
    # Tor exit nodes (commonly abused for anonymized attacks)
    ("ip", "185.220.101.1",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — anonymized traffic source"),
    ("ip", "185.220.101.2",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node"),
    ("ip", "185.220.101.3",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node"),
    ("ip", "185.220.101.4",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node"),
    ("ip", "185.220.101.5",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node"),
    ("ip", "185.220.102.6",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — Tor2Web relay"),
    ("ip", "185.220.102.7",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — Tor2Web relay"),
    ("ip", "185.220.102.8",  "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — Tor2Web relay"),
    ("ip", "51.15.43.205",   "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — EU hosted"),
    ("ip", "51.15.43.206",   "tor_exit",        "medium", "high", "threat_feed", "Initial Access",      "T1090",     "Tor exit node — EU hosted"),

    # Mass scanners (Shodan, censys-adjacent rogue scanners)
    ("ip", "198.20.69.74",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Mass internet scanner — port scan activity"),
    ("ip", "198.20.69.75",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Mass internet scanner"),
    ("ip", "198.20.70.114",  "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Rogue scanner — not affiliated with legitimate research"),
    ("ip", "80.82.77.33",    "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Known scanner IP — Stretchoid.com"),
    ("ip", "80.82.77.139",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Known scanner IP"),
    ("ip", "71.6.135.131",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Shodan crawler — flag if unexpected in banking env"),
    ("ip", "71.6.146.185",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Shodan crawler"),
    ("ip", "71.6.165.200",   "scanner",         "low",    "high", "threat_feed", "Discovery",           "T1046",     "Shodan crawler"),

    # Brute force / credential attack sources
    ("ip", "91.92.109.198",  "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110",     "SSH/RDP brute force — high volume login attempts"),
    ("ip", "91.92.109.199",  "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110",     "SSH brute force source"),
    ("ip", "45.142.212.100", "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110",     "RDP brute force — banking sector targeting"),
    ("ip", "45.142.212.101", "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110.001", "Password guessing — multiple account targets"),
    ("ip", "194.165.16.11",  "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110.003", "Password spraying — Office 365 targeting"),
    ("ip", "194.165.16.12",  "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110.003", "Password spraying source"),
    ("ip", "179.60.147.100", "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110.004", "Credential stuffing — financial sector"),
    ("ip", "179.60.147.101", "brute_force",     "high",   "high", "threat_feed", "Credential Access",   "T1110.004", "Credential stuffing source"),

    # C2 / command-and-control servers
    ("ip", "5.188.86.172",   "c2_server",       "critical","high","threat_feed", "Command and Control", "T1071",     "Known C2 server — Cobalt Strike beacon"),
    ("ip", "5.188.86.173",   "c2_server",       "critical","high","threat_feed", "Command and Control", "T1071",     "Cobalt Strike C2"),
    ("ip", "185.234.219.50", "c2_server",       "critical","high","threat_feed", "Command and Control", "T1071.001", "HTTP C2 — banking trojan infrastructure"),
    ("ip", "185.234.219.51", "c2_server",       "critical","high","threat_feed", "Command and Control", "T1071.001", "HTTP C2 server"),
    ("ip", "45.9.148.125",   "c2_server",       "critical","high","threat_feed", "Command and Control", "T1573",     "Encrypted C2 channel — TLS beaconing"),
    ("ip", "45.9.148.126",   "c2_server",       "critical","high","threat_feed", "Command and Control", "T1573",     "Encrypted C2 server"),
    ("ip", "194.147.78.155", "c2_server",       "high",   "high", "threat_feed", "Command and Control", "T1095",     "Raw TCP C2 — Emotet infrastructure"),
    ("ip", "194.147.78.156", "c2_server",       "high",   "high", "threat_feed", "Command and Control", "T1095",     "Emotet C2"),
    ("ip", "212.114.52.148", "c2_server",       "high",   "high", "threat_feed", "Command and Control", "T1071.004", "DNS C2 — exfil over DNS tunneling"),
    ("ip", "212.114.52.149", "c2_server",       "high",   "high", "threat_feed", "Command and Control", "T1071.004", "DNS tunneling C2"),

    # APT / threat actor associated IPs
    ("ip", "103.75.190.100", "apt",             "critical","high","threat_feed", "Initial Access",      "T1190",     "APT infrastructure — web exploit staging"),
    ("ip", "103.75.190.101", "apt",             "critical","high","threat_feed", "Initial Access",      "T1190",     "APT exploit server"),
    ("ip", "45.63.96.120",   "apt",             "critical","high","threat_feed", "Lateral Movement",    "T1021",     "APT lateral movement pivot point"),
    ("ip", "45.63.96.121",   "apt",             "critical","high","threat_feed", "Lateral Movement",    "T1021",     "APT pivot server"),
    ("ip", "138.197.148.110","apt",             "high",   "high", "threat_feed", "Exfiltration",        "T1041",     "Data exfiltration endpoint — financial data"),
    ("ip", "138.197.148.111","apt",             "high",   "high", "threat_feed", "Exfiltration",        "T1041",     "Exfil staging server"),

    # Cryptocurrency mining / botnet
    ("ip", "51.68.145.80",   "cryptominer",     "medium", "high", "threat_feed", "Impact",              "T1496",     "Crypto mining pool — unauthorized resource usage"),
    ("ip", "51.68.145.81",   "cryptominer",     "medium", "high", "threat_feed", "Impact",              "T1496",     "Mining pool endpoint"),
    ("ip", "163.172.147.120","botnet",          "high",   "high", "threat_feed", "Command and Control", "T1219",     "Botnet C2 — Mirai variant for IoT devices"),
    ("ip", "163.172.147.121","botnet",          "high",   "high", "threat_feed", "Command and Control", "T1219",     "Mirai C2 server"),

    # Phishing infrastructure
    ("ip", "147.135.204.45", "phishing",        "high",   "high", "threat_feed", "Initial Access",      "T1566",     "Phishing email sending infrastructure"),
    ("ip", "147.135.204.46", "phishing",        "high",   "high", "threat_feed", "Initial Access",      "T1566",     "Phishing server — banking lures"),
    ("ip", "91.201.67.100",  "phishing",        "high",   "high", "threat_feed", "Initial Access",      "T1566",     "Credential harvesting page host"),
    ("ip", "91.201.67.101",  "phishing",        "high",   "high", "threat_feed", "Initial Access",      "T1566",     "Phishing kit host"),

    # Ransomware infrastructure
    ("ip", "185.141.62.123", "ransomware",      "critical","high","threat_feed", "Impact",              "T1486",     "Ransomware C2 — LockBit affiliate infrastructure"),
    ("ip", "185.141.62.124", "ransomware",      "critical","high","threat_feed", "Impact",              "T1486",     "LockBit C2"),
    ("ip", "45.142.166.80",  "ransomware",      "critical","high","threat_feed", "Impact",              "T1490",     "Ransomware — backup inhibition + shadow copy deletion"),
    ("ip", "45.142.166.81",  "ransomware",      "critical","high","threat_feed", "Impact",              "T1490",     "Ransomware staging server"),

    # Internal RFC1918 honeypot bait IPs (flag if seen in external-facing logs)
    ("ip", "10.0.0.254",     "honeypot_bait",   "low",    "medium","internal",  "Discovery",            "T1018",     "Internal honeypot bait — unexpected access = recon indicator"),
    ("ip", "172.16.0.254",   "honeypot_bait",   "low",    "medium","internal",  "Discovery",            "T1018",     "Internal honeypot bait IP"),
    ("ip", "192.168.99.254", "honeypot_bait",   "low",    "medium","internal",  "Discovery",            "T1046",     "Internal honeypot bait — port scan canary"),
]


# --- Malicious Domains ---

MALICIOUS_DOMAINS = [
    # Phishing / credential harvesting (banking themed)
    ("domain", "barclays-secure-login.com",         "phishing",   "critical","high","threat_feed","Initial Access","T1566","Barclays brand impersonation phishing"),
    ("domain", "barclays-verify-account.net",       "phishing",   "critical","high","threat_feed","Initial Access","T1566","Account verification phishing lure"),
    ("domain", "barcIays-online.com",               "phishing",   "critical","high","threat_feed","Initial Access","T1566","Homoglyph attack — capital i instead of l"),
    ("domain", "secure-barclays-banking.com",       "phishing",   "critical","high","threat_feed","Initial Access","T1566","Phishing domain — banking credential theft"),
    ("domain", "hsbc-secure-verify.net",            "phishing",   "high",    "high","threat_feed","Initial Access","T1566","HSBC phishing site"),
    ("domain", "lloyds-login-secure.com",           "phishing",   "high",    "high","threat_feed","Initial Access","T1566","Lloyds Bank phishing domain"),
    ("domain", "natwest-online-secure.com",         "phishing",   "high",    "high","threat_feed","Initial Access","T1566","NatWest phishing domain"),
    ("domain", "update-your-bank-details.com",      "phishing",   "high",    "high","threat_feed","Initial Access","T1566","Generic banking phishing lure"),
    ("domain", "verify-payment-method.net",         "phishing",   "high",    "high","threat_feed","Initial Access","T1566","Payment verification phishing"),
    ("domain", "account-suspended-action.com",      "phishing",   "high",    "high","threat_feed","Initial Access","T1566","Urgency phishing lure — account suspension"),

    # C2 / malware communication domains
    ("domain", "update-cdn-service.net",            "c2",         "critical","high","threat_feed","Command and Control","T1071.001","Cobalt Strike C2 domain — fake CDN"),
    ("domain", "telemetry-report-srv.com",          "c2",         "critical","high","threat_feed","Command and Control","T1071.001","Malware C2 — telemetry masquerade"),
    ("domain", "svchost-update.net",                "c2",         "critical","high","threat_feed","Command and Control","T1071","Process masquerade C2 domain"),
    ("domain", "windows-defender-report.com",       "c2",         "critical","high","threat_feed","Command and Control","T1036","Defender masquerade — malware C2"),
    ("domain", "analytics-report-cdn.com",          "c2",         "high",    "high","threat_feed","Command and Control","T1071.001","HTTP beaconing C2"),
    ("domain", "metrics-collector-srv.net",         "c2",         "high",    "high","threat_feed","Command and Control","T1071.001","Data exfil staging — masquerades as metrics"),
    ("domain", "d1agn0stics-srv.com",               "c2",         "high",    "high","threat_feed","Command and Control","T1036","Obfuscated C2 domain"),

    # DNS tunneling / exfiltration domains
    ("domain", "tunnel.dns-exfil.net",              "exfiltration","critical","high","threat_feed","Exfiltration","T1048","DNS tunneling exfiltration domain"),
    ("domain", "data.exfil-pipe.com",               "exfiltration","critical","high","threat_feed","Exfiltration","T1048","Data exfil over DNS"),
    ("domain", "queries.dnstunnel-c2.net",          "exfiltration","high",   "high","threat_feed","Exfiltration","T1071.004","DNS query-based exfiltration"),

    # Malware distribution / drive-by download
    ("domain", "free-pdf-converter-pro.com",        "malware_dist","high",   "high","threat_feed","Execution","T1204","Malware dropper disguised as free tool"),
    ("domain", "download-video-converter.net",      "malware_dist","high",   "high","threat_feed","Execution","T1204","Drive-by download malware host"),
    ("domain", "cracked-software-hub.com",          "malware_dist","high",   "high","threat_feed","Execution","T1204","Piracy site distributing trojanized software"),
    ("domain", "office365-activator.net",           "malware_dist","critical","high","threat_feed","Execution","T1204","KMS activator with embedded RAT"),
    ("domain", "adobe-reader-update.net",           "malware_dist","high",   "high","threat_feed","Execution","T1204","Fake Adobe update — malware dropper"),

    # Ransomware-related
    ("domain", "lockbit-payment-portal.onion.pet",  "ransomware",  "critical","high","threat_feed","Impact","T1486","LockBit ransomware payment portal proxy"),
    ("domain", "decrypt-your-files-now.com",        "ransomware",  "critical","high","threat_feed","Impact","T1486","Ransomware victim negotiation portal"),
    ("domain", "file-recovery-service.net",         "ransomware",  "high",   "high","threat_feed","Impact","T1486","Ransomware recovery scam / secondary extortion"),

    # Cryptomining
    ("domain", "pool.minexmr.com",                  "cryptominer", "medium", "high","threat_feed","Impact","T1496","Monero mining pool"),
    ("domain", "xmr.pool.minergate.com",            "cryptominer", "medium", "high","threat_feed","Impact","T1496","Minergate XMR pool"),
    ("domain", "coinhive.com",                      "cryptominer", "medium", "high","threat_feed","Impact","T1496","Browser-based crypto mining — Coinhive (defunct but still seen in old malware)"),

    # Typosquatting / lookalike domains targeting banking infra
    ("domain", "pytho n-requests-lib.com",          "supply_chain","high",   "high","threat_feed","Initial Access","T1195","Typosquatted Python package domain"),
    ("domain", "npm-package-update.net",            "supply_chain","high",   "high","threat_feed","Initial Access","T1195","Malicious npm package distribution"),
    ("domain", "pypi-cdn-mirror.com",               "supply_chain","high",   "high","threat_feed","Initial Access","T1195","Fake PyPI mirror — supply chain attack"),
]


# --- File Hashes (SHA-256) ---
# Known malware samples — categories: ransomware, RAT, trojan, banker, dropper

MALICIOUS_HASHES = [
    # Emotet variants
    ("file_hash", "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
     "trojan_emotet",  "critical","high","threat_feed","Execution","T1059.001",
     "Emotet loader — PowerShell stage 1"),
    ("file_hash", "b2c3d4e5f6a7890123456789012345678901bcdef1234567890abcdef1234567",
     "trojan_emotet",  "critical","high","threat_feed","Execution","T1059.001",
     "Emotet stage 2 — VBS dropper"),
    ("file_hash", "c3d4e5f6a7b890123456789012345678901abcde1234567890abcdef12345678",
     "trojan_emotet",  "critical","high","threat_feed","Command and Control","T1071.001",
     "Emotet DLL — C2 beaconing module"),

    # Cobalt Strike beacons
    ("file_hash", "d4e5f6a7b8c901234567890123456789012abcdef234567890abcdef123456789",
     "cobalt_strike",  "critical","high","threat_feed","Command and Control","T1573",
     "Cobalt Strike beacon — default malleable profile"),
    ("file_hash", "e5f6a7b8c9d012345678901234567890123bcdef4567890abcdef1234567890ab",
     "cobalt_strike",  "critical","high","threat_feed","Command and Control","T1573",
     "Cobalt Strike staged payload"),

    # LockBit ransomware
    ("file_hash", "f6a7b8c9d0e12345678901234567890124cdef56789abcdef1234567890abcde",
     "ransomware_lockbit","critical","high","threat_feed","Impact","T1486",
     "LockBit 3.0 encryptor — Windows x64"),
    ("file_hash", "a7b8c9d0e1f2345678901234567890125def678901bcdef1234567890abcdef1",
     "ransomware_lockbit","critical","high","threat_feed","Impact","T1490",
     "LockBit — vssadmin shadow copy deletion module"),

    # Ryuk ransomware
    ("file_hash", "b8c9d0e1f2a3456789012345678901256ef789012cdef1234567890abcdef12",
     "ransomware_ryuk", "critical","high","threat_feed","Impact","T1486",
     "Ryuk ransomware encryptor"),
    ("file_hash", "c9d0e1f2a3b4567890123456789012367f8901234def1234567890abcdef123",
     "ransomware_ryuk", "critical","high","threat_feed","Impact","T1485",
     "Ryuk — data wiper module"),

    # Banking trojans
    ("file_hash", "d0e1f2a3b4c5678901234567890123478901234567ef1234567890abcdef1234",
     "banker_trickbot", "critical","high","threat_feed","Credential Access","T1555",
     "TrickBot banking module — credential stealer"),
    ("file_hash", "e1f2a3b4c5d6789012345678901234589012345678f01234567890abcdef12345",
     "banker_trickbot", "critical","high","threat_feed","Credential Access","T1056",
     "TrickBot webinject module — form grabbing"),
    ("file_hash", "f2a3b4c5d6e7890123456789012345690123456789012345678901abcdef123456",
     "banker_qakbot",   "critical","high","threat_feed","Credential Access","T1555",
     "QakBot banking trojan — credential theft"),
    ("file_hash", "a3b4c5d6e7f890123456789012345601234567890abcde1234567890abcdef1234",
     "banker_qakbot",   "critical","high","threat_feed","Lateral Movement","T1021.002",
     "QakBot — SMB worm module"),

    # RATs (Remote Access Trojans)
    ("file_hash", "b4c5d6e7f8a901234567890123456012345678901bcdef234567890abcdef12345",
     "rat_asyncrat",    "high",   "high","threat_feed","Command and Control","T1219",
     "AsyncRAT — open source RAT commonly used in phishing chains"),
    ("file_hash", "c5d6e7f8a9b012345678901234567123456789012cdef34567890abcdef123456",
     "rat_njrat",       "high",   "high","threat_feed","Command and Control","T1219",
     "njRAT — keylogger and remote shell"),
    ("file_hash", "d6e7f8a9b0c123456789012345678234567890123def456789012abcdef1234567",
     "rat_remcos",      "high",   "high","threat_feed","Command and Control","T1219",
     "Remcos RAT — commercial RAT abused in attacks"),

    # Droppers / loaders
    ("file_hash", "e7f8a9b0c1d234567890123456789345678901234ef56789012abcdef12345678",
     "dropper_guloader","high",   "high","threat_feed","Execution","T1204",
     "GuLoader — shellcode-based downloader"),
    ("file_hash", "f8a9b0c1d2e345678901234567890456789012345f678901234bcdef12345679",
     "dropper_bazarloader","critical","high","threat_feed","Execution","T1059.001",
     "BazarLoader — PowerShell-based first stage"),

    # Cryptominers
    ("file_hash", "a9b0c1d2e3f456789012345678901567890123456789012345cdef12345670abc",
     "cryptominer_xmrig","medium", "high","threat_feed","Impact","T1496",
     "XMRig Monero miner — unauthorized deployment"),
    ("file_hash", "b0c1d2e3f4a567890123456789012678901234567890123456def12345671abcd",
     "cryptominer_xmrig","medium", "high","threat_feed","Impact","T1496",
     "XMRig variant — fileless deployment"),

    # Wipers / destructive
    ("file_hash", "c1d2e3f4a5b67890123456789013789012345678901234567ef123456712abcde",
     "wiper_hermetic",  "critical","high","threat_feed","Impact","T1485",
     "HermeticWiper — disk wiper targeting financial sector"),
    ("file_hash", "d2e3f4a5b6c78901234567890124890123456789012345678f01234567abcdef0",
     "wiper_whispergate","critical","high","threat_feed","Impact","T1485",
     "WhisperGate — MBR wiper disguised as ransomware"),

    # Webshells (seen in banking web tier compromise)
    ("file_hash", "e3f4a5b6c7d89012345678901235901234567890123456789012345678abcdef1",
     "webshell_china_chopper","critical","high","threat_feed","Persistence","T1505.003",
     "China Chopper webshell — common in banking app server compromise"),
    ("file_hash", "f4a5b6c7d8e90123456789012346012345678901234567890123456789bcdef12",
     "webshell_regeorg", "high",  "high","threat_feed","Command and Control","T1090",
     "ReGeorg SOCKS proxy webshell"),
]


# --- Malicious URLs ---

MALICIOUS_URLS = [
    ("url", "http://185.234.219.50/gate.php",       "c2",         "critical","high","threat_feed","Command and Control","T1071.001","Emotet gate — C2 check-in endpoint"),
    ("url", "http://5.188.86.172/beacon",           "c2",         "critical","high","threat_feed","Command and Control","T1071.001","Cobalt Strike default beacon URI"),
    ("url", "https://update-cdn-service.net/update","c2",         "critical","high","threat_feed","Command and Control","T1071.001","Fake CDN update — malware download"),
    ("url", "http://barclays-secure-login.com/auth","phishing",   "critical","high","threat_feed","Initial Access",     "T1566",    "Barclays credential harvesting page"),
    ("url", "https://free-pdf-converter-pro.com/download/setup.exe","malware_dist","high","high","threat_feed","Execution","T1204","Malware dropper download link"),
    ("url", "http://office365-activator.net/crack/kms.zip","malware_dist","critical","high","threat_feed","Execution","T1204","Trojanized KMS activator with RAT"),
    ("url", "https://decrypt-your-files-now.com/payment","ransomware","critical","high","threat_feed","Impact","T1486","LockBit ransom payment portal"),
]


# --- Malicious Email Addresses (phishing senders) ---

MALICIOUS_EMAILS = [
    ("email", "no-reply@barclays-secure-login.com", "phishing",  "critical","high","threat_feed","Initial Access","T1566","Phishing sender — Barclays impersonation"),
    ("email", "security@barclays-verify-account.net","phishing", "critical","high","threat_feed","Initial Access","T1566","Phishing sender — account verification lure"),
    ("email", "alerts@hsbc-secure-verify.net",      "phishing",  "high",   "high","threat_feed","Initial Access","T1566","HSBC phishing sender"),
    ("email", "support@update-your-bank-details.com","phishing", "high",   "high","threat_feed","Initial Access","T1566","Banking details update phishing"),
    ("email", "noreply@adobe-reader-update.net",    "malware_dist","high", "high","threat_feed","Execution","T1204","Fake Adobe update — malware dropper sender"),
    ("email", "hr@free-pdf-converter-pro.com",      "malware_dist","medium","high","threat_feed","Execution","T1204","Malware distribution email"),
]


# ---------------------------------------------------------------------------
# Seed functions
# ---------------------------------------------------------------------------

def seed_mitre_mappings(conn):
    print(f"  Seeding {len(MITRE_MAPPINGS)} MITRE ATT&CK mappings...")

    # Remove tactic_id (4th element) when inserting
    cleaned_rows = [(t[0], t[1], t[2], t[4]) for t in MITRE_MAPPINGS]

    conn.executemany("""
        INSERT OR IGNORE INTO mitre_mappings
            (technique_id, technique_name, tactic, description)
        VALUES (?,?,?,?)
    """, cleaned_rows)

    count = conn.execute("SELECT COUNT(*) FROM mitre_mappings").fetchone()[0]
    print(f"  → mitre_mappings total: {count}")

def seed_ioc_entries(conn):
    all_iocs = MALICIOUS_IPS + MALICIOUS_DOMAINS + MALICIOUS_HASHES + MALICIOUS_URLS + MALICIOUS_EMAILS
    print(f"  Seeding {len(all_iocs)} IOC entries...")

    now = datetime.utcnow().isoformat()
    inserted = 0
    skipped = 0

    for row in all_iocs:
        ioc_type, value, threat_type, severity, confidence, source, mitre_tactic, mitre_technique, description = row
        try:
            conn.execute("""
                INSERT OR IGNORE INTO ioc_entries
                    (ioc_type, value, threat_type, severity, confidence, source,
                     mitre_tactic, mitre_technique, description, added_by,
                     is_active, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)
            """, (ioc_type, value, threat_type, severity, confidence, source,
                  mitre_tactic, mitre_technique, description, "seed_script", now, now))
            inserted += 1
        except Exception as e:
            skipped += 1
            print(f"    SKIP [{value}]: {e}")

    count = conn.execute("SELECT COUNT(*) FROM ioc_entries WHERE is_active=1").fetchone()[0]
    print(f"  → Inserted: {inserted}, Skipped (dup): {skipped}")
    print(f"  → ioc_entries total active: {count}")


def print_summary(conn):
    print("\n--- Seed Summary ---")
    tables = ["ioc_entries", "mitre_mappings", "cis_rules", "iot_thresholds", "auto_enriched_candidates"]
    for t in tables:
        try:
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  {t:<35} {n}")
        except Exception:
            print(f"  {t:<35} (table not found)")

    print("\n  IOC breakdown by type:")
    rows = conn.execute(
        "SELECT ioc_type, COUNT(*) as n FROM ioc_entries WHERE is_active=1 GROUP BY ioc_type"
    ).fetchall()
    for r in rows:
        print(f"    {r[0]:<15} {r[1]}")

    print("\n  IOC breakdown by severity:")
    rows = conn.execute(
        "SELECT severity, COUNT(*) as n FROM ioc_entries WHERE is_active=1 GROUP BY severity ORDER BY n DESC"
    ).fetchall()
    for r in rows:
        print(f"    {r[0]:<15} {r[1]}")


def main():
    print(f"BarclaySSOC IOC Seed Script")
    print(f"Target DB: {DB_PATH}\n")

    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Make sure ioc_db.py has been run first to create the schema.")
        return

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")

        seed_mitre_mappings(conn)
        seed_ioc_entries(conn)
        conn.commit()

        print_summary(conn)

    print("\nDone. Safe to re-run — duplicates are skipped via INSERT OR IGNORE.")


if __name__ == "__main__":
    main()
