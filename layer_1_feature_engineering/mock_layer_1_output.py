import time
import random
import threading
import sys
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers

# --- CONFIGURATION ---
ES_HOST = "http://127.0.0.1:9200"
INDICES = ["logs-web", "logs-auth", "logs-endpoint", "logs-network"]

print("🔌 Connecting to Elasticsearch Data Lake...")
es = Elasticsearch(ES_HOST, request_timeout=30, max_retries=3, retry_on_timeout=True)

for idx in INDICES:
    if not es.indices.exists(index=idx):
        es.indices.create(index=idx)

# --- HELPER FUNCTIONS FOR QUICK LOG GENERATION ---
def get_time():
    return datetime.now(timezone.utc).isoformat()

def push_log(index, doc):
    doc["@timestamp"] = get_time()
    es.index(index=index, document=doc)

# --- BACKGROUND NOISE GENERATOR (Runs in a separate thread) ---
def generate_background_noise():
    """Silently pumps normal traffic into all 4 indices every second."""
    while True:
        # 1. Normal Web
        push_log("logs-web", {
            "log_type": "web",
            "source": {"ip": f"10.0.{random.randint(1,5)}.{random.randint(1,255)}", "geo": {"country_iso_code": "US"}},
            "destination": {"ip": "10.0.1.10", "port": 443},
            "request": {"uri": random.choice(["/index.html", "/api/data", "/login"]), "body": ""},
            "user_agent": {"original": "Mozilla/5.0 (Windows NT 10.0)"},
            "raw_event": {"action": "HTTP GET", "affected_host": "PROD-WEB-01"}
        })
        # 2. Normal Auth
        push_log("logs-auth", {
            "log_type": "auth",
            "source": {"ip": f"10.0.2.{random.randint(10,50)}"},
            "event": {"category": "authentication", "outcome": "success"},
            "raw_event": {"affected_user": random.choice(["jdoe", "asmith", "bwayne"]), "action": "Logon"}
        })
        # 3. Normal Endpoint
        push_log("logs-endpoint", {
            "log_type": "endpoint",
            "process": {"command_line": "chrome.exe", "name": "chrome.exe"},
            "raw_event": {"affected_user": "jdoe", "source_ip": "10.0.2.15", "action": "Process Creation"}
        })
        # 4. Normal Network
        push_log("logs-network", {
            "log_type": "network",
            "source": {"ip": f"10.0.2.{random.randint(10,50)}"},
            "destination": {"ip": "8.8.8.8", "port": 53},
            "network": {"bytes": random.randint(100, 500), "transport": "udp"},
            "dns": {"question": {"name": "google.com", "type": "A"}},
            "raw_event": {"action": "DNS Query"}
        })
        time.sleep(1) # Send a burst of 4 logs every 1 second

# --- ATTACK PAYLOADS ---
def fire_attack(attack_id):
    attacker_ip = f"{random.randint(100,200)}.14.5.9" # Randomize external attacker IP per attack
    
    print(f"\n🔥 [FIRING ATTACK {attack_id}] Injecting payloads into stream...")
    
    if attack_id == 1: # WEB_SQLI
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "UNION SELECT username, password"}, "raw_event": {"action": "HTTP GET"}})
    
    elif attack_id == 2: # WEB_CMDI
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "/ping?ip=127.0.0.1 | bash"}, "raw_event": {"action": "HTTP GET"}})
    
    elif attack_id == 3: # WEB_LFI
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "../../../../etc/passwd"}, "raw_event": {"action": "HTTP GET"}})
    
    elif attack_id == 4: # WEB_XSS
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "<script>alert(1)</script>"}, "raw_event": {"action": "HTTP POST"}})
    
    elif attack_id == 5: # WEB_SCANNER
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "/"}, "user_agent": {"original": "sqlmap/1.0"}, "raw_event": {"action": "HTTP GET"}})
    
    elif attack_id == 6: # WEB_SSRF
        push_log("logs-web", {"log_type": "web", "source": {"ip": attacker_ip}, "request": {"uri": "169.254.169.254/latest/meta-data/"}, "raw_event": {"action": "HTTP GET"}})
    
    elif attack_id == 7: # AUTH_BRUTEFORCE (>20 failures)
        for _ in range(25):
            push_log("logs-auth", {"log_type": "auth", "source": {"ip": attacker_ip}, "event": {"outcome": "failure"}, "raw_event": {"affected_user": "admin", "action": "Failed Login"}})
            
    elif attack_id == 8: # AUTH_SPRAY (>10 unique users)
        for i in range(15):
            push_log("logs-auth", {"log_type": "auth", "source": {"ip": attacker_ip}, "event": {"outcome": "failure"}, "raw_event": {"affected_user": f"user_{i}", "action": "Failed Login"}})
            
    elif attack_id == 9: # AUTH_MFA_FATIGUE
        for _ in range(8):
            push_log("logs-auth", {"log_type": "auth", "event": {"category": "authentication", "action": "mfa_prompt"}, "raw_event": {"affected_user": "ceo_account"}})
            
    elif attack_id == 10: # AUTH_PRIV_ABUSE
        push_log("logs-auth", {"log_type": "auth", "source": {"ip": "192.168.1.100"}, "event": {"outcome": "success"}, "raw_event": {"affected_user": "root", "action": "Login"}})
        
    elif attack_id == 11: # EP_RANSOMWARE
        for _ in range(5):
            push_log("logs-endpoint", {"log_type": "endpoint", "process": {"command_line": "vssadmin delete shadows"}, "raw_event": {"action": "mass_file_modification"}})
            
    elif attack_id == 12: # EP_LOLBIN
        push_log("logs-endpoint", {"log_type": "endpoint", "process": {"command_line": "powershell.exe -ExecutionPolicy Bypass"}, "raw_event": {"action": "Process Creation"}})
        
    elif attack_id == 13: # EP_CREDENTIAL_DUMP
        push_log("logs-endpoint", {"log_type": "endpoint", "process": {"command_line": "procdump -ma lsass.exe"}, "raw_event": {"action": "Process Access"}})
        
    elif attack_id == 14: # EP_DEF_EVASION
        push_log("logs-endpoint", {"log_type": "endpoint", "process": {"command_line": "wevtutil cl Security"}, "raw_event": {"action": "Process Creation"}})
        
    elif attack_id == 15: # EP_PERSISTENCE
        push_log("logs-endpoint", {"log_type": "endpoint", "process": {"command_line": "schtasks /create /tn backdoor"}, "raw_event": {"action": "Process Creation"}})
        
    elif attack_id == 16: # NET_PORTSCAN (>50 ports)
        for port in range(100, 160):
            push_log("logs-network", {"log_type": "network", "source": {"ip": attacker_ip}, "destination": {"port": port, "ip": "10.0.1.50"}})
            
    elif attack_id == 17: # NET_C2_BEACON (Periodic connections)
        # For simulation, we backdate 15 logs exactly 60 seconds apart
        for i in range(15):
            t = (datetime.now(timezone.utc) - __import__('datetime').timedelta(seconds=60*i)).isoformat()
            es.index(index="logs-network", document={"@timestamp": t, "log_type": "network", "source": {"ip": "10.0.2.15"}, "destination": {"ip": attacker_ip}})
            
    elif attack_id == 18: # NET_DNS_TUNNEL
        push_log("logs-network", {"log_type": "network", "destination": {"port": 53}, "dns": {"question": {"name": "a"*65 + ".evil.com", "type": "TXT"}}})
        
    elif attack_id == 19: # NET_EXFIL (>1GB outbound)
        push_log("logs-network", {"log_type": "network", "source": {"ip": "10.0.2.15"}, "destination": {"ip": attacker_ip}, "network": {"bytes": 1500000000}})
        
    elif attack_id == 20: # NET_LATERAL (>5 internal targets)
        for i in range(10, 20):
            push_log("logs-network", {"log_type": "network", "source": {"ip": "10.0.2.15"}, "destination": {"ip": f"10.0.1.{i}", "port": 445}})

    print("✅ Payloads delivered successfully. Watch Layer 2!")

# --- TUI MENU ---
def print_menu():
    print("\n" + "="*50)
    print(" 🎯 tuxSOC RED TEAM SIMULATOR")
    print("="*50)
    print("--- WEB ATTACKS ---")
    print(" 1. SQL Injection (SQLi)        2. Command Injection (CMDI)")
    print(" 3. Local File Inclusion (LFI)  4. Cross-Site Scripting (XSS)")
    print(" 5. Scanner Traffic             6. Server-Side Request Forgery")
    print("--- AUTH ATTACKS ---")
    print(" 7. Brute Force (>20 fails)     8. Password Spraying")
    print(" 9. MFA Fatigue                10. Privileged Account Abuse")
    print("--- ENDPOINT ATTACKS ---")
    print("11. Ransomware Behavior        12. LOLBin (PowerShell Bypass)")
    print("13. Credential Dump (lsass)    14. Defense Evasion (Clear Logs)")
    print("15. Persistence (schtasks) ")
    print("--- NETWORK ATTACKS ---")
    print("16. Port Scan (>50 ports)      17. C2 Beaconing")
    print("18. DNS Tunneling              19. Data Exfiltration (>1GB)")
    print("20. Lateral Movement (SMB)")
    print("--------------------------------------------------")
    print(" 0. EXIT")

if __name__ == "__main__":
    # Start the background noise on a separate thread
    noise_thread = threading.Thread(target=generate_background_noise, daemon=True)
    noise_thread.start()
    print("🌊 Background noise generator running silently...")

    # Main TUI Loop
    while True:
        print_menu()
        try:
            choice = int(input("\nSelect attack ID to fire (0-20): "))
            if choice == 0:
                print("Exiting...")
                sys.exit(0)
            elif 1 <= choice <= 20:
                fire_attack(choice)
            else:
                print("❌ Invalid ID. Choose between 1 and 20.")
        except ValueError:
            print("❌ Please enter a number.")