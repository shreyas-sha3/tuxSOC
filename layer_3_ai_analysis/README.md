# Layer 3 — Autonomous AI Incident Analyst

> Part of the **Barclays Cyber Incident Response Orchestrator** — a 4-layer autonomous SOC pipeline built for the Barclays Hackathon.

---


## Setup

### Requirements

```bash
pip install fastapi uvicorn langchain-ollama langgraph requests
```

### Pull the model

```bash
ollama pull llama3
```


### Verify Ollama is running

```bash
ollama serve
```

---

## How to Run

```bash
python app.py
```

The server starts on `http://0.0.0.0:8001`.

Interactive Swagger UI for manual testing:

```
http://localhost:8001/docs
```

Health check:

```
GET http://localhost:8001/health
→ {"status": "online", "engine": "llama3-8b"}
```

---

## API Integration Guide — FOR LAYER 2 (Detection)

### Endpoint

```
POST http://<LAYER_3_IP>:8001/analyze
```

Send your raw enriched incident JSON here. Layer 3 will:
1. Normalise the data format (handles both `dict` and `list` payloads)
2. Apply tiered priority logic — blacklist hits override all other context
3. Suppress false positives (authorised backups, scheduled scans, service accounts)
4. Derive a CVSS v3.1 vector from the telemetry
5. Return a structured 5-key SOC report

### Sample Request

```json
{
  "event_id": "evt_8c9e12",
  "timestamp": "2026-03-25T02:01:14Z",
  "log_type": "network",
  "source": {
    "ip": "10.10.1.50",
    "port": 53122,
    "user": "unknown"
  },
  "destination": {
    "ip": "10.50.10.23",
    "port": 22
  },
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110",
    "technique_name": "Brute Force"
  },
  "anomaly_detection": {
    "pyod_score": 0.81,
    "is_outlier": true,
    "fidelity_score": 0.67
  },
  "threat_intel": {
    "ioc_matches": [],
    "ioc_confidence": 0.0
  }
}
```

### Sample Response

```json
{
  "event_id": "evt_8c9e12",
  "ai_analysis": {
    "intent": "Internal Brute Force — Credential Access via SSH",
    "severity": "high",
    "cvss_vector": {
      "AV": "A", "AC": "L", "PR": "N",
      "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"
    },
    "narrative": "An internal host at 10.10.1.50 launched a brute force attack against 10.50.10.23 on port 22, consistent with MITRE T1110 Credential Access. The anomaly score of 0.81 and outlier flag indicate this is not baseline behaviour.",
    "recommended_actions": [
      "Block 10.10.1.50 at the internal firewall immediately",
      "Lock all accounts targeted on 10.50.10.23",
      "Review SSH authentication logs on 10.50.10.23 for the last 24 hours",
      "Enable alerting for repeated SSH failures from the 10.10.x.x subnet"
    ],
    "ai_failed": false
  }
}
```

---

## Data Handoff Guide — FOR LAYER 4 (Scoring)

Layer 3 **automatically pushes** results to your scoring endpoint after every successful analysis:

```
POST http://<LAYER_4_IP>:8000/score
```

Update the target IP in `ai_orchestrator.py`:

```python
CVSS_LAYER_URL = "http://<LAYER_4_IP>:8000/score"
```

### The 5 Canonical Keys

Every successful response contains exactly these keys inside `ai_analysis`:

| Key | Type | Description |
|---|---|---|
| `intent` | `str` | One-line incident title (e.g., `"External Brute Force — Credential Access"`) |
| `severity` | `str` | `critical / high / medium / low / informational` |
| `cvss_vector` | `dict` | Full CVSS v3.1 vector with keys `AV, AC, PR, UI, S, C, I, A` |
| `narrative` | `str` | 2-sentence professional SOC summary |
| `recommended_actions` | `list[str]` | 3–4 executable SOC response actions |

---

## Key Features

**Context-Aware False Positive Suppression**
Service accounts (`svc_*`, `backup_*`) performing their primary job — rsync, Veeam, robocopy — are correctly classified as `informational`, not escalated as exfiltration. A high anomaly score alone does not trigger an alert for known maintenance activity.

**Tiered Priority Logic — Blacklist Overrides**
A strict evaluation order prevents the AI from being fooled by misleading context. If `threat_intel.ioc_matches` is non-empty or the destination IP is external and blacklisted, all maintenance rules are voided and the incident is forced to `critical`. The blacklist always wins.

**Fully Offline — Zero External Data Transfer**
All inference runs locally via Ollama. No telemetry, no API calls, no data leaves the machine. Compliant with air-gapped SOC environments.

**LangGraph 3-Node Pipeline**
```
analyze_incident_master → patch_and_fix → finalize_and_validate
```
Node 1 runs LLM inference. Node 2 normalises key names and fills gaps. Node 3 validates all 5 required keys are present before the result is returned.

---

## Architecture

```
Layer 2 (Detection)
        │
        │  POST /analyze
        ▼
┌─────────────────────────────┐
│   Layer 3 — AI Analyst      │
│   FastAPI  :8001            │
│                             │
│   LangGraph Agent           │
│   ├── Node 1: LLM Inference │
│   ├── Node 2: Key Mapping   │
│   └── Node 3: Validation    │
│                             │
│   Ollama (phi3 / llama3)    │
│   Fully local — offline     │
└─────────────────────────────┘
        │
        │  POST /score
        ▼
Layer 4 (CVSS Scoring)  :8000
```
