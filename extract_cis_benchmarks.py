import json
import re
import sys
from pathlib import Path


def generate_tags(entry):
    text = (
        str(entry.get("title", "")) + " " +
        str(entry.get("description", "")) + " " +
        str(entry.get("section", "")) + " " +
        str(entry.get("remediation", ""))
    ).lower()

    tags = []

    if any(x in text for x in ["password", "credential", "login", "authentication"]):
        tags += ["authentication", "credentials"]

    if any(x in text for x in ["admin", "privileged", "enable password", "exec mode"]):
        tags += ["privileged_access", "admin_account"]

    if "ssh" in text:
        tags += ["ssh", "remote_access"]

    if any(x in text for x in ["http", "https", "tls", "ssl"]):
        tags += ["web_security"]

    if any(x in text for x in ["logging", "syslog", "log "]):
        tags += ["logging", "monitoring"]

    if "snmp" in text:
        tags += ["snmp"]

    if "ntp" in text:
        tags += ["time_sync"]

    if any(x in text for x in ["firewall", "acl", "access list", "interface", "routing", "bgp", "ospf", "eigrp"]):
        tags += ["network_security"]

    return sorted(set(tags))


def generate_keywords(entry):
    text = (
        str(entry.get("title", "")) + " " +
        str(entry.get("description", ""))
    ).lower()

    words = re.findall(r"\b[a-z][a-z0-9\-\+]{3,}\b", text)
    seen = []
    for w in words:
        if w not in seen:
            seen.append(w)
    return seen[:12]


def infer_source_benchmark(input_name: str) -> str:
    name = Path(input_name).stem.lower()

    if "firepower" in name:
        return "firepower"
    if "cisco_firewall" in name or "firewall" in name:
        return "cisco_firewall"
    if "iosxe16" in name:
        return "iosxe16"
    if "iosxe17" in name:
        return "iosxe17"
    if "iosxr7" in name:
        return "iosxr7"
    if "nxos" in name:
        return "nxos"

    return name


def transform(entry, source_benchmark: str):
    return {
        "benchmark_id": entry.get("benchmark_id"),
        "source_benchmark": source_benchmark,
        "framework": "CIS",
        "domain": "network",
        "title": entry.get("title"),
        "section": entry.get("section"),
        "profile_level": entry.get("profile_level"),
        "assessment_type": entry.get("assessment_type"),
        "description": entry.get("description"),
        "rationale": entry.get("rationale"),
        "audit_procedure": entry.get("audit_procedure"),
        "remediation": entry.get("remediation"),
        "references": entry.get("references"),
        "cis_controls": entry.get("cis_controls"),
        "tags": generate_tags(entry),
        "keywords": generate_keywords(entry),
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_cis_benchmarks.py <input_json> <output_json>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"Input file not found: {input_file}")
        sys.exit(1)

    with input_file.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if not isinstance(data, list):
        print("Input JSON must be a list of benchmark objects.")
        sys.exit(1)

    source_benchmark = infer_source_benchmark(input_file.name)

    cleaned = []
    for entry in data:
        if isinstance(entry, dict) and entry.get("benchmark_id"):
            cleaned.append(transform(entry, source_benchmark))

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2)

    print(f"Processed {len(cleaned)} entries -> {output_file}")


if __name__ == "__main__":
    main()