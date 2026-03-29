import json
from pathlib import Path


INPUT_FILES = [
    "clean_firepower.json",
    "clean_cisco_firewall.json",
    "clean_iosxe16.json",
    "clean_iosxe17.json",
    "clean_iosxr7.json",
    "clean_nxos.json",
]

OUTPUT_FILE = r".\layer_3_domain_recommendation\mappings\benchmark_catalog\network_controls_catalog.json"


def main():
    merged = []

    for file_name in INPUT_FILES:
        path = Path(file_name)
        if not path.exists():
            print(f"Skipping missing file: {file_name}")
            continue

        with path.open("r", encoding="utf-8-sig") as f:
            data = json.load(f)

        if not isinstance(data, list):
            print(f"Skipping non-list JSON: {file_name}")
            continue

        for entry in data:
            if isinstance(entry, dict) and entry.get("benchmark_id"):
                merged.append(entry)

    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)

    print(f"Merged {len(merged)} entries -> {output_path}")


if __name__ == "__main__":
    main()