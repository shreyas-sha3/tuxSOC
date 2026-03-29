import json
import sys
from pathlib import Path
from layer_3_domain_recommendation.orchestrator import run_layer3


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m layer_3_domain_recommendation.run_layer3 <layer2_output.json>")
        sys.exit(1)

    input_file = Path(sys.argv[1])

    if not input_file.exists():
        print(f"Input file not found: {input_file}")
        sys.exit(1)

    with input_file.open("r", encoding="utf-8") as f:
        layer2_output = json.load(f)

    result = run_layer3(layer2_output)

    output_file = input_file.parent / "layer3_output.json"
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"Layer 3 output written to: {output_file}")


if __name__ == "__main__":
    main()