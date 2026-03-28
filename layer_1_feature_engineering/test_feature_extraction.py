import sys
import os
import json

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from feature_orchestrator import run_feature_engineering
from detection_ready_formatter import format_detection_ready_log
# REMOVE this line
# from log_normalizer import normalize_parsed_log

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def main():
    input_file = "sample_logs.json"  # <-- your JSON file

    try:
        raw_logs = load_json(input_file)

        print(f"\n Loaded {len(raw_logs)} logs")

        enriched_logs = []

        for log in raw_logs:
            try:
                # Step 1: Normalize
                enriched = run_feature_engineering(log)

                # Step 2: Format for detection
                formatted_log = format_detection_ready_log(enriched)
                formatted = format_detection_ready_log(enriched)
                enriched_logs.append(formatted )

            except Exception as e:
                print(f" Error processing log: {e}")

        # Print output
        print("\n SAMPLE OUTPUT:\n")
        print(json.dumps(enriched_logs[:2], indent=2))  # show first 2 logs

        # Save full output
        with open("output_enriched.json", "w") as f:
            json.dump(enriched_logs, f, indent=2)

        print("\n Full output saved to output_enriched.json")

    except Exception as e:
        print(f" Fatal error: {e}")


if __name__ == "__main__":
    main()