from log_parsers import file_to_parsed_list
from log_normalizer import normalize_parsed_log
from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering

TEST_FILE =  "test_iot_kv.log"


def verify_result(result: dict, label: str) -> None:
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"{'='*50}")

    print(f"\n  log_family:             {result.get('log_family')}")
    print(f"  classification_conf:    {result.get('classification_confidence')}")

    print(f"\n  ── Blocks added ──────────────────────")
    blocks = [
        "time_windows",
        "temporal_features",
        "user_profile",
        "behavioral_features",
        "frequency_features",
        "pattern_features",
        "network_traffic_features",
        "network_protocol_features",
        "web_http_features",
        "web_session_features",
        "iot_device_features",
        "iot_telemetry_features"
    ]

    for block in blocks:
        present = "✅" if block in result else "──"
        print(f"  {present}  {block}")

    errors = result.get("feature_errors", [])
    warnings = result.get("feature_warnings", [])

    print(f"\n  ── Pipeline health ───────────────────")
    print(f"  errors:   {errors if errors else 'none'}")
    print(f"  warnings: {warnings if warnings else 'none'}")


def main():
    print("\n🔍 Running Ingestion -> Layer 1 E2E Test...\n")

    parsed_logs = file_to_parsed_list(TEST_FILE)
    print(f"Total logs parsed: {len(parsed_logs)}")

    for i, raw in enumerate(parsed_logs, 1):
        normalized = normalize_parsed_log(raw)
        enriched = run_feature_engineering(normalized)
        verify_result(enriched, f"LOG #{i}")


if __name__ == "__main__":
    main()