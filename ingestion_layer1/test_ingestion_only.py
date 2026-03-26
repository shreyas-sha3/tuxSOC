from log_parsers import file_to_parsed_list
from log_normalizer import normalize_parsed_log

# CHANGE THIS PATH to your test log file
TEST_FILE = "test_iot_kv.log"


def test_ingestion():
    print("\n🔍 Testing Ingestion Pipeline...\n")

    parsed_logs = file_to_parsed_list(TEST_FILE)

    print(f"Total logs parsed: {len(parsed_logs)}\n")

    for i, raw in enumerate(parsed_logs[:5]):  # test first 5 logs
        print("=" * 60)
        print(f"Log #{i+1}")

        normalized = normalize_parsed_log(raw)

        print("\nRaw Parsed:")
        print(raw)

        print("\nNormalized Output:")
        print({
            "log_family": normalized.get("log_family"),
            "classification_confidence": normalized.get("classification_confidence"),
            "src_ip": normalized.get("src_ip"),
            "dst_ip": normalized.get("dst_ip"),
            "protocol": normalized.get("protocol"),
            "http_method": normalized.get("http_method"),
            "device_id": normalized.get("device_id"),
        })

        print("=" * 60)


if __name__ == "__main__":
    test_ingestion()