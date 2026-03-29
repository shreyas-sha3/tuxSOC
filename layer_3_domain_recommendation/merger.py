def merge_processed_entries(layer2_output: dict, processed_entries: list[dict]) -> dict:
    return {
        "status": layer2_output.get("status", "success"),
        "file": layer2_output.get("file"),
        "total_processed": layer2_output.get("total_processed", len(processed_entries)),
        "layer3_status": "success",
        "domain_enriched_detections": processed_entries
    }