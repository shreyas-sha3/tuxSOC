from layer_3_domain_recommendation.router import route_entry
from layer_3_domain_recommendation.merger import merge_processed_entries


def run_layer3(layer2_output: dict) -> dict:
    detections = layer2_output.get("detections", []) or []

    processed_entries = []
    for entry in detections:
        processed_entries.append(route_entry(entry))

    return merge_processed_entries(layer2_output, processed_entries)