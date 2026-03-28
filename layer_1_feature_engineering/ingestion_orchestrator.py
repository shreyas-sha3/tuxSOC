import json
import csv
import io
from typing import Any, Dict, List

from ingestion_normalizer import normalize_record
from feature_orchestrator import run_feature_engineering


# ─────────────────────────────────────────
# JSON Parsing
# ─────────────────────────────────────────

def parse_json_content(content: str) -> List[Dict[str, Any]]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {str(e)}")

    if isinstance(parsed, dict):
        return [parsed]

    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise ValueError("JSON array must contain only JSON objects")
        return parsed

    raise ValueError("JSON must be an object or an array of objects")


def parse_jsonl_content(content: str) -> List[Dict[str, Any]]:
    records = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSONL at line {line_num}: {str(e)}")

        if not isinstance(obj, dict):
            raise ValueError(f"JSONL line {line_num} must be a JSON object")

        records.append(obj)

    return records


# ─────────────────────────────────────────
# CSV Parsing
# ─────────────────────────────────────────

def parse_csv_content(content: str) -> List[Dict[str, Any]]:
    try:
        buffer = io.StringIO(content)
        reader = csv.DictReader(buffer)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header row")

        records = []
        for row_num, row in enumerate(reader, start=2):
            cleaned_row = {}
            for key, value in row.items():
                if key is None:
                    continue
                cleaned_key = str(key).strip()
                cleaned_value = value.strip() if isinstance(value, str) else value
                cleaned_row[cleaned_key] = cleaned_value

            # skip completely empty rows
            if any(v not in (None, "") for v in cleaned_row.values()):
                records.append(cleaned_row)

        if not records:
            raise ValueError("CSV file contains no data rows")

        return records

    except csv.Error as e:
        raise ValueError(f"Invalid CSV: {str(e)}")


# ─────────────────────────────────────────
# Processing Pipeline
# ─────────────────────────────────────────

def process_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    normalized_records = []
    enriched_records = []

    for record in records:
        normalized = normalize_record(record)
        enriched = run_feature_engineering(normalized)

        normalized_records.append(normalized)
        enriched_records.append(enriched)

    return {
        "total_records": len(records),
        "normalized_records": normalized_records,
        "enriched_records": enriched_records,
    }


def process_json_text(content: str) -> Dict[str, Any]:
    records = parse_json_content(content)
    return process_records(records)


def process_jsonl_text(content: str) -> Dict[str, Any]:
    records = parse_jsonl_content(content)
    return process_records(records)


def process_csv_text(content: str) -> Dict[str, Any]:
    records = parse_csv_content(content)
    return process_records(records)