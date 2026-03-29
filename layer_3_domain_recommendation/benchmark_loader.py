import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CATALOG_DIR = BASE_DIR / "mappings" / "benchmark_catalog"


CATALOG_FILES = {
    "web": CATALOG_DIR / "web_owasp_catalog.json",
    "network": CATALOG_DIR / "network_controls_catalog.json",
    "iot": CATALOG_DIR / "iot_cis_catalog.json",
}


def load_catalog(domain: str) -> list[dict]:
    """
    Loads the benchmark catalog JSON for a given domain.
    Returns a list of benchmark/control entries.
    """
    domain = domain.strip().lower()
    if domain not in CATALOG_FILES:
        return []

    file_path = CATALOG_FILES[domain]

    if not file_path.exists():
        return []

    with file_path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    return []