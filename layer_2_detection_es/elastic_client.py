"""
elastic_client.py
-----------------
Elasticsearch client with retry logic, timeout handling, and
missing-index protection.  Falls back to a no-op stub when ES is
unavailable so the rest of the pipeline never crashes on import.
"""

import logging
import time
from typing import Any

from layer_2_detection_es.config import (
    ES_HOST, ES_TIMEOUT, ES_MAX_RETRIES, ES_RETRY_DELAY
)

logger = logging.getLogger(__name__)

# ── No-op stub ─────────────────────────────────────────────────────────────

class _NoOpES:
    """Absorbs all ES calls silently when the cluster is unreachable."""
    def ping(self):                          return False
    def search(self, **kw):                  return {"hits": {"hits": [], "total": {"value": 0}}}
    def indices(self):                       return self
    def exists(self, index=""):              return False
    def __getattr__(self, name):             return lambda *a, **kw: None


# ── Singleton client ───────────────────────────────────────────────────────

_client = None


def get_client():
    global _client
    if _client is not None:
        return _client
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(ES_HOST, request_timeout=ES_TIMEOUT)
        if es.ping():
            logger.info("Elasticsearch connected at %s", ES_HOST)
            _client = es
            return _client
        raise ConnectionError("ping failed")
    except Exception as exc:
        logger.warning("Elasticsearch unavailable (%s) — using no-op stub", exc)
        _client = _NoOpES()
        return _client


# ── Query helpers ──────────────────────────────────────────────────────────

def _retry(fn, *args, **kwargs) -> Any:
    """Execute fn with exponential-backoff retry."""
    last_exc = None
    for attempt in range(1, ES_MAX_RETRIES + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            logger.warning("ES attempt %d/%d failed: %s", attempt, ES_MAX_RETRIES, exc)
            time.sleep(ES_RETRY_DELAY * attempt)
    logger.error("ES query failed after %d attempts: %s", ES_MAX_RETRIES, last_exc)
    return None


def _index_exists(index: str) -> bool:
    es = get_client()
    try:
        return bool(es.indices.exists(index=index))
    except Exception:
        return False


def search_index(index: str, query: dict, size: int = 500) -> list[dict]:
    """
    Run a search query against a single index.
    Returns a list of _source documents.
    Silently returns [] if the index does not exist.
    """
    if not _index_exists(index):
        logger.debug("Index %s does not exist — skipping", index)
        return []
    es = get_client()
    result = _retry(es.search, index=index, body=query, size=size)
    if result is None:
        return []
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


def search_all_logs(query: dict, size: int = 500) -> list[dict]:
    """Search across all Layer-1 log indices (logs-*)."""
    return search_index("logs-*", query, size=size)


def run_aggregation(index: str, query: dict) -> dict:
    """
    Run an aggregation query.
    Returns the aggregations dict, or {} on failure.
    """
    if not _index_exists(index):
        logger.debug("Index %s does not exist — skipping aggregation", index)
        return {}
    es = get_client()
    result = _retry(es.search, index=index, body=query, size=0)
    if result is None:
        return {}
    return result.get("aggregations", {})


def count_hits(index: str, query: dict) -> int:
    """Return the total hit count for a query without fetching documents."""
    if not _index_exists(index):
        return 0
    es = get_client()
    result = _retry(es.count, index=index, body=query)
    if result is None:
        return 0
    return result.get("count", 0)
