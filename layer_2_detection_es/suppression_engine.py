"""
suppression_engine.py
---------------------
Prevents repeated alerts for the same rule + entity within a cooldown window.
Uses an in-memory TTL cache.  Thread-safe via a simple lock.
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

# {(rule_id, entity): expiry_timestamp}
_cache: dict[tuple, float] = {}
_lock  = threading.Lock()


def is_suppressed(rule_id: str, entity: str) -> bool:
    """Return True if this rule+entity combination is still in cooldown."""
    key = (rule_id, entity)
    with _lock:
        expiry = _cache.get(key)
        if expiry is None:
            return False
        if time.monotonic() < expiry:
            return True
        # Expired — clean up
        del _cache[key]
        return False


def record_alert(rule_id: str, entity: str, cooldown_seconds: int):
    """Record that an alert fired; suppress future alerts until cooldown expires."""
    key = (rule_id, entity)
    with _lock:
        _cache[key] = time.monotonic() + cooldown_seconds
    logger.debug(
        "Suppression set: rule=%s entity=%s cooldown=%ds",
        rule_id, entity, cooldown_seconds
    )


def clear_suppression(rule_id: str, entity: str):
    """Manually clear suppression for a rule+entity (useful for testing)."""
    key = (rule_id, entity)
    with _lock:
        _cache.pop(key, None)


def clear_all():
    """Clear all suppressions (useful for replay / testing)."""
    with _lock:
        _cache.clear()


def get_active_suppressions() -> list[dict]:
    """Return all currently active suppressions for observability."""
    now = time.monotonic()
    with _lock:
        return [
            {"rule_id": k[0], "entity": k[1], "expires_in_s": round(v - now, 1)}
            for k, v in _cache.items()
            if v > now
        ]
