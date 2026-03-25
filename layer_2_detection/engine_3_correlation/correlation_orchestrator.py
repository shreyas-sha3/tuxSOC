"""
correlation_orchestrator.py
---------------------------
Engine 3 orchestrator. Links events and builds the attack timeline.
Always runs — it needs both Engine 1 and Engine 2 results to do its job.
"""

import logging
import event_linker
import timeline_builder

logger = logging.getLogger(__name__)


def run(engine_1: dict, engine_2: dict, raw_event: dict) -> dict:
    """
    Run Engine 3: event correlation + timeline construction.

    Args:
        engine_1  : Output from anomaly_orchestrator.run()
        engine_2  : Output from intel_orchestrator.run() (can be empty dict if skipped)
        raw_event : Original normalized log event.

    Returns engine_3_correlation block:
        {
          "linked_events":  list[dict],
          "event_count":    int,
          "attack_timeline":list[dict],
        }
    """
    logger.debug("Engine 3 starting")

    linked = event_linker.link(engine_1, engine_2, raw_event)
    timeline = timeline_builder.build(raw_event, linked)

    result = {
        "linked_events":   linked,
        "event_count":     len(linked),
        "attack_timeline": timeline,
    }

    logger.debug("Engine 3 done — %d linked events, %d timeline entries",
                 len(linked), len(timeline))
    return result