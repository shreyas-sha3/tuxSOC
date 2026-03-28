# json_parser.py
# Location: layer_3_ai_analysis/json_parser.py
#
# PURPOSE:
# Safely parses JSON responses from the LLM.
# LLMs sometimes produce slightly malformed JSON —
# extra text before or after the block, missing quotes,
# trailing commas. This file handles all of that gracefully.
#
# WHY THIS IS CRITICAL:
# If JSON parsing fails and we raise an exception,
# the entire agent crashes. This file ensures that
# even bad LLM output produces a usable result
# with clear error information.
#
# FALLBACK STRATEGY:
# 1. Try direct json.loads() — works if output is clean
# 2. Try extracting JSON block between { } — handles extra text
# 3. Try cleaning common LLM formatting issues — handles markdown
# 4. Return a fallback dict with the raw text — never crashes
#
# CALLED BY:
# agent_nodes.py — every node parses its LLM response here


import json
import re


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _try_direct_parse(text: str) -> dict | None:
    """
    Attempt 1: Direct JSON parse.
    Works when LLM output is clean JSON.
    """
    try:
        return json.loads(text.strip())
    except Exception:
        return None


def _try_extract_json_block(text: str) -> dict | None:
    """
    Attempt 2: Extract JSON block between outermost { }.
    Works when LLM adds explanation text before or after JSON.
    Example:
        'Here is the analysis: {"key": "value"} Hope this helps!'
        → extracts {"key": "value"}
    """
    try:
        # Find the first { and last } in the text
        start = text.find("{")
        end   = text.rfind("}")

        if start == -1 or end == -1 or start >= end:
            return None

        json_block = text[start:end + 1]
        return json.loads(json_block)
    except Exception:
        return None


def _try_clean_and_parse(text: str) -> dict | None:
    """
    Attempt 3: Clean common LLM formatting issues then parse.
    Handles:
    - Markdown code fences: ```json ... ```
    - Trailing commas before } or ]
    - Single quotes instead of double quotes
    """
    try:
        cleaned = text.strip()

        # Remove markdown code fences
        cleaned = re.sub(r"```json\s*", "", cleaned)
        cleaned = re.sub(r"```\s*",     "", cleaned)

        # Remove trailing commas before closing braces/brackets
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)

        # Replace single quotes with double quotes
        # Only when used as JSON string delimiters
        cleaned = re.sub(r"(?<![\\])'", '"', cleaned)

        return json.loads(cleaned.strip())

    except Exception:
        return None


def _try_extract_after_clean(text: str) -> dict | None:
    """
    Attempt 4: Clean first, then extract JSON block.
    Combination of attempts 2 and 3.
    """
    try:
        cleaned = text.strip()
        cleaned = re.sub(r"```json\s*", "", cleaned)
        cleaned = re.sub(r"```\s*",     "", cleaned)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)

        start = cleaned.find("{")
        end   = cleaned.rfind("}")

        if start == -1 or end == -1 or start >= end:
            return None

        json_block = cleaned[start:end + 1]
        return json.loads(json_block)

    except Exception:
        return None


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def parse_llm_response(text: str, expected_keys: list = None) -> dict:
    # ... (keep your initial empty text checks) ...

    strategies = [
        ("direct", _try_direct_parse),
        ("extract_block", _try_extract_json_block),
        ("clean_and_parse", _try_clean_and_parse),
        ("extract_after_clean", _try_extract_after_clean)
    ]

    for strategy_name, strategy_fn in strategies:
        result = strategy_fn(text)
        if result is not None and isinstance(result, dict):
            
            # ─── FUZZY MAPPING LOGIC START ───
            # If the AI is lazy and uses synonyms, we fix them here
            synonym_map = {
                "intent": "attack_intent",
                "attack": "attack_intent",
                "threat": "attack_intent",
                "goal": "attack_intent",
                "stage": "attack_stage"
            }
            
            for syn, official_key in synonym_map.items():
                # If the official key is missing but the synonym exists
                if official_key not in result and syn in result:
                    result[official_key] = result[syn]
            # ─── FUZZY MAPPING LOGIC END ───

            # Now check for missing keys AFTER we've tried to fix them
            missing = []
            if expected_keys:
                missing = [k for k in expected_keys if k not in result]

            return {
                "parsed": True,
                "data": result,
                "raw_text": text,
                "parse_strategy": strategy_name,
                "missing_keys": missing,
                "error": None
            }

    # All strategies failed — return raw text as fallback
    return {
        "parsed":         False,
        "data":           None,
        "raw_text":       text,
        "parse_strategy": "failed",
        "missing_keys":   expected_keys or [],
        "error":          "All parse strategies failed"
    }


def safe_get(parsed_result: dict, key: str, fallback=None):
    """
    Safely retrieves a key from parsed LLM output.
    Returns fallback if parsing failed or key is missing.

    Args:
        parsed_result: dict returned by parse_llm_response()
        key:           key to retrieve from parsed data
        fallback:      value to return if key not found

    Returns:
        value from parsed data or fallback
    """
    if not parsed_result.get("parsed"):
        return fallback

    data = parsed_result.get("data", {})
    return data.get(key, fallback)