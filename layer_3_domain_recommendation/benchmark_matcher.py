from typing import Any
import re
from layer_3_domain_recommendation.benchmark_loader import load_catalog


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_list(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, list):
        return [_normalize_text(v) for v in values if _normalize_text(v)]
    return [_normalize_text(values)]


def _score_entry(entry: dict, query_tags: list[str], query_keywords: list[str], section_hint: list[str]) -> int:
    score = 0

    entry_tags = _normalize_list(entry.get("tags", []))
    entry_keywords = _normalize_list(entry.get("keywords", []))
    entry_section = _normalize_text(entry.get("section", ""))
    entry_title = _normalize_text(entry.get("title", ""))
    entry_description = _normalize_text(entry.get("description", ""))

    for tag in query_tags:
        if tag in entry_tags:
            score += 3

    for keyword in query_keywords:
        if keyword in entry_keywords:
            score += 3
        elif keyword in entry_title:
            score += 2
        elif keyword in entry_description:
            score += 1

    for hint in section_hint:
        if hint and hint in entry_section:
            score += 2

    return score


def _normalize_title_for_family(title: str) -> str:
    title = _normalize_text(title)
    title = title.replace("'", "")
    title = title.replace('"', "")
    title = re.sub(r"\s+", " ", title)
    return title


def retrieve_benchmarks(
    domain: str,
    query_tags: list[str] | None = None,
    query_keywords: list[str] | None = None,
    section_hint: list[str] | None = None,
    max_results: int = 5
) -> list[dict]:
    """
    Retrieves the most relevant benchmark/control entries from the domain catalog.
    Collapses similar entries so AI gets one representative benchmark per control family.
    """
    query_tags = _normalize_list(query_tags or [])
    query_keywords = _normalize_list(query_keywords or [])
    section_hint = _normalize_list(section_hint or [])

    catalog = load_catalog(domain)
    if not catalog:
        return []

    scored = []
    for entry in catalog:
        score = _score_entry(entry, query_tags, query_keywords, section_hint)
        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)

    family_best = {}

    for score, entry in scored:
        family_key = _normalize_title_for_family(entry.get("title", ""))

        if not family_key:
            family_key = (
                str(entry.get("benchmark_id", "")),
                str(entry.get("source_benchmark", "")),
            )

        if family_key not in family_best:
            family_best[family_key] = {
                "score": score,
                "entry": entry,
                "source_benchmarks_considered": set(
                    [entry.get("source_benchmark")] if entry.get("source_benchmark") else []
                )
            }
        else:
            family_best[family_key]["source_benchmarks_considered"].update(
                [entry.get("source_benchmark")] if entry.get("source_benchmark") else []
            )

    collapsed = sorted(
        family_best.values(),
        key=lambda item: item["score"],
        reverse=True
    )

    results = []
    for item in collapsed[:max_results]:
        entry = item["entry"]
        results.append({
            "benchmark_id": entry.get("benchmark_id"),
            "source_benchmark": entry.get("source_benchmark"),
            "source_benchmarks_considered": sorted(item["source_benchmarks_considered"]),
            "framework": entry.get("framework"),
            "title": entry.get("title"),
            "section": entry.get("section"),
            "profile_level": entry.get("profile_level"),
            "description": entry.get("description"),
            "rationale": entry.get("rationale"),
            "audit_procedure": entry.get("audit_procedure"),
            "remediation": entry.get("remediation"),
            "references": entry.get("references"),
            "tags": entry.get("tags", []),
            "keywords": entry.get("keywords", []),
        })

    return results