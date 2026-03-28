def build_vector_string(metrics: dict) -> str:
    """
    Converts a dictionary of metrics into a CVSS v3.1 vector string.
    Includes fallback logic if the LLM misses a required metric.
    """
    # Define safe defaults (assuming lowest impact if missing)
    defaults = {
        "AV": "L", "AC": "H", "PR": "H", "UI": "R",
        "S": "U", "C": "N", "I": "N", "A": "N"
    }

    # Ensure all metrics are strings, uppercase, and stripped of whitespace
    clean_metrics = {}
    for k, v in metrics.items():
        if isinstance(v, str):
            val = v.strip().upper()
            
            # Map "Medium" to "Low" (CVSS 3.1 compatibility for LLM hallucinations)
            if val.startswith("M"):
                val = "L"
            elif val and len(val) > 1 and val[0] in "NALPHRUC":
                val = val[0]
                
            clean_metrics[k] = val

    valid_choices = {
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "R"},
        "S":  {"U", "C"},
        "C":  {"H", "L", "N"},
        "I":  {"H", "L", "N"},
        "A":  {"H", "L", "N"}
    }

    final_metrics = {}
    for k in defaults.keys():
        val = clean_metrics.get(k, defaults[k])
        if val not in valid_choices[k]:
            val = defaults[k]
        final_metrics[k] = val

    vector_parts = [
        f"AV:{final_metrics.get('AV', 'L')}",
        f"AC:{final_metrics.get('AC', 'H')}",
        f"PR:{final_metrics.get('PR', 'H')}",
        f"UI:{final_metrics.get('UI', 'R')}",
        f"S:{final_metrics.get('S', 'U')}",
        f"C:{final_metrics.get('C', 'N')}",
        f"I:{final_metrics.get('I', 'N')}",
        f"A:{final_metrics.get('A', 'N')}"
    ]

    return "CVSS:3.1/" + "/".join(vector_parts)
