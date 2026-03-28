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

    # Merge LLM metrics with defaults
    final_metrics = {**defaults, **metrics}

    vector_parts = [
        f"AV:{final_metrics['AV']}",
        f"AC:{final_metrics['AC']}",
        f"PR:{final_metrics['PR']}",
        f"UI:{final_metrics['UI']}",
        f"S:{final_metrics['S']}",
        f"C:{final_metrics['C']}",
        f"I:{final_metrics['I']}",
        f"A:{final_metrics['A']}"
    ]

    return "CVSS:3.1/" + "/".join(vector_parts)
