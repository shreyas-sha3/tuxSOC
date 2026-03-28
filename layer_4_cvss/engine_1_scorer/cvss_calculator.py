from cvss import CVSS3

def calculate_base_score(vector_string: str) -> float:
    """Calculates the 0.0 to 10.0 score from the vector string."""
    try:
        c = CVSS3(vector_string)
        return c.scores()[0]  # scores()[0] is the Base Score
    except Exception as e:
        print(f"Error calculating score for {vector_string}: {e}")
        return 0.0 # Fail-safe score
