# ollama_client.py
# Location: layer_3_ai_analysis/ollama_client.py
#
# PURPOSE:
# Manages the connection to the local Ollama server.
# All LLM inference happens here — nothing leaves the machine.
# This is the privacy-preserving core of Layer 3.
#
# WHY LANGCHAIN-OLLAMA:
# LangChain's Ollama integration handles connection pooling,
# retry logic, and response streaming cleanly.
# We use it instead of raw HTTP to keep the code simple
# and consistent with the rest of the LangChain stack.
#
# CALLED BY:
# agent_nodes.py — every node calls run_inference()


from langchain_ollama import OllamaLLM


# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

OLLAMA_BASE_URL    = "http://localhost:11434"
OLLAMA_MODEL       = "llama3"

# Temperature 0 = deterministic output
# For security analysis we want consistent,
# repeatable results — not creative variation
OLLAMA_TEMPERATURE = 0


# ─────────────────────────────────────────
# CLIENT BUILDER
# ─────────────────────────────────────────

def get_ollama_client() -> OllamaLLM:
    """
    Returns a configured OllamaLLM client instance.
    Called once per node inference call.

    Returns:
        OllamaLLM: configured LangChain Ollama client
    """
    return OllamaLLM(
        base_url    = OLLAMA_BASE_URL,
        model       = OLLAMA_MODEL,
        temperature = OLLAMA_TEMPERATURE
    )


# ─────────────────────────────────────────
# CONNECTION CHECKER
# ─────────────────────────────────────────

def check_ollama_connection() -> dict:
    """
    Verifies Ollama server is reachable and model is available.
    Returns a status dict — never raises an exception.

    Returns:
        {
            "connected": True | False,
            "model":     "llama3.2:3b",
            "error":     None | str
        }
    """
    try:
        import requests
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=5
        )

        if response.status_code == 200:
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]

            # Check if our model is available
            model_available = any(
                OLLAMA_MODEL in name for name in model_names
            )

            if model_available:
                return {
                    "connected": True,
                    "model":     OLLAMA_MODEL,
                    "error":     None
                }
            else:
                return {
                    "connected": False,
                    "model":     OLLAMA_MODEL,
                    "error":     f"Model {OLLAMA_MODEL} not found. "
                                 f"Available: {model_names}"
                }
        else:
            return {
                "connected": False,
                "model":     OLLAMA_MODEL,
                "error":     f"Ollama returned status {response.status_code}"
            }

    except Exception as e:
        return {
            "connected": False,
            "model":     OLLAMA_MODEL,
            "error":     str(e)
        }


# ─────────────────────────────────────────
# INFERENCE RUNNER
# ─────────────────────────────────────────

def run_inference(prompt: str) -> dict:
    """
    Sends a prompt to Ollama and returns the response.
    Wraps the call in error handling so pipeline never breaks.

    Args:
        prompt: fully constructed prompt string from prompt_builder

    Returns:
        {
            "success":  True | False,
            "response": str | None,
            "error":    None | str
        }
    """
    try:
        client   = get_ollama_client()
        response = client.invoke(prompt)

        return {
            "success":  True,
            "response": response,
            "error":    None
        }

    except Exception as e:
        return {
            "success":  False,
            "response": None,
            "error":    str(e)
        }