import requests
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# -----------------------
# CONFIG
# -----------------------

# Replace with the private IP or hostname of the VM running Ollama.
# Do not expose real infrastructure addresses in a public repository.
OLLAMA_HOST = "http://YOUR_OLLAMA_VM_IP:11434"

MODEL = "llama3"

# LLM inference can be slow when running on CPU-only VMs.
TIMEOUT = 180

# -----------------------
# HEALTH CHECK
# -----------------------
def is_ollama_reachable() -> bool:
    """
    Check whether the Ollama API is reachable before
    attempting a full LLM inference request.
    """

    try:
        response = requests.get(
            f"{OLLAMA_HOST}/api/tags",
            timeout=5
        )

        return response.status_code == 200

    except requests.exceptions.RequestException:
        return False


# -----------------------
# MAIN LLM CALLER
# -----------------------
def query_llm(prompt: str, system: str = "") -> str:
    """
    Send a prompt to Ollama and return the generated response.

    Raises RuntimeError if Ollama cannot be reached,
    the request times out, or an invalid HTTP response is returned.
    """

    if not is_ollama_reachable():
        raise RuntimeError(
            f"Ollama is not reachable at {OLLAMA_HOST}. "
            "Check network connectivity and verify that "
            "the Ollama service is running."
        )

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,

        "options": {
            # Lower temperature for more consistent rule generation
            "temperature": 0.3,

            # Maximum generated output
            "num_predict": 2048,

            # Context window
            "num_ctx": 8192,

            "top_p": 0.9,

            # Discourage repetitive output
            "repeat_penalty": 1.1
        }
    }

    try:

        log.info(
            f"Sending request to Ollama ({MODEL})..."
        )

        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json=payload,
            timeout=TIMEOUT
        )

        response.raise_for_status()

        result = response.json()

        if "response" not in result:
            raise RuntimeError(
                f"Unexpected Ollama response structure: {result}"
            )

        # Log token usage when returned by Ollama
        if "eval_count" in result:

            log.info(
                f"Tokens — "
                f"prompt: {result.get('prompt_eval_count', '?')}, "
                f"output: {result.get('eval_count', '?')}"
            )

        return result["response"]

    except requests.exceptions.Timeout:

        raise RuntimeError(
            f"Ollama request timed out after {TIMEOUT} seconds. "
            "Consider reducing the prompt size or increasing TIMEOUT."
        )

    except requests.exceptions.ConnectionError as e:

        raise RuntimeError(
            f"Connection error reaching Ollama: {e}"
        )

    except requests.exceptions.HTTPError as e:

        raise RuntimeError(
            f"Ollama HTTP error: {e}. "
            f"Response: {response.text}"
        )
