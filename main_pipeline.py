import subprocess
import logging
import os
import sys
from datetime import datetime

# -----------------------
# PATHS
# -----------------------
BASE_DIR = "/opt/siem-ai"

COLLECTOR = os.path.join(
    BASE_DIR,
    "collector",
    "fetch_alerts.py"
)

ANALYZER = os.path.join(
    BASE_DIR,
    "analyzer",
    "analyze_alerts.py"
)

RULE_GENERATOR = os.path.join(
    BASE_DIR,
    "ai_engine",
    "generate_rules.py"
)

LOG_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

LOG_FILE = os.path.join(
    LOG_DIR,
    "pipeline.log"
)

# Use the same Python interpreter running this script.
# When main_pipeline.py runs inside the venv,
# all child scripts will also use the venv Python.
PYTHON = sys.executable

# -----------------------
# LOGGING
# -----------------------
os.makedirs(
    LOG_DIR,
    exist_ok=True
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

log = logging.getLogger(__name__)


# -----------------------
# RUN PIPELINE STAGE
# -----------------------
def run_stage(name: str, script: str) -> bool:
    """
    Execute one pipeline stage.

    Returns True on success and False on failure.
    """

    log.info(
        f"Starting pipeline stage: {name}"
    )

    if not os.path.exists(script):

        log.error(
            f"{name} script not found: {script}"
        )

        return False

    try:

        result = subprocess.run(
            [PYTHON, script],
            capture_output=True,
            text=True,
            timeout=600
        )

        if result.stdout:

            log.info(
                f"{name} output:\n"
                f"{result.stdout.strip()}"
            )

        if result.returncode != 0:

            log.error(
                f"{name} failed with "
                f"exit code {result.returncode}"
            )

            if result.stderr:

                log.error(
                    f"{name} error:\n"
                    f"{result.stderr.strip()}"
                )

            return False

        log.info(
            f"{name} completed successfully."
        )

        return True

    except subprocess.TimeoutExpired:

        log.error(
            f"{name} timed out after 600 seconds."
        )

        return False

    except Exception as e:

        log.exception(
            f"Unexpected error while running {name}: {e}"
        )

        return False


# -----------------------
# MAIN PIPELINE
# -----------------------
def main():

    start_time = datetime.utcnow()

    log.info(
        "=" * 60
    )

    log.info(
        "Starting SIEM AI pipeline"
    )

    # -----------------------
    # STAGE 1 — COLLECT
    # -----------------------
    if not run_stage(
        "Alert Collector",
        COLLECTOR
    ):

        log.error(
            "Pipeline stopped: "
            "alert collection failed."
        )

        raise SystemExit(1)

    # -----------------------
    # STAGE 2 — ANALYZE
    # -----------------------
    if not run_stage(
        "Alert Analyzer",
        ANALYZER
    ):

        log.error(
            "Pipeline stopped: "
            "alert analysis failed."
        )

        raise SystemExit(1)

    # -----------------------
    # STAGE 3 — AI RULE GENERATION
    # -----------------------
    if not run_stage(
        "AI Rule Generator",
        RULE_GENERATOR
    ):

        log.error(
            "Pipeline stopped: "
            "AI rule generation failed."
        )

        raise SystemExit(1)

    # -----------------------
    # COMPLETE
    # -----------------------
    end_time = datetime.utcnow()

    duration = (
        end_time - start_time
    ).total_seconds()

    log.info(
        f"SIEM AI pipeline completed successfully "
        f"in {duration:.2f} seconds."
    )

    log.info(
        "=" * 60
    )


if __name__ == "__main__":
    main()
