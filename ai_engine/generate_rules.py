import json
import os
import re
import sys
import logging
import xml.etree.ElementTree as ET
from datetime import datetime

# Add current directory to path so llm_client import works
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from llm_client import query_llm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# -----------------------
# PATHS
# -----------------------
SUMMARY_FILE = "/opt/siem-ai/data/summary.json"
SKILLS_FILE = "/opt/siem-ai/knowledge/skills.md"
PREV_SUGGESTIONS = "/opt/siem-ai/reports/latest_suggestions.json"
RULE_ID_TRACKER = "/opt/siem-ai/data/rule_id_tracker.json"
REPORT_DIR = "/opt/siem-ai/reports"
FAILED_DIR = "/opt/siem-ai/reports/failed"

# -----------------------
# CONTEXT BUDGET
# -----------------------
MAX_TOP_RULES = 8
MAX_HIGH_SEV = 5
MAX_PREV_IDS = 5


# -----------------------
# SYSTEM PROMPT
# -----------------------
def build_system_prompt(skills: str) -> str:
    return f"""You are a Wazuh SIEM rule engineer. Analyze alert summaries and suggest detection rules.
Respond with a single valid JSON object only. No markdown. No text outside the JSON.

Output schema:
{{
  "analysis_time": "<ISO 8601 timestamp>",
  "threat_summary": "<2-3 sentences describing current threat patterns>",
  "new_rule_suggestions": [
    {{
      "id": "<exact ID from the reserved list>",
      "title": "<short descriptive title>",
      "severity": "<critical|high|medium|low>",
      "mitre_tactic": "<Txxxx - Name>",
      "rationale": "<1-2 sentences: why this rule is needed based on the alerts>",
      "wazuh_rule_xml": "<single valid Wazuh rule XML string, escape all quotes>",
      "false_positive_notes": "<one sentence>"
    }}
  ],
  "changes_from_last_run": "<1-2 sentences on what is new vs previous suggestions>"
}}

## Reference knowledge:
{skills}"""


# -----------------------
# USER PROMPT
# -----------------------
def build_prompt(
    summary: dict,
    prev_rule_ids: list,
    reserved_ids: list
) -> str:

    current = summary.get("current_window", {})
    historical = summary.get("historical_window", {})
    diff = summary.get("diff", {})

    # Trim context to stay within model budget
    top_rules = current.get(
        "top_rules", []
    )[:MAX_TOP_RULES]

    high_sev = current.get(
        "high_severity_sample", []
    )[:MAX_HIGH_SEV]

    # Strip potentially large fields
    for alert in high_sev:
        alert.pop("full_log", None)
        alert.pop("data", None)

    prev_context = (
        f"Previously suggested rule IDs: "
        f"{', '.join(prev_rule_ids)}. "
        "Do not suggest these IDs again."
        if prev_rule_ids
        else "No previous suggestions — this is the first run."
    )

    new_rules_this_window = diff.get(
        "new_rules_this_window",
        []
    )

    diff_context = (
        "New rules seen this window "
        "(not in history): "
        f"{json.dumps(new_rules_this_window, indent=2)}"
        if new_rules_this_window
        else "No new rule types vs historical window."
    )

    return f"""## Current alert window ({current.get('total_alerts', 0)} total, {current.get('filtered_alerts', 0)} after noise filter):

### Top triggered rules:
{json.dumps(top_rules, indent=2)}

### High severity alerts (level 10+):
{json.dumps(high_sev, indent=2)}

### Historical context:
- Total historical alerts: {historical.get('total_alerts', 0)}
- Top historical rules: {json.dumps(historical.get('top_rules', [])[:5], indent=2)}

### What changed vs history:
{diff_context}

### Continuity:
{prev_context}

## Your task:
Suggest exactly 3-5 new Wazuh detection rules that address gaps in coverage.
Use ONLY these reserved rule IDs in order: {', '.join(reserved_ids)}
Rules must be valid Wazuh XML.
Escape all special characters inside XML strings.
Respond with JSON only."""


# -----------------------
# SIMPLIFIED RETRY PROMPT
# -----------------------
def build_retry_prompt(
    summary: dict,
    reserved_ids: list
) -> str:

    top_rules = (
        summary
        .get("current_window", {})
        .get("top_rules", [])[:5]
    )

    return f"""## Top triggered Wazuh rules (last analysis window):
{json.dumps(top_rules, indent=2)}

Suggest exactly 3 new Wazuh detection rules for gaps in coverage.
Use these rule IDs: {', '.join(reserved_ids[:3])}

Respond with JSON only.
Follow the output schema exactly."""


# -----------------------
# RULE ID TRACKER
# -----------------------
def get_next_rule_ids(count: int) -> list:

    tracker = {
        "last_id": 100000
    }

    if os.path.exists(RULE_ID_TRACKER):
        with open(RULE_ID_TRACKER) as f:
            tracker = json.load(f)

    ids = []

    for _ in range(count):
        tracker["last_id"] += 1
        ids.append(
            str(tracker["last_id"])
        )

    with open(RULE_ID_TRACKER, "w") as f:
        json.dump(
            tracker,
            f
        )

    return ids


# -----------------------
# XML VALIDATOR
# -----------------------
def validate_rule_xml(xml_str: str) -> tuple:

    try:

        # Wrap generated rule to create a valid XML root
        wrapped = (
            f"<group name='test'>"
            f"{xml_str}"
            f"</group>"
        )

        root = ET.fromstring(wrapped)

        rules = root.findall("rule")

        if not rules:
            return False, "No <rule> element found"

        for rule in rules:

            if "id" not in rule.attrib:
                return False, "Rule missing 'id' attribute"

            if "level" not in rule.attrib:
                return False, "Rule missing 'level' attribute"

            if rule.find("description") is None:
                return False, "Rule missing <description> tag"

        return True, "OK"

    except ET.ParseError as e:

        return False, f"XML parse error: {e}"


# -----------------------
# JSON PARSER
# -----------------------
def parse_llm_response(raw: str) -> dict | None:

    # Remove common markdown fences
    clean = re.sub(
        r'```json\s*|\s*```',
        '',
        raw.strip()
    )

    # Extract JSON object if the model
    # added text around the response
    match = re.search(
        r'\{.*\}',
        clean,
        re.DOTALL
    )

    if not match:
        return None

    try:

        return json.loads(
            match.group()
        )

    except json.JSONDecodeError as e:

        log.warning(
            f"JSON decode error: {e}"
        )

        return None


# -----------------------
# LOAD HELPERS
# -----------------------
def load_json(path: str, fallback):

    if not os.path.exists(path):
        return fallback

    with open(path) as f:
        return json.load(f)


def load_skills() -> str:

    if os.path.exists(SKILLS_FILE):

        with open(SKILLS_FILE) as f:
            return f.read()

    log.warning(
        "skills.md not found — "
        "LLM will run without domain knowledge"
    )

    return ""


# -----------------------
# MAIN
# -----------------------
def main():

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    os.makedirs(
        FAILED_DIR,
        exist_ok=True
    )

    # -----------------------
    # LOAD INPUTS
    # -----------------------
    summary = load_json(
        SUMMARY_FILE,
        fallback={}
    )

    if not summary:

        log.error(
            "summary.json is empty or missing — "
            "run analyze_alerts.py first"
        )

        raise SystemExit(1)

    prev = load_json(
        PREV_SUGGESTIONS,
        fallback={}
    )

    prev_rule_ids = [
        rule.get("id")
        for rule in prev.get(
            "new_rule_suggestions",
            []
        )
        if rule.get("id")
    ][-MAX_PREV_IDS:]

    skills = load_skills()

    # -----------------------
    # RESERVE RULE IDs
    # -----------------------
    reserved_ids = get_next_rule_ids(5)

    log.info(
        f"Reserved rule IDs: {reserved_ids}"
    )

    # -----------------------
    # ATTEMPT 1
    # -----------------------
    log.info(
        "Querying LLM (attempt 1)..."
    )

    system_prompt = build_system_prompt(
        skills
    )

    prompt = build_prompt(
        summary,
        prev_rule_ids,
        reserved_ids
    )

    try:

        raw = query_llm(
            prompt,
            system=system_prompt
        )

        result = parse_llm_response(
            raw
        )

    except RuntimeError as e:

        log.error(
            f"LLM call failed: {e}"
        )

        raise SystemExit(1)

    # -----------------------
    # ATTEMPT 2
    # -----------------------
    if result is None:

        log.warning(
            "Attempt 1 parse failed — "
            "saving raw output and retrying..."
        )

        ts = datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )

        with open(
            f"{FAILED_DIR}/raw_failed_{ts}.txt",
            "w"
        ) as f:

            f.write(raw)

        try:

            retry_prompt = build_retry_prompt(
                summary,
                reserved_ids
            )

            raw = query_llm(
                retry_prompt,
                system=system_prompt
            )

            result = parse_llm_response(
                raw
            )

        except RuntimeError as e:

            log.error(
                f"LLM retry call failed: {e}"
            )

            raise SystemExit(1)

    # -----------------------
    # GIVE UP AFTER RETRY
    # -----------------------
    if result is None:

        log.error(
            "Both attempts failed. "
            "Saving raw output."
        )

        ts = datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )

        with open(
            f"{FAILED_DIR}/raw_failed_{ts}_retry.txt",
            "w"
        ) as f:

            f.write(raw)

        raise SystemExit(1)

    # -----------------------
    # VALIDATE XML
    # -----------------------
    for suggestion in result.get(
        "new_rule_suggestions",
        []
    ):

        xml = suggestion.get(
            "wazuh_rule_xml",
            ""
        )

        ok, reason = validate_rule_xml(
            xml
        )

        suggestion["xml_valid"] = ok

        suggestion["xml_validation_note"] = (
            None if ok else reason
        )

        if not ok:

            log.warning(
                f"Rule {suggestion.get('id')} "
                f"XML invalid: {reason}"
            )

    # -----------------------
    # ENFORCE MAX 5 RULES
    # -----------------------
    result["new_rule_suggestions"] = (
        result.get(
            "new_rule_suggestions",
            []
        )[:5]
    )

    # -----------------------
    # SAVE LATEST
    # -----------------------
    with open(
        PREV_SUGGESTIONS,
        "w"
    ) as f:

        json.dump(
            result,
            f,
            indent=2
        )

    # -----------------------
    # SAVE TIMESTAMPED REPORT
    # -----------------------
    ts = datetime.utcnow().strftime(
        "%Y%m%d_%H%M%S"
    )

    timestamped_path = (
        f"{REPORT_DIR}/"
        f"suggestions_{ts}.json"
    )

    with open(
        timestamped_path,
        "w"
    ) as f:

        json.dump(
            result,
            f,
            indent=2
        )

    valid_count = sum(
        1
        for rule in result[
            "new_rule_suggestions"
        ]
        if rule.get("xml_valid")
    )

    log.info(
        f"Done — "
        f"{len(result['new_rule_suggestions'])} suggestions, "
        f"{valid_count} with valid XML. "
        f"Saved to {timestamped_path}"
    )


if __name__ == "__main__":
    main()
