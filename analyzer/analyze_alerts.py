import json
import os
import logging
from datetime import datetime
from collections import Counter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# -----------------------
# PATHS
# -----------------------
ALERTS_FILE = "/opt/siem-ai/data/alerts.json"
HISTORY_FILE = "/opt/siem-ai/data/alerts_history.json"
SUMMARY_FILE = "/opt/siem-ai/data/summary.json"

# -----------------------
# TUNING
# -----------------------
TOP_RULES_LIMIT = 8
HIGH_SEV_LIMIT = 5
MIN_LEVEL_INCLUDE = 4
HIGH_SEV_THRESHOLD = 10

# -----------------------
# LOADERS
# -----------------------
def load_json(path: str, fallback):
    if not os.path.exists(path):
        log.warning(f"{path} not found — using fallback.")
        return fallback

    try:
        with open(path) as f:
            return json.load(f)

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse {path}: {e}")
        return fallback


# -----------------------
# CORE SUMMARIZER
# -----------------------
def summarize(alerts: list) -> dict:
    """
    Compress a list of alerts into a summary for the LLM.
    Raw full_log and data fields are not included in the summary.
    """

    if not alerts:
        return {
            "total_alerts": 0,
            "filtered_alerts": 0,
            "top_rules": [],
            "high_severity_sample": [],
            "unique_source_ips": [],
            "agents_involved": []
        }

    # Filter alerts below configured severity threshold
    filtered = [
        a for a in alerts
        if a.get("rule_level") is not None
        and int(a.get("rule_level", 0)) >= MIN_LEVEL_INCLUDE
    ]

    log.info(
        f"Summarizing {len(filtered)}/{len(alerts)} alerts "
        f"(filtered alerts below level {MIN_LEVEL_INCLUDE})"
    )

    # -----------------------
    # TOP RULES
    # -----------------------
    rule_counter = Counter()
    rule_meta = {}

    for alert in filtered:
        rule_id = alert.get("rule_id")

        if not rule_id:
            continue

        rule_counter[rule_id] += 1

        if rule_id not in rule_meta:
            rule_meta[rule_id] = {
                "rule_id": rule_id,
                "rule_level": alert.get("rule_level"),
                "rule_description": alert.get("rule_description"),
                "groups": alert.get("groups", []),
                "mitre": alert.get("mitre", {})
            }

    top_rules = []

    for rule_id, count in rule_counter.most_common(TOP_RULES_LIMIT):
        entry = dict(rule_meta[rule_id])
        entry["count"] = count
        top_rules.append(entry)

    # -----------------------
    # HIGH SEVERITY ALERTS
    # -----------------------
    high_sev_raw = [
        alert for alert in filtered
        if int(alert.get("rule_level", 0)) >= HIGH_SEV_THRESHOLD
    ]

    # Highest severity alerts first
    high_sev_raw.sort(
        key=lambda x: int(x.get("rule_level", 0)),
        reverse=True
    )

    high_severity = []

    for alert in high_sev_raw[:HIGH_SEV_LIMIT]:
        high_severity.append({
            "rule_id": alert.get("rule_id"),
            "rule_level": alert.get("rule_level"),
            "rule_description": alert.get("rule_description"),
            "agent_name": alert.get("agent_name"),
            "timestamp": alert.get("timestamp"),
            "srcip": alert.get("srcip"),
            "mitre": alert.get("mitre", {}),
            "groups": alert.get("groups", [])
        })

    # -----------------------
    # SOURCE IP ANALYSIS
    # -----------------------
    all_ips = [
        alert.get("srcip")
        for alert in filtered
        if alert.get("srcip")
        and alert.get("srcip") not in ("127.0.0.1", "::1")
    ]

    ip_counter = Counter(all_ips)

    unique_ips = [
        {
            "ip": ip,
            "count": count
        }
        for ip, count in ip_counter.most_common(10)
    ]

    # -----------------------
    # AGENT ANALYSIS
    # -----------------------
    agent_counter = Counter(
        alert.get("agent_name")
        for alert in filtered
        if alert.get("agent_name")
    )

    agents = [
        {
            "agent": name,
            "alert_count": count
        }
        for name, count in agent_counter.most_common(5)
    ]

    return {
        "total_alerts": len(alerts),
        "filtered_alerts": len(filtered),
        "top_rules": top_rules,
        "high_severity_sample": high_severity,
        "unique_source_ips": unique_ips,
        "agents_involved": agents
    }


# -----------------------
# DIFF VS HISTORY
# -----------------------
def diff_vs_history(current: dict, historical: dict) -> dict:
    """
    Compare current top rule IDs against historical top rule IDs.
    """

    current_rule_ids = {
        r["rule_id"]
        for r in current.get("top_rules", [])
    }

    history_rule_ids = {
        r["rule_id"]
        for r in historical.get("top_rules", [])
    }

    new_rule_ids = current_rule_ids - history_rule_ids
    recurring_ids = current_rule_ids & history_rule_ids
    resolved_ids = history_rule_ids - current_rule_ids

    new_rules_detail = [
        rule
        for rule in current.get("top_rules", [])
        if rule["rule_id"] in new_rule_ids
    ]

    return {
        "new_rules_this_window": new_rules_detail,
        "recurring_rule_ids": list(recurring_ids),
        "resolved_rule_ids": list(resolved_ids),
        "new_rule_count": len(new_rule_ids),
        "recurring_rule_count": len(recurring_ids),
        "resolved_rule_count": len(resolved_ids)
    }


# -----------------------
# MAIN
# -----------------------
def main():

    log.info("Starting alert analysis...")

    alerts = load_json(
        ALERTS_FILE,
        fallback=[]
    )

    history = load_json(
        HISTORY_FILE,
        fallback=[]
    )

    if not alerts:
        log.warning(
            "No alerts to analyze. Writing empty summary."
        )

    current_summary = summarize(alerts)
    historical_summary = summarize(history)

    diff = diff_vs_history(
        current_summary,
        historical_summary
    )

    summary = {
        "generated_at": datetime.utcnow().isoformat(),

        "current_window": current_summary,

        "historical_window": {
            "total_alerts": historical_summary["total_alerts"],
            "filtered_alerts": historical_summary["filtered_alerts"],
            "top_rules": historical_summary["top_rules"][:5],
            "agents_involved": historical_summary["agents_involved"]
        },

        "diff": diff
    }

    os.makedirs(
        os.path.dirname(SUMMARY_FILE),
        exist_ok=True
    )

    with open(SUMMARY_FILE, "w") as f:
        json.dump(
            summary,
            f,
            indent=2
        )

    log.info(
        f"Summary written — "
        f"{current_summary['total_alerts']} alerts, "
        f"{current_summary['filtered_alerts']} after filter, "
        f"{len(current_summary['high_severity_sample'])} high severity, "
        f"{diff['new_rule_count']} new rules vs history."
    )


if __name__ == "__main__":
    main()
