# AI-Assisted Wazuh SIEM Tuning

An AI-assisted detection engineering system that analyzes Wazuh SIEM alerts and uses a locally hosted Large Language Model (LLM) to generate Wazuh detection rule suggestions.

The project was created to explore how AI can assist SOC analysts and detection engineers with repetitive SIEM analysis and rule tuning tasks.

> **Status:** Work in progress. The core alert collection, analysis, and AI rule suggestion pipeline is operational.

---

## Project Overview

SIEM platforms can generate large volumes of security alerts. Manually reviewing alert patterns and identifying opportunities for rule tuning can become time-consuming as the environment grows.

This project creates an automated pipeline that periodically:

1. Collects Wazuh alerts from the Wazuh Indexer.
2. Maintains a rolling history of previous alerts.
3. Analyzes current and historical alert patterns.
4. Identifies frequently triggered rules and high-severity events.
5. Extracts information about source IPs and affected agents.
6. Compares current activity with historical patterns.
7. Sends a structured alert summary to a locally hosted LLM.
8. Generates Wazuh detection rule suggestions.
9. Validates the basic XML structure of generated rules.
10. Saves the suggestions for analyst review.

The AI-generated rules are recommendations only and are not automatically deployed to Wazuh.

---

## Architecture

```text
Wazuh Agents
      │
      ▼
Wazuh Manager
      │
      ▼
Wazuh Indexer (OpenSearch)
      │
      ▼
┌─────────────────────────────┐
│      AI / Analysis VM       │
│                             │
│  Alert Collector            │
│        │                    │
│        ▼                    │
│  Alert Analyzer             │
│        │                    │
│        ▼                    │
│  Structured Summary         │
│        │                    │
│        ▼                    │
│  Ollama + Llama             │
│        │                    │
│        ▼                    │
│  Rule Suggestions           │
└─────────────────────────────┘
      │
      ▼
Analyst Review
```

The Wazuh infrastructure and AI analysis components run on cloud virtual machines connected through private networking.

---

## How It Works

The complete processing flow is:

```text
fetch_alerts.py
      │
      ▼
alerts.json
alerts_history.json
      │
      ▼
analyze_alerts.py
      │
      ▼
summary.json
      │
      ▼
generate_rules.py
      │
      ├──── skills.md
      │
      └──── llm_client.py
                 │
                 ▼
             Ollama / Llama
                 │
                 ▼
      latest_suggestions.json
      suggestions_<timestamp>.json
```

`main_pipeline.py` orchestrates the collector, analyzer, and AI rule generation stages.

---

## Project Structure

```text
wazuh-ai-siem-tuning/
│
├── collector/
│   └── fetch_alerts.py
│
├── analyzer/
│   └── analyze_alerts.py
│
├── ai_engine/
│   ├── llm_client.py
│   └── generate_rules.py
│
├── knowledge/
│   └── skills.md
│
├── examples/
│   ├── sample_alert.json
│   ├── sample_summary.json
│   └── sample_suggestions.json
│
├── main_pipeline.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

Runtime directories such as `data/`, `reports/`, `logs/`, and `venv/` are excluded from version control.

---

## Components

### Alert Collector

`collector/fetch_alerts.py`

Connects to the Wazuh Indexer through OpenSearch and retrieves new Wazuh alerts.

The collector:

- Queries Wazuh alert indexes.
- Tracks the previous collection time.
- Uses OpenSearch scrolling for larger result sets.
- Maintains a current alert batch.
- Maintains a rolling historical alert dataset.
- Prevents duplicate alerts from being added to history.

---

### Alert Analyzer

`analyzer/analyze_alerts.py`

Processes collected alerts before they are sent to the LLM.

The analyzer extracts information including:

- Total alert volume.
- Frequently triggered Wazuh rules.
- High-severity alerts.
- Source IP frequency.
- Agents generating alerts.
- Current vs. historical rule patterns.

Instead of sending large amounts of raw log data directly to the LLM, the analyzer produces a smaller structured summary. This reduces unnecessary context and allows the model to focus on relevant security patterns.

---

### AI Rule Generation Engine

`ai_engine/generate_rules.py`

The AI engine combines:

- Current alert analysis.
- Historical alert patterns.
- Previous AI suggestions.
- Detection engineering guidance from `skills.md`.

The structured context is then sent to a locally hosted LLM.

The model is instructed to return structured JSON containing:

- A threat summary.
- Suggested Wazuh detection rules.
- Rule rationale.
- Severity.
- MITRE ATT&CK context.
- Potential false-positive information.

Generated XML is checked for basic structural validity before the recommendations are saved.

The system also maintains a rule ID tracker to help prevent generated custom rule ID collisions.

---

### LLM Client

`ai_engine/llm_client.py`

Provides communication between the Python pipeline and the Ollama API.

The current implementation is designed to use a locally hosted Llama model running through Ollama.

This allows the AI inference component to run on infrastructure controlled by the project rather than requiring alert summaries to be sent to an external hosted LLM service.

---

### Detection Engineering Knowledge Base

`knowledge/skills.md`

Contains reference guidance provided to the LLM when generating rule suggestions.

It includes guidance related to:

- Wazuh rule levels.
- Custom rule ID ranges.
- Wazuh XML structure.
- Noise reduction principles.
- Detection engineering practices.
- MITRE ATT&CK usage.
- Safe rule generation.

This file provides runtime context and instructions to the LLM. It does not fine-tune or retrain the underlying language model.

---

### Pipeline Orchestrator

`main_pipeline.py`

Runs the major pipeline stages in sequence:

```text
Alert Collection
      ↓
Alert Analysis
      ↓
AI Rule Generation
```

If an earlier stage fails, the pipeline stops instead of continuing with potentially stale or incomplete data.

Pipeline activity and errors are recorded for troubleshooting.

---

## Example Data

The `examples/` directory contains sanitized examples showing the different stages of the pipeline:

```text
sample_alert.json
        ↓
sample_summary.json
        ↓
sample_suggestions.json
```

This makes it possible to understand the project's data flow without requiring access to the original Wazuh environment.

The examples do not contain real infrastructure addresses, credentials, or production security logs.

---

## Technology Stack

- Wazuh
- OpenSearch
- Python
- Ollama
- Llama
- Azure Virtual Machines
- Azure Virtual Network

---

## Current Status

| Component | Status |
|---|---|
| Wazuh SIEM deployment | ✅ Complete |
| Wazuh agent integration | ✅ Complete |
| Alert collection | ✅ Complete |
| Rolling alert history | ✅ Complete |
| Alert analysis | ✅ Complete |
| Local LLM integration | ✅ Complete |
| AI-generated rule suggestions | ✅ Complete |
| Pipeline orchestration | ✅ Complete |
| Automatic rule deployment | ❌ Not implemented |

---

## Security Considerations

This repository contains sanitized code and example data.

The following information should never be committed:

- OpenSearch passwords.
- API keys.
- Internal or public infrastructure IP addresses.
- Private certificates or keys.
- Real security logs containing sensitive information.
- Environment-specific credentials.

AI-generated detection rules should always be reviewed and tested before deployment.

---

## Important Note About AI-Generated Rules

The LLM acts as an assistant to the detection engineering process, not as an autonomous security control.

The current system:

- Analyzes alert patterns.
- Suggests potential detection improvements.
- Generates candidate Wazuh XML rules.
- Performs basic XML structure validation.
- Saves recommendations for analyst review.

The current system does **not** automatically deploy generated rules into the production Wazuh environment.

Human review remains part of the workflow.

---

## Future Improvements

Planned improvements include:

- Improved alert trend and spike detection.
- Better comparison between historical and current alert behavior.
- Rule confidence scoring.
- Detection rule testing before recommendation.
- Better validation of Wazuh-specific rule semantics.
- Analyst feedback mechanisms.
- Measuring the effectiveness of accepted rule changes.
- Improved AI context management for larger alert volumes.

---

## Disclaimer

This project is intended for educational, research, and detection engineering experimentation.

AI-generated detection rules may contain logical errors, false positives, false negatives, or incomplete detection logic.

Generated rules should always be reviewed and tested by a security analyst before being deployed to a production environment.

---

## License

This project is licensed under the MIT License.
