# AI-Assisted Wazuh SIEM Tuning

An AI-assisted detection engineering system that analyzes Wazuh SIEM alerts and uses a locally hosted Large Language Model (LLM) to generate Wazuh detection rule suggestions.

The project was created to explore how AI can assist SOC analysts and detection engineers with repetitive SIEM analysis and rule tuning tasks.

> **Status:** Work in progress. The core alert collection, analysis, and AI rule suggestion pipeline is operational.

---

## Overview

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
│        AI / Analysis VM     │
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
