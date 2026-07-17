# AI-Assisted Wazuh SIEM Tuning

An AI-assisted detection engineering project that analyzes Wazuh SIEM alerts and generates Wazuh detection rule suggestions using a locally hosted LLM.

## Project Overview

SIEM platforms can generate a large number of repetitive alerts, making manual analysis and rule tuning time-consuming.

This project creates an automated pipeline that collects Wazuh alerts, analyzes alert patterns, and uses AI to suggest new detection rules.

## Architecture

Wazuh Agents
    ↓
Wazuh Manager
    ↓
Wazuh Indexer (OpenSearch)
    ↓
Alert Collector
    ↓
Alert Analyzer
    ↓
AI Engine (Ollama + Llama)
    ↓
Wazuh Rule Suggestions

## How It Works

1. Wazuh agents send security events to the Wazuh Manager.
2. Alerts are stored in the Wazuh Indexer.
3. The collector periodically retrieves new alerts.
4. A rolling alert history is maintained for historical analysis.
5. The analyzer identifies frequent rules, high-severity alerts, source IP patterns, and involved agents.
6. Current alerts are compared with historical patterns.
7. A structured summary is provided to a locally hosted LLM.
8. The AI generates Wazuh detection rule suggestions.
9. Generated XML rules are validated before being saved as recommendations.

## Current Status

- Wazuh SIEM deployment: ✅ Complete
- Wazuh agent integration: ✅ Complete
- Alert collection: ✅ Complete
- Rolling alert history: ✅ Complete
- Alert analysis: ✅ Complete
- Local LLM integration: ✅ Complete
- AI-generated rule suggestions: ✅ Complete
- Dashboard integration: 🚧 In Progress
- Automatic rule deployment: 🚧 Planned

## Technology Stack

- Wazuh
- OpenSearch
- Python
- Ollama
- Llama
- Azure Virtual Machines
- Azure Virtual Network

## Project Structure

    collector/
        fetch_alerts.py

    analyzer/
        analyze_alerts.py

    ai_engine/
        llm_client.py
        generate_rules.py
        push_to_dashboard.py

    knowledge/
        skills.md

    data/
        Runtime alert and analysis data

    reports/
        AI-generated rule suggestions

## Security

This repository contains sanitized code and example data only.

Passwords, credentials, internal IP addresses, production logs, and other sensitive information are not included.

## Disclaimer

AI-generated detection rules should always be reviewed and tested before being deployed to a production SIEM environment.

## Status

This project is currently under active development.
