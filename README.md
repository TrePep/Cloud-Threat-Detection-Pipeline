# Cloud Threat Detection Pipeline

A real-time cloud security threat detection system that ingests logs from AWS, Azure, and GCP, applies detection rules, identifies anomalies, and sends alerts through multiple channels.

## Features

- **Multi-Cloud Log Ingestion** - AWS CloudTrail, Azure Activity Logs, GCP Audit Logs
- **Unified Schema Normalization** - Standardized event format across all cloud providers
- **Triple Detection Engine** - Rule-based, ML anomaly detection, and heuristic analysis
- **Multi-Channel Alerts** - Slack, Email, PagerDuty, and custom webhooks
- **Sample Data Testing** - Test without cloud credentials using generated sample logs

## Quick Start

```bash
# Clone and install
git clone <repository-url>
cd cloud-threat-detection
python -m venv venv
venv\Scripts\activate  
pip install -r requirements.txt

# Test with sample data (no credentials needed
python quick_test.py

# Run all tests
pytest tests/ -v

# Configure for production
cp config\config.example.yaml config\config.yaml
# Edit config\config.yaml with your credentials

# Run the pipeline
python -m src.main
```

## Project Structure

```
src/
├── ingestion/          # Cloud provider log connectors
├── normalization/      # Schema normalization and enrichment
├── detection/          # Rule-based, anomaly, and heuristic engines
├── alerting/           # Alert management and notification channels
└── utils/              # Configuration, logging, and metrics

config/                 # Configuration files
rules/                  # YAML detection rule definitions
models/                 # ML models for anomaly detection
tests/                  # Unit and integration tests
```

## Detection Rules

Create custom rules in `rules/` directory:

```yaml
name: suspicious_privilege_escalation
severity: high
description: Detects attempts to escalate privileges
conditions:
  - field: eventName
    operator: in
    value: [AssumeRole, AddUserToGroup, PutUserPolicy]
  - field: errorCode
    operator: not_equals
    value: AccessDenied
```

## Configuration

Edit `config/config.yaml`:

```yaml



