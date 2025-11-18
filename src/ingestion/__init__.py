"""
Log Ingestion Module

This module handles ingestion of logs from multiple cloud providers:
- AWS (CloudTrail, GuardDuty, VPC Flow Logs)
- Azure (Activity Logs, Security Center)
- GCP (Audit Logs, Cloud Logging)

Architecture:
- Base ingestion interface for all connectors
- Provider-specific implementations
- Authentication and credential management
- Polling and streaming support
- Error handling and retry logic
"""

from .base import BaseIngestion
from .aws_ingestion import AWSIngestion
from .azure_ingestion import AzureIngestion
from .gcp_ingestion import GCPIngestion
from .ingestion_manager import IngestionManager

__all__ = [
    'BaseIngestion',
    'AWSIngestion',
    'AzureIngestion',
    'GCPIngestion',
    'IngestionManager',
]
