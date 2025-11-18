#GCP Ingestion 

from google.cloud import logging as cloud_logging
from google.cloud.logging_v2 import Client as LoggingClient
from google.oauth2 import service_account
from typing import Dict, Any, Optional, Iterator, List
from datetime import datetime, timedelta
import json

from .base import BaseIngestion


class GCPIngestion(BaseIngestion):    
    def __init__(self, config: Dict[str, Any]):
        self.loggingClient = None
        self.credentials = None
        super().__init__(config)
    
    def _initializeClient(self) -> None:
        try:
            projectId = self.config.get('projectId')
            credentialsFile = self.config.get('credentialsFile')
            
            # Load credentials
            if credentialsFile:
                self.credentials = service_account.Credentials.from_service_account_file(
                    credentialsFile
                )
                self.loggingClient = LoggingClient(
                    project=projectId,
                    credentials=self.credentials
                )
            else:
                # Use Default
                self.loggingClient = LoggingClient(project=projectId)
            
            self.logger.info("GCP clients initialized successfully")
        except Exception as e:
            self.handleError(e, "GCP client initialization")
            raise
    
    def getRequiredFields(self) -> List[str]:
        return ['projectId']
    
    def testConnection(self) -> bool:
        try:
            list(self.loggingClient.list_entries(
                maxResults=1
            ))
            self.logger.info("GCP connection successful")
            return True
        except Exception as e:
            self.handleError(e, "GCP connection test")
            return False
    
    def fetchLogs(
        self,
        startTime: Optional[datetime] = None,
        endTime: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        if not endTime:
            endTime = datetime.utcnow()
        if not startTime:
            startTime = endTime - timedelta(hours=1)
        
        if self.config.get('audit_logs', {}).get('enabled', False):
            yield from self._fetchAuditLogs(startTime, endTime, filters)
        
        if self.config.get('cloud_logging', {}).get('enabled', False):
            yield from self._fetchCloudLogs(startTime, endTime, filters)
        
        self.lastIngestionTime = datetime.utcnow()
    
    def _fetchAuditLogs(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        """
        Fetch GCP Cloud Audit Logs.
        
        Yields:
            Audit log events
        """
        try:
            filterStr = (
                f'timestamp >= "{startTime.isoformat()}Z" AND '
                f'timestamp <= "{endTime.isoformat()}Z" AND '
                f'logName:"cloudaudit.googleapis.com"'
            )
            
            entries = self.loggingClient.list_entries(
                filter_=filterStr,
                orderBy='timestamp desc',
                pageSize=1000
            )
            
            for entry in entries:
                protoPayload = entry.payload if hasattr(entry, 'payload') else {}
                
                yield {
                    'source': 'gcp_audit_logs',
                    'log_name': entry.log_name,
                    'timestamp': entry.timestamp,
                    'severity': entry.severity,
                    'resource': {
                        'type': entry.resource.type if entry.resource else None,
                        'labels': dict(entry.resource.labels) if entry.resource else {}
                    },
                    'method_name': getattr(protoPayload, 'method_name', None),
                    'service_name': getattr(protoPayload, 'service_name', None),
                    'principal_email': getattr(protoPayload, 'authentication_info', {}).get('principal_email'),
                    'status': getattr(protoPayload, 'status', None),
                    'request': getattr(protoPayload, 'request', {}),
                    'response': getattr(protoPayload, 'response', {}),
                    'raw_entry': {
                        'logName': entry.log_name,
                        'severity': entry.severity,
                        'insertId': entry.insert_id,
                        'labels': dict(entry.labels) if entry.labels else {}
                    }
                }
        
        except Exception as e:
            self.handleError(e, "GCP Audit Logs fetching")
    
    def _fetchCloudLogs(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        try:
            filterStr = (
                f'timestamp >= "{startTime.isoformat()}Z" AND '
                f'timestamp <= "{endTime.isoformat()}Z"'
            )
            

            if filters and 'min_severity' in filters:
                filterStr += f' AND severity >= {filters["min_severity"]}'
            
            entries = self.loggingClient.list_entries(
                filter_=filterStr,
                orderBy='timestamp desc',
                pageSize=1000
            )
            
            for entry in entries:
                yield {
                    'source': 'gcp_cloud_logging',
                    'log_name': entry.log_name,
                    'timestamp': entry.timestamp,
                    'severity': entry.severity,
                    'resource': {
                        'type': entry.resource.type if entry.resource else None,
                        'labels': dict(entry.resource.labels) if entry.resource else {}
                    },
                    'text_payload': entry.payload if isinstance(entry.payload, str) else None,
                    'json_payload': entry.payload if isinstance(entry.payload, dict) else None,
                    'labels': dict(entry.labels) if entry.labels else {},
                    'trace': entry.trace,
                    'span_id': entry.span_id,
                    'raw_entry': {
                        'logName': entry.log_name,
                        'severity': entry.severity,
                        'insertId': entry.insert_id
                    }
                }
        
        except Exception as e:
            self.handleError(e, "GCP Cloud Logging fetching")
