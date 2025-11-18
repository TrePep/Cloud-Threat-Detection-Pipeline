#Azure

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from typing import Dict, Any, Optional, Iterator, List
from datetime import datetime, timedelta
import logging

from .base import BaseIngestion


class AzureIngestion(BaseIngestion):
    
    def __init__(self, config: Dict[str, Any]):

        self.credential = None
        self.monitorClient = None
        self.securityClient = None
        super().__init__(config)
    
    def _initializeClient(self) -> None:
        try:
            if all(k in self.config for k in ['tenantId', 'clientId', 'clientSecret']):
                self.credential = ClientSecretCredential(
                    tenantId=self.config['tenantId'],
                    clientId=self.config['clientId'],
                    clientSecret=self.config['clientSecret']
                )
            else:
                self.credential = DefaultAzureCredential()
            
            subscriptionId = self.config.get('subscriptionId')
            
            #Initialize clients
            self.monitorClient = MonitorManagementClient(
                self.credential,
                subscriptionId
            )
            
            self.securityClient = SecurityCenter(
                self.credential,
                subscriptionId,
                ascLocation='centralus'  #centeralus is default location
            )
            
            self.logger.info("Azure clients initialized successfully")
        except Exception as e:
            self.handleError(e, "Azure client initialization")
            raise
    
    def getRequiredFields(self) -> List[str]:
        return ['subscriptionId']
    
    def testConnection(self) -> bool:
        try:
            list(self.monitorClient.activityLogs.list(
                filter=f"eventTimestamp ge '{datetime.utcnow().isoformat()}Z'",
                select='eventName'
            ))
            self.logger.info("Azure connection successful")
            return True
        except Exception as e:
            self.handleError(e, "Azure connection test")
            return False
    
    def fetchLogs(
        self,
        startTime: Optional[datetime] = None,
        endTime: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        # Set default time range
        if not endTime:
            endTime = datetime.utcnow()
        if not startTime:
            startTime = endTime - timedelta(hours=1)
        
        # Fetch from each enabled service
        if self.config.get('activityLogs', {}).get('enabled', False):
            yield from self._fetchActivityLogs(startTime, endTime, filters)
        
        if self.config.get('security_center', {}).get('enabled', False):
            yield from self._fetchSecurityCenterAlerts(startTime, endTime, filters)
        
        self.lastIngestionTime = datetime.utcnow()
    
    def _fetchActivityLogs(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        """
        Fetch Azure Activity Logs.
        
        Yields:
            Activity log events
        """
        try:
            # Build OData filter
            filterStr = (
                f"eventTimestamp ge '{startTime.isoformat()}Z' and "
                f"eventTimestamp le '{endTime.isoformat()}Z'"
            )
            
            # Fetch activity logs
            activityLogs = self.monitorClient.activityLogs.list(
                filter=filterStr,
                select='eventTimestamp,level,operationName,resourceId,resourceGroupName,status'
            )
            
            for log in activityLogs:
                yield {
                    'source': 'azure_activity_logs',
                    'event_timestamp': log.event_timestamp,
                    'level': log.level,
                    'operation_name': log.operation_name.value if log.operation_name else None,
                    'resource_id': log.resource_id,
                    'resource_group': log.resource_group_name,
                    'status': log.status.value if log.status else None,
                    'caller': log.caller,
                    'correlation_id': log.correlation_id,
                    'description': log.description,
                    'event_data_id': log.event_data_id,
                    'category': log.category.value if log.category else None,
                    'rawEvent': {
                        'operationName': str(log.operation_name),
                        'status': str(log.status),
                        'properties': log.properties
                    }
                }
        
        except Exception as e:
            self.handleError(e, "Azure Activity Logs fetching")
    
    def _fetchSecurityCenterAlerts(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        """
        Fetch Azure Security Center alerts.
        
        Yields:
            Security Center alerts
        """
        try:
            # Fetch security alerts
            alerts = self.securityClient.alerts.list()
            
            for alert in alerts:
                # Filter by time
                alertTime = getattr(alert, 'time_generated_utc', None)
                if alertTime and startTime <= alertTime <= endTime:
                    yield {
                        'source': 'azure_security_center',
                        'alert_id': alert.id,
                        'alert_name': alert.name,
                        'alert_type': alert.type,
                        'display_name': alert.alert_display_name,
                        'description': alert.description,
                        'severity': alert.severity,
                        'status': alert.status,
                        'time_generated': alert.time_generated_utc,
                        'compromised_entity': alert.compromised_entity,
                        'remediation_steps': alert.remediation_steps,
                        'extended_properties': alert.extended_properties,
                        'raw_alert': {
                            'id': alert.id,
                            'name': alert.name,
                            'properties': {
                                'severity': alert.severity,
                                'status': alert.status,
                                'description': alert.description
                            }
                        }
                    }
        
        except Exception as e:
            self.handleError(e, "Azure Security Center alerts fetching")
