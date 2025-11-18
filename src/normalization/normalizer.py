from typing import Dict, Any, Optional
from datetime import datetime
import logging

from .schema import UnifiedEventSchema, EventType, Severity, OutcomeStatus, Actor, Resource, NetworkContext
from .field_mapper import FieldMapper
from .enrichment import EventEnricher


class LogNormalizer:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.fieldMapper = FieldMapper()
        self.enricher = EventEnricher(config.get('enrichment', {}))
    
    def normalize(self, rawEvent: Dict[str, Any]) -> Optional[UnifiedEventSchema]:
        try:
            source = rawEvent.get('source', '')
            
            if source.startswith('aws_'):
                return self._normalizeAws(rawEvent)
            elif source.startswith('azure_'):
                return self._normalizeAzure(rawEvent)
            elif source.startswith('gcp_'):
                return self._normalizeGcp(rawEvent)
            else:
                self.logger.warning(f"Unknown event source: {source}")
                return None
        
        except Exception as e:
            self.logger.error(f"Error normalizing event: {e}", exc_info=True)
            return None
    
    def _normalizeAws(self, rawEvent: Dict[str, Any]) -> Optional[UnifiedEventSchema]:
        source = rawEvent.get('source')
        
        if source == 'aws_cloudtrail':
            return self._normalizeAwsCloudtrail(rawEvent)
        elif source == 'aws_guardduty':
            return self._normalizeAwsGuardduty(rawEvent)
        elif source == 'aws_vpc_flow_logs':
            return self._normalizeAwsVpcFlow(rawEvent)
        
        return None
    
    def _normalizeAwsCloudtrail(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        ctEvent = rawEvent.get('cloud_trail_event', rawEvent)
        
        eventName = ctEvent.get('eventName', rawEvent.get('eventName', ''))
        eventType = self._classifyAwsEvent(eventName)
        
        userIdentity = ctEvent.get('userIdentity', {})
        actor = Actor(
            username=userIdentity.get('userName') or rawEvent.get('username'),
            userId=userIdentity.get('principalId'),
            userType=userIdentity.get('type'),
            ipAddress=ctEvent.get('sourceIPAddress'),
            userAgent=ctEvent.get('userAgent'),
            sessionId=userIdentity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName')
        )
        
        resources = rawEvent.get('resources', [])
        resource = None
        if resources:
            res = resources[0]
            resource = Resource(
                resourceId=res.get('ARN'),
                resourceType=res.get('ResourceType'),
                resourceName=res.get('ResourceName'),
                accountId=ctEvent.get('recipientAccountId')
            )
        
        outcome = OutcomeStatus.SUCCESS
        errorCode = ctEvent.get('errorCode')
        if errorCode:
            outcome = OutcomeStatus.FAILURE
        
        timestamp = datetime.utcnow()
        event_time_str = ctEvent.get('eventTime', rawEvent.get('eventTime'))
        if event_time_str:
            try:
                from dateutil import parser
                timestamp = parser.parse(event_time_str)
            except Exception as e:
                self.logger.warning(f"Failed to parse timestamp '{event_time_str}': {e}")
        
        event = UnifiedEventSchema(
            eventId=ctEvent.get('eventID', rawEvent.get('eventId', '')),
            timestamp=timestamp,
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=eventType,
            eventName=eventName,
            eventCategory=ctEvent.get('eventCategory'),
            severity=Severity.INFO,
            actor=actor,
            resource=resource,
            action=eventName,
            outcome=outcome,
            outcome_reason=ctEvent.get('errorMessage'),
            requestParameters=ctEvent.get('requestParameters', {}),
            responseElements=ctEvent.get('responseElements', {}),
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        
        return event
    
    def _normalizeAwsGuardduty(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        severityMap = {
            0: Severity.INFO,
            1: Severity.LOW,
            2: Severity.LOW,
            3: Severity.LOW,
            4: Severity.MEDIUM,
            5: Severity.MEDIUM,
            6: Severity.MEDIUM,
            7: Severity.HIGH,
            8: Severity.HIGH,
            9: Severity.CRITICAL,
            10: Severity.CRITICAL
        }
        
        gdSeverity = rawEvent.get('severity', 0)
        if isinstance(gdSeverity, (int, float)):
            severity = severityMap.get(int(gdSeverity), Severity.MEDIUM)
        else:
            severity = Severity.MEDIUM
        
        network = None
        serviceInfo = rawEvent.get('service', {})
        action = serviceInfo.get('action', {})
        if action.get('actionType') == 'NETWORK_CONNECTION':
            networkInfo = action.get('networkConnectionAction', {})
            network = NetworkContext(
                sourceIp=networkInfo.get('remoteIpDetails', {}).get('ipAddressV4'),
                destinationIp=networkInfo.get('localIpDetails', {}).get('ipAddressV4'),
                destinationPort=networkInfo.get('localPortDetails', {}).get('port'),
                protocol=networkInfo.get('protocol')
            )
        
        event = UnifiedEventSchema(
            eventId=rawEvent.get('finding_id', ''),
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='guardduty',
            eventType=EventType.SECURITY_ALERT,
            eventName=rawEvent.get('type', ''),
            severity=severity,
            network=network,
            description=rawEvent.get('description'),
            threatIndicators=[rawEvent.get('type', '')],
            risk_score=float(gdSeverity) / 10.0,
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        return event
    
    def _normalizeAwsVpcFlow(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        network = NetworkContext(
            sourceIp=rawEvent.get('src_addr'),
            sourcePort=int(rawEvent.get('src_port', 0)) if rawEvent.get('src_port') else None,
            destinationIp=rawEvent.get('dst_addr'),
            destinationPort=int(rawEvent.get('dst_port', 0)) if rawEvent.get('dst_port') else None,
            protocol=rawEvent.get('protocol'),
            bytesSent=int(rawEvent.get('bytes', 0)) if rawEvent.get('bytes') else None,
            packets=int(rawEvent.get('packets', 0)) if rawEvent.get('packets') else None,
            action=rawEvent.get('action')
        )
        
        event = UnifiedEventSchema(
            eventId=f"vpc_flow_{rawEvent.get('timestamp')}",
            timestamp=datetime.fromtimestamp(int(rawEvent.get('timestamp', 0)) / 1000) if rawEvent.get('timestamp') else datetime.utcnow(),
            sourceProvider='aws',
            sourceService='vpc_flow_logs',
            eventType=EventType.NETWORK_TRAFFIC,
            eventName='network_connection',
            severity=Severity.INFO,
            network=network,
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        return event
    
    def _normalizeAzure(self, rawEvent: Dict[str, Any]) -> Optional[UnifiedEventSchema]:
        source = rawEvent.get('source')
        
        if source == 'azure_activity_logs':
            return self._normalizeAzureActivity(rawEvent)
        elif source == 'azure_security_center':
            return self._normalizeAzureSecurity(rawEvent)
        
        return None
    
    def _normalizeAzureActivity(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        severityMap = {
            'Critical': Severity.CRITICAL,
            'Error': Severity.HIGH,
            'Warning': Severity.MEDIUM,
            'Informational': Severity.INFO
        }
        
        actor = Actor(
            email=rawEvent.get('caller'),
            userId=rawEvent.get('caller')
        )
        
        resource = Resource(
            resourceId=rawEvent.get('resourceId'),
            resourceName=rawEvent.get('resource_group'),
            resourceType='azure_resource'
        )
        
        event = UnifiedEventSchema(
            eventId=rawEvent.get('event_data_id', ''),
            timestamp=rawEvent.get('event_timestamp', datetime.utcnow()),
            sourceProvider='azure',
            sourceService='activityLogs',
            eventType=EventType.ADMINISTRATIVE_ACTION,
            eventName=rawEvent.get('operation_name', ''),
            eventCategory=rawEvent.get('category'),
            severity=severityMap.get(rawEvent.get('level', ''), Severity.INFO),
            actor=actor,
            resource=resource,
            action=rawEvent.get('operation_name'),
            outcome=OutcomeStatus.SUCCESS if rawEvent.get('status') == 'Succeeded' else OutcomeStatus.FAILURE,
            description=rawEvent.get('description'),
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        return event
    
    def _normalizeAzureSecurity(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        severityMap = {
            'High': Severity.HIGH,
            'Medium': Severity.MEDIUM,
            'Low': Severity.LOW,
            'Informational': Severity.INFO
        }
        
        event = UnifiedEventSchema(
            eventId=rawEvent.get('alertId', ''),
            timestamp=rawEvent.get('time_generated', datetime.utcnow()),
            sourceProvider='azure',
            sourceService='security_center',
            eventType=EventType.SECURITY_ALERT,
            eventName=rawEvent.get('display_name', ''),
            severity=severityMap.get(rawEvent.get('severity', ''), Severity.MEDIUM),
            description=rawEvent.get('description'),
            threatIndicators=[rawEvent.get('alert_type', '')],
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        return event
    
    def _normalizeGcp(self, rawEvent: Dict[str, Any]) -> Optional[UnifiedEventSchema]:
        source = rawEvent.get('source')
        
        if source in ['gcp_audit_logs', 'gcp_cloud_logging']:
            return self._normalizeGcpLog(rawEvent)
        
        return None
    
    def _normalizeGcpLog(self, rawEvent: Dict[str, Any]) -> UnifiedEventSchema:
        severityMap = {
            'CRITICAL': Severity.CRITICAL,
            'ERROR': Severity.HIGH,
            'WARNING': Severity.MEDIUM,
            'INFO': Severity.INFO,
            'DEBUG': Severity.INFO
        }
        
        actor = Actor(
            email=rawEvent.get('principal_email'),
            userId=rawEvent.get('principal_email')
        )
        
        resourceInfo = rawEvent.get('resource', {})
        resource = Resource(
            resourceType=resourceInfo.get('type'),
            resourceName=resourceInfo.get('labels', {}).get('resourceName')
        )
        
        event = UnifiedEventSchema(
            eventId=rawEvent.get('raw_entry', {}).get('insertId', ''),
            timestamp=rawEvent.get('timestamp', datetime.utcnow()),
            sourceProvider='gcp',
            sourceService=rawEvent.get('source'),
            eventType=self._classifyGcpEvent(rawEvent.get('method_name', '')),
            eventName=rawEvent.get('method_name', ''),
            severity=severityMap.get(rawEvent.get('severity', 'INFO'), Severity.INFO),
            actor=actor,
            resource=resource,
            action=rawEvent.get('method_name'),
            requestParameters=rawEvent.get('request', {}),
            responseElements=rawEvent.get('response', {}),
            rawEvent=rawEvent
        )
        
        self.enricher.enrich(event)
        return event
    
    def _classifyAwsEvent(self, eventName: str) -> EventType:
        eventNameLower = eventName.lower()
        
        if 'login' in eventNameLower or 'authenticate' in eventNameLower:
            return EventType.AUTHENTICATION
        elif 'authorize' in eventNameLower or 'policy' in eventNameLower:
            return EventType.AUTHORIZATION
        elif 'create' in eventNameLower or 'delete' in eventNameLower or 'update' in eventNameLower:
            return EventType.CONFIGURATION_CHANGE
        elif 'get' in eventNameLower or 'list' in eventNameLower or 'describe' in eventNameLower:
            return EventType.RESOURCE_ACCESS
        else:
            return EventType.UNKNOWN
    
    def _classifyGcpEvent(self, method_name: str) -> EventType:
        methodLower = method_name.lower()
        
        if 'login' in methodLower or 'authenticate' in methodLower:
            return EventType.AUTHENTICATION
        elif 'create' in methodLower or 'delete' in methodLower or 'update' in methodLower:
            return EventType.CONFIGURATION_CHANGE
        elif 'get' in methodLower or 'list' in methodLower:
            return EventType.RESOURCE_ACCESS
        else:
            return EventType.UNKNOWN
