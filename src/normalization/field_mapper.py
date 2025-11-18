from typing import Dict, Any, Optional
import logging


class FieldMapper:
    
    def __init__(self):
        """Initialize field mapper with predefined mappings."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initializeMappings()
    
    def _initializeMappings(self) -> None:
        """Initialize field mapping configurations for each provider."""
        
        # AWS CloudTrail 
        self.awsCloudtrailMapping = {
            'eventId': 'eventID',
            'eventName': 'eventName',
            'eventTime': 'eventTime',
            'username': 'userIdentity.userName',
            'user_type': 'userIdentity.type',
            'source_ip': 'sourceIPAddress',
            'user_agent': 'userAgent',
            'aws_region': 'awsRegion',
            'error_code': 'errorCode',
            'error_message': 'errorMessage'
        }
        
        # Azure Activity Logs 
        self.azureActivityMapping = {
            'eventId': 'operationId',
            'eventName': 'operationName.value',
            'eventTime': 'eventTimestamp',
            'caller': 'caller',
            'level': 'level',
            'status': 'status.value',
            'resource_id': 'resourceId',
            'subscriptionId': 'subscriptionId'
        }
        
        # GCP Audit Logs 
        self.gcpAuditMapping = {
            'method_name': 'protoPayload.methodName',
            'service_name': 'protoPayload.serviceName',
            'principal_email': 'protoPayload.authenticationInfo.principalEmail',
            'caller_ip': 'protoPayload.requestMetadata.callerIp',
            'status_code': 'protoPayload.status.code',
            'resource_name': 'protoPayload.resourceName'
        }
    
    def mapFields(
        self,
        source_data: Dict[str, Any],
        mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        mappedData = {}
        
        for target_field, source_path in mapping.items():
            value = self._extractNestedField(source_data, source_path)
            if value is not None:
                mappedData[target_field] = value
        
        return mappedData
    
    def _extractNestedField(
        self,
        data: Dict[str, Any],
        field_path: str
    ) -> Optional[Any]:
        try:
            keys = field_path.split('.')
            value = data
            
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    return None
                
                if value is None:
                    return None
            
            return value
        
        except Exception as e:
            self.logger.debug(f"Error extracting field {field_path}: {e}")
            return None
    
    def getMappingForSource(self, source: str) -> Dict[str, str]:
        mappingMap = {
            'aws_cloudtrail': self.awsCloudtrailMapping,
            'azure_activity_logs': self.azureActivityMapping,
            'gcp_audit_logs': self.gcpAuditMapping
        }
        
        return mappingMap.get(source, {})
