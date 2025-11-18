# AWS Ingestion Connector

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional, Iterator, List
from datetime import datetime, timedelta
import json

from .base import BaseIngestion


class AWSIngestion(BaseIngestion):
    
    def __init__(self, config: Dict[str, Any]):
        self.s3_client = None
        self.cloudtrailClient = None
        self.guarddutyClient = None
        self.logsClient = None
        super().__init__(config)
    
    def _initializeClient(self) -> None:
        try:
            sessionConfig = {
                'region_name': self.config.get('region', 'us-east-1')
            }
            
            #Add credentials if provided
            if 'access_key_id' in self.config and 'secret_access_key' in self.config:
                sessionConfig['aws_access_key_id'] = self.config['access_key_id']
                sessionConfig['aws_secret_access_key'] = self.config['secret_access_key']
            
            self.s3_client = boto3.client('s3', **sessionConfig)
            self.cloudtrailClient = boto3.client('cloudtrail', **sessionConfig)
            self.guarddutyClient = boto3.client('guardduty', **sessionConfig)
            self.logsClient = boto3.client('logs', **sessionConfig)
            
            self.logger.info("AWS clients initialized successfully")
        except Exception as e:
            self.handleError(e, "AWS client initialization")
            raise
    
    def getRequiredFields(self) -> List[str]:
        return ['region']
    
    def testConnection(self) -> bool:
        try:
            stsClient = boto3.client('sts')
            response = stsClient.get_caller_identity()
            self.logger.info(f"AWS connection successful. Account: {response['Account']}")
            return True
        except (ClientError, BotoCoreError) as e:
            self.handleError(e, "AWS connection test")
            return False
    
    def fetchLogs(
        self,
        startTime: Optional[datetime] = None,
        endTime: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        # Set default time range if not provided
        if not endTime:
            endTime = datetime.utcnow()
        if not startTime:
            startTime = endTime - timedelta(hours=1)
        
        if self.config.get('cloudtrail', {}).get('enabled', False):
            yield from self._fetchCloudtrailLogs(startTime, endTime, filters)
        
        if self.config.get('guardduty', {}).get('enabled', False):
            yield from self._fetchGuarddutyFindings(startTime, endTime, filters)
        
        if self.config.get('vpc_flow_logs', {}).get('enabled', False):
            yield from self._fetchVpcFlowLogs(startTime, endTime, filters)
        
        self.lastIngestionTime = datetime.utcnow()
    
    def _fetchCloudtrailLogs(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        try:
            cloudtrailConfig = self.config.get('cloudtrail', {})
            
            response = self.cloudtrailClient.lookup_events(
                StartTime=startTime,
                EndTime=endTime,
                MaxResults=50
            )
            
            for event in response.get('Events', []):
                yield {
                    'source': 'aws_cloudtrail',
                    'eventId': event.get('EventId'),
                    'eventName': event.get('EventName'),
                    'eventTime': event.get('EventTime'),
                    'username': event.get('Username'),
                    'resources': event.get('Resources', []),
                    'cloud_trail_event': json.loads(event.get('CloudTrailEvent', '{}')),
                    'rawEvent': event
                }
            
            
        except (ClientError, BotoCoreError) as e:
            self.handleError(e, "CloudTrail log fetching")
    
    def _fetchGuarddutyFindings(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        try:
            # Get list of detectors
            detectorsResponse = self.guarddutyClient.list_detectors()
            detectorIds = detectorsResponse.get('DetectorIds', [])
            
            for detector_id in detectorIds:
                # Get findings within time range
                findingsResponse = self.guarddutyClient.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'updatedAt': {
                                'Gte': int(startTime.timestamp() * 1000),
                                'Lte': int(endTime.timestamp() * 1000)
                            }
                        }
                    }
                )
                
                findingIds = findingsResponse.get('FindingIds', [])
                
                if findingIds:
                    findingsDetails = self.guarddutyClient.get_findings(
                        DetectorId=detector_id,
                        FindingIds=findingIds
                    )
                    
                    for finding in findingsDetails.get('Findings', []):
                        yield {
                            'source': 'aws_guardduty',
                            'detector_id': detector_id,
                            'finding_id': finding.get('Id'),
                            'severity': finding.get('Severity'),
                            'type': finding.get('Type'),
                            'title': finding.get('Title'),
                            'description': finding.get('Description'),
                            'resource': finding.get('Resource'),
                            'service': finding.get('Service'),
                            'raw_finding': finding
                        }
        
        except (ClientError, BotoCoreError) as e:
            self.handleError(e, "GuardDuty findings fetching")
    
    def _fetchVpcFlowLogs(
        self,
        startTime: datetime,
        endTime: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        try:
            logGroupName = self.config.get('vpc_flow_logs', {}).get('logGroupName')
            
            if not logGroupName:
                self.logger.warning("VPC Flow Logs log group not configured")
                return
            
            response = self.logsClient.filter_log_events(
                logGroupName=logGroupName,
                startTime=int(startTime.timestamp() * 1000),
                endTime=int(endTime.timestamp() * 1000),
                limit=1000
            )
            
            for event in response.get('events', []):
                message = event.get('message', '')
                fields = message.split()
                
                if len(fields) >= 14:  
                    yield {
                        'source': 'aws_vpc_flow_logs',
                        'timestamp': event.get('timestamp'),
                        'account_id': fields[1] if len(fields) > 1 else None,
                        'interface_id': fields[2] if len(fields) > 2 else None,
                        'src_addr': fields[3] if len(fields) > 3 else None,
                        'dst_addr': fields[4] if len(fields) > 4 else None,
                        'src_port': fields[5] if len(fields) > 5 else None,
                        'dst_port': fields[6] if len(fields) > 6 else None,
                        'protocol': fields[7] if len(fields) > 7 else None,
                        'packets': fields[8] if len(fields) > 8 else None,
                        'bytes': fields[9] if len(fields) > 9 else None,
                        'action': fields[12] if len(fields) > 12 else None,
                        'raw_message': message
                    }
        
        except (ClientError, BotoCoreError) as e:
            self.handleError(e, "VPC Flow Logs fetching")
