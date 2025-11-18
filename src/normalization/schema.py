from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class EventType(Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RESOURCE_ACCESS = "resource_access"
    NETWORK_TRAFFIC = "network_traffic"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_ACCESS = "data_access"
    SECURITY_ALERT = "security_alert"
    ADMINISTRATIVE_ACTION = "administrative_action"
    UNKNOWN = "unknown"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OutcomeStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


@dataclass
class Actor:
    userId: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    userType: Optional[str] = None  # human, service_account, system
    sessionId: Optional[str] = None
    ipAddress: Optional[str] = None
    userAgent: Optional[str] = None
    geo_location: Optional[Dict[str, Any]] = None


@dataclass
class Resource:
    resourceId: Optional[str] = None
    resourceType: Optional[str] = None
    resourceName: Optional[str] = None
    accountId: Optional[str] = None
    region: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkContext:
    sourceIp: Optional[str] = None
    source_port: Optional[int] = None
    destinationIp: Optional[str] = None
    destinationPort: Optional[int] = None
    protocol: Optional[str] = None
    bytesSent: Optional[int] = None
    bytesReceived: Optional[int] = None
    packets: Optional[int] = None
    action: Optional[str] = None  # allow, deny, drop


@dataclass
class UnifiedEventSchema:
    eventId: str
    timestamp: datetime
    sourceProvider: str  
    sourceService: str   
    eventType: EventType
    eventName: str
    eventCategory: Optional[str] = None
    severity: Severity = Severity.INFO
    
    actor: Optional[Actor] = None
    
    resource: Optional[Resource] = None
    
    network: Optional[NetworkContext] = None
    
    action: Optional[str] = None
    outcome: OutcomeStatus = OutcomeStatus.UNKNOWN
    outcome_reason: Optional[str] = None
    
    description: Optional[str] = None
    requestParameters: Dict[str, Any] = field(default_factory=dict)
    responseElements: Dict[str, Any] = field(default_factory=dict)
    
    enrichment: Dict[str, Any] = field(default_factory=dict)
    
    threatIndicators: List[str] = field(default_factory=list)
    risk_score: Optional[float] = None
    
    rawEvent: Dict[str, Any] = field(default_factory=dict)
    
    ingestion_timestamp: datetime = field(default_factory=datetime.utcnow)
    normalization_timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        
        data['eventType'] = self.eventType.value
        data['severity'] = self.severity.value
        data['outcome'] = self.outcome.value
        
        data['timestamp'] = self.timestamp.isoformat()
        data['ingestion_timestamp'] = self.ingestion_timestamp.isoformat()
        data['normalization_timestamp'] = self.normalization_timestamp.isoformat()
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UnifiedEventSchema':
        # Convert string enums back to enum types
        if 'eventType' in data and isinstance(data['eventType'], str):
            data['eventType'] = EventType(data['eventType'])
        
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = Severity(data['severity'])
        
        if 'outcome' in data and isinstance(data['outcome'], str):
            data['outcome'] = OutcomeStatus(data['outcome'])
        
        # Convert ISO strings back to datetime
        for field_name in ['timestamp', 'ingestion_timestamp', 'normalization_timestamp']:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])
        
        return cls(**data)
    
    def validate(self) -> bool:
        if not self.eventId:
            raise ValueError("eventId is required")
        
        if not self.timestamp:
            raise ValueError("timestamp is required")
        
        if not self.sourceProvider:
            raise ValueError("sourceProvider is required")
        
        if not self.eventName:
            raise ValueError("eventName is required")
        
        return True
