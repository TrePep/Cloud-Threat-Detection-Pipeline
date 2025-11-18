# Defines the structure of security alerts.
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import hashlib
import json


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Alert status."""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    # Security alert representation
    alertId: str
    title: str
    description: str
    severity: AlertSeverity
    eventId: str
    detectionMethods: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    status: AlertStatus = AlertStatus.NEW
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    fingerprint: Optional[str] = None
    
    firstSeen: datetime = field(default_factory=datetime.utcnow)
    lastSeen: datetime = field(default_factory=datetime.utcnow)
    occurrenceCount: int = 1
    
    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self.generate_fingerprint()
    
    def generate_fingerprint(self) -> str:
        # Generate unique fingerprint for deduplication.
        fp_data = {
            'title': self.title,
            'severity': self.severity.value,
            'detectionMethods': sorted(self.detectionMethods),
            'indicators': sorted(self.indicators)[:5] 
        }
        
        fp_string = json.dumps(fp_data, sort_keys=True)
        return hashlib.sha256(fp_string.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        # Convert alert to dictionary.
        data = asdict(self)
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        data['timestamp'] = self.timestamp.isoformat()
        data['firstSeen'] = self.firstSeen.isoformat()
        data['lastSeen'] = self.lastSeen.isoformat()
        return data
    
    def to_markdown(self) -> str:
        #format alert as markdown for notifications.
        md = f"## {self.title}\n\n"
        md += f"**Severity:** {self.severity.value.upper()}\n"
        md += f"**Alert ID:** `{self.alertId}`\n"
        md += f"**Event ID:** `{self.eventId}`\n"
        md += f"**Timestamp:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        
        md += f"**Description:**\n{self.description}\n\n"
        
        if self.detectionMethods:
            md += f"**Detection Methods:** {', '.join(self.detectionMethods)}\n\n"
        
        if self.indicators:
            md += "**Indicators:**\n"
            for indicator in self.indicators[:10]: 
                md += f"- {indicator}\n"
            if len(self.indicators) > 10:
                md += f"- ... and {len(self.indicators) - 10} more\n"
            md += "\n"
        
        if self.occurrenceCount > 1:
            md += f"**Occurrences:** {self.occurrenceCount}\n"
            md += f"**First Seen:** {self.firstSeen.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            md += f"**Last Seen:** {self.lastSeen.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        
        if self.metadata:
            md += "**Additional Context:**\n"
            for key, value in list(self.metadata.items())[:5]:
                md += f"- **{key}:** {value}\n"
        
        return md
    
    def updateOccurrenceCount(self) -> None:
        """Update occurrence count and last seen time."""
        self.occurrenceCount += 1
        self.lastSeen = datetime.utcnow()
