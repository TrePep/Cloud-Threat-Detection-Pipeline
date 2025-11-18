# Alerting Manager
# Handles alert generation and notification via multiple channels.

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
from collections import defaultdict

from src.alerting.alert import Alert, AlertSeverity, AlertStatus
from src.alerting.channels import NotificationChannel, SlackChannel, EmailChannel, PagerDutyChannel, WebhookChannel
from src.detection.detection_manager import DetectionResult
from src.normalization.schema import UnifiedEventSchema


class AlertManager:

    # Manages security alerts and notification dispatch.    
    def __init__(self, config: Dict[str, Any]):
        # Initialize alert manager.
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        alertConfig = config.get('alerting', {})
        
        
        self.deduplicationEnabled = alertConfig.get('deduplication', {}).get('enabled', True)
        self.deduplicationWindowMinutes = alertConfig.get('deduplication', {}).get('time_window_minutes', 60)
        
        self.throttleEnabled = alertConfig.get('throttling', {}).get('enabled', True)
        self.maxAlertsPerHour = alertConfig.get('throttling', {}).get('max_alerts_per_hour', 100)
        
        self.activeAlerts: Dict[str, Alert] = {}
        
        self.alertHistory: List[datetime] = []
    
        self.channels: List[NotificationChannel] = []
        self.initializeChannels(alertConfig.get('channels', {}))
        
        self.logger.info("Alert manager initialized")
    
    def initializeChannels(self, channelsConfig: Dict[str, Any]) -> None:
        #Initialize notification channels.
        slackConfig = channelsConfig.get('slack', {})
        if slackConfig.get('enabled', False):
            try:
                channel = SlackChannel(slackConfig)
                self.channels.append(channel)
                self.logger.info("Slack channel initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Slack channel: {e}")
        
        emailConfig = channelsConfig.get('email', {})
        if emailConfig.get('enabled', False):
            try:
                channel = EmailChannel(emailConfig)
                self.channels.append(channel)
                self.logger.info("Email channel initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Email channel: {e}")
        
        pagerdutyConfig = channelsConfig.get('pagerduty', {})
        if pagerdutyConfig.get('enabled', False):
            try:
                channel = PagerDutyChannel(pagerdutyConfig)
                self.channels.append(channel)
                self.logger.info("PagerDuty channel initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize PagerDuty channel: {e}")
        
        webhookConfig = channelsConfig.get('webhook', {})
        if webhookConfig.get('enabled', False):
            try:
                channel = WebhookChannel(webhookConfig)
                self.channels.append(channel)
                self.logger.info("Webhook channel initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Webhook channel: {e}")
    
    def createAlert(
        self,
        detectionResult: DetectionResult,
        event: UnifiedEventSchema
    ) -> Optional[Alert]:
        if not detectionResult.overallThreatDetected:
            return None
        
        severity = self.determineSeverity(detectionResult)
        title = self.buildAlertTitle(detectionResult, event)
        description = self.buildAlertDescription(detectionResult, event)
        
        indicators = self.collectIndicators(detectionResult, event)
        
        alert = Alert(
            alertId=f"alert_{event.eventId}_{int(datetime.utcnow().timestamp())}",
            title=title,
            description=description,
            severity=severity,
            eventId=event.eventId,
            detectionMethods=detectionResult.detectionMethods,
            indicators=indicators,
            metadata={
                'sourceProvider': event.sourceProvider,
                'sourceService': event.sourceService,
                'eventType': event.eventType.value,
                'eventName': event.eventName,
                'overallScore': detectionResult.overallScore
            }
        )
        
        return alert
    
    def processAlert(self, alert: Alert) -> bool:
        #Process an alert through deduplication, throttling, and dispatch.


        if self.deduplicationEnabled:
            if self.isDuplicate(alert):
                self.logger.info(f"Alert deduplicated: {alert.fingerprint}")
                return False
        
        if self.throttleEnabled:
            if self.isThrottled():
                self.logger.warning("Alert throttled due to rate limit")
                return False
        
        self.dispatchAlert(alert)
        
        self.trackAlert(alert)
        
        return True
    
    def isDuplicate(self, alert: Alert) -> bool:
        existingAlert = self.activeAlerts.get(alert.fingerprint)
        
        if existingAlert:
            existingAlert.updateOccurrenceCount()
            
            timeDifference = datetime.utcnow() - existingAlert.first_seen
            if timeDifference.total_seconds() / 60 < self.deduplicationWindowMinutes:
                return True
            else:
                # Outside window, treat as new alert
                self.activeAlerts[alert.fingerprint] = alert
                return False
        else:
            self.activeAlerts[alert.fingerprint] = alert
            return False
    
    def isThrottled(self) -> bool:
        #Check if alerts are being throttled.
        cutoffTime = datetime.utcnow() - timedelta(hours=1)
        self.alertHistory = [ts for ts in self.alertHistory if ts > cutoffTime]
        
        return len(self.alertHistory) >= self.maxAlertsPerHour
    
    def trackAlert(self, alert: Alert) -> None:
        self.alertHistory.append(datetime.utcnow())
    
    def dispatchAlert(self, alert: Alert) -> None:
        #Dispatch alert to all configured channels.

        for channel in self.channels:
            try:
                if channel.should_notify(alert):
                    channel.send(alert)
                    self.logger.info(
                        f"Alert {alert.alert_id} sent to {channel.__class__.__name__}"
                    )
            except Exception as e:
                self.logger.error(
                    f"Error sending alert to {channel.__class__.__name__}: {e}"
                )
    
    def determineSeverity(self, detectionResult: DetectionResult) -> AlertSeverity:
        #Determine alert severity from detection result.
        if detectionResult.matchedRules:
            severity_priority = ['critical', 'high', 'medium', 'low', 'info']
            for sev in severity_priority:
                for rule in detectionResult.matchedRules:
                    if rule.severity == sev:
                        return AlertSeverity(sev)
        
        score = detectionResult.overallScore
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        elif score >= 0.7:
            return AlertSeverity.HIGH
        elif score >= 0.5:
            return AlertSeverity.MEDIUM
        elif score >= 0.3:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def buildAlertTitle(self, detectionResult: DetectionResult, event: UnifiedEventSchema) -> str:
        if detectionResult.matchedRules:
            return detectionResult.matchedRules[0].name
        elif detectionResult.anomalyResult.get('is_anomaly'):
            return f"Anomalous Activity Detected: {event.eventName}"
        elif detectionResult.heuristicResult.get('is_suspicious'):
            return f"Suspicious Activity Detected: {event.eventName}"
        else:
            return f"Security Event: {event.eventName}"
    
    def buildAlertDescription(self, detectionResult: DetectionResult, event: UnifiedEventSchema) -> str:
        desc = []
        
        if detectionResult.matchedRules:
            desc.append("**Matched Rules:**")
            for rule in detectionResult.matchedRules:
                desc.append(f"- {rule.name}: {rule.description}")
            desc.append("")
        
        if detectionResult.anomalyResult.get('is_anomaly'):
            desc.append("**Anomaly Detection:**")
            reasons = detectionResult.anomalyResult.get('reasons', [])
            for reason in reasons:
                desc.append(f"- {reason}")
            desc.append("")
        

        if detectionResult.heuristicResult.get('is_suspicious'):
            desc.append("**Heuristic Analysis:**")
            indicators = detectionResult.heuristicResult.get('indicators', [])
            for indicator in indicators:
                desc.append(f"- {indicator}")
            desc.append("")
        
        desc.append(f"**Event:** {event.eventName}")
        desc.append(f"**Source:** {event.sourceProvider}/{event.sourceService}")
        desc.append(f"**Time:** {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        if event.actor:
            desc.append(f"**Actor:** {event.actor.username or event.actor.userId or 'Unknown'}")
            if event.actor.ipAddress:
                desc.append(f"**IP Address:** {event.actor.ipAddress}")
        
        return "\n".join(desc)
    
    def collectIndicators(self, detectionResult: DetectionResult, event: UnifiedEventSchema) -> List[str]:
        # Initialize indicators list
        indicators = list(event.threatIndicators)
        
        if detectionResult.heuristicResult.get('is_suspicious'):
            indicators.extend(detectionResult.heuristicResult.get('indicators', []))
        
        if detectionResult.anomalyResult.get('is_anomaly'):
            indicators.extend(detectionResult.anomalyResult.get('reasons', []))
        
        return list(set(indicators)) 
