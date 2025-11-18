#Implements notification channels for alerts.

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .alert import Alert, AlertSeverity


class NotificationChannel(ABC): #Base class for notification channels.
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def send(self, alert: Alert) -> bool:
        pass
    
    def shouldNotify(self, alert: Alert) -> bool:
        # Default: notify for all alerts
        return True


class SlackChannel(NotificationChannel):
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url')
        self.channel = config.get('channel', '#security-alerts')
        self.username = config.get('username', 'Threat Detector')
        self.mention_on_critical = config.get('mention_on_critical', True)
    
    def send(self, alert: Alert) -> bool:
        try:
            text = ""
            if alert.severity == AlertSeverity.CRITICAL and self.mention_on_critical:
                text = "<!channel> Critical security alert!"
            
            attachment = {
                'title': alert.title,
                'text': alert.description[:500],  
                'fields': [
                    {
                        'title': 'Severity',
                        'value': alert.severity.value.upper(),
                        'short': True
                    },
                    {
                        'title': 'Alert ID',
                        'value': alert.alert_id,
                        'short': True
                    },
                    {
                        'title': 'Detection Methods',
                        'value': ', '.join(alert.detection_methods),
                        'short': True
                    },
                    {
                        'title': 'Timestamp',
                        'value': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'short': True
                    }
                ],
                'footer': 'Cloud Threat Detection Pipeline',
                'ts': int(alert.timestamp.timestamp())
            }
            
            if alert.indicators:
                attachment['fields'].append({
                    'title': 'Indicators',
                    'value': '\n'.join([f"• {ind}" for ind in alert.indicators[:5]]),
                    'short': False
                })
            
            payload = {
                'channel': self.channel,
                'username': self.username,
                'text': text,
                'attachments': [attachment]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Alert sent to Slack: {alert.alert_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error sending to Slack: {e}")
            return False


class EmailChannel(NotificationChannel):
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_host = config.get('smtp_host')
        self.smtp_port = config.get('smtp_port', 587)
        self.smtp_user = config.get('smtp_user')
        self.smtp_password = config.get('smtp_password')
        self.from_address = config.get('from_address')
        self.to_addresses = config.get('to_addresses', [])
        self.subject_prefix = config.get('subject_prefix', '[SECURITY ALERT]')
    
    def send(self, alert: Alert) -> bool:
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"{self.subject_prefix} {alert.title}"
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            text_body = f"""
Security Alert

Severity: {alert.severity.value.upper()}
Alert ID: {alert.alert_id}
Timestamp: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

{alert.description}

Detection Methods: {', '.join(alert.detection_methods)}

Indicators:
{chr(10).join([f"- {ind}" for ind in alert.indicators])}

---
Cloud Threat Detection Pipeline
            """
            
            html_body = f"""
<html>
<body>
    <h2>Security Alert</h2>
    <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
    <p><strong>Alert ID:</strong> {alert.alert_id}</p>
    <p><strong>Timestamp:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    
    <h3>Description</h3>
    <p>{alert.description.replace(chr(10), '<br>')}</p>
    
    <p><strong>Detection Methods:</strong> {', '.join(alert.detection_methods)}</p>
    
    <h3>Indicators</h3>
    <ul>
        {''.join([f"<li>{ind}</li>" for ind in alert.indicators])}
    </ul>
    
    <hr>
    <p><em>Cloud Threat Detection Pipeline</em></p>
</body>
</html>
            """
            
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            self.logger.info(f"Alert sent via email: {alert.alert_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error sending email: {e}")
            return False


class PagerDutyChannel(NotificationChannel):
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.integration_key = config.get('integration_key')
        self.severity_mapping = config.get('severity_mapping', {})
    
    def send(self, alert: Alert) -> bool:
        try:
            pd_severity = self.severity_mapping.get(
                alert.severity.value,
                'error'
            )
            payload = {
                'routing_key': self.integration_key,
                'event_action': 'trigger',
                'payload': {
                    'summary': alert.title,
                    'severity': pd_severity,
                    'source': 'cloud-threat-detection',
                    'custom_details': {
                        'alert_id': alert.alert_id,
                        'eventId': alert.eventId,
                        'detection_methods': ', '.join(alert.detection_methods),
                        'indicators': alert.indicators[:10],
                        'description': alert.description[:500]
                    }
                },
                'dedup_key': alert.fingerprint
            }
            
            response = requests.post(
                'https://events.pagerduty.com/v2/enqueue',
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.info(f"Alert sent to PagerDuty: {alert.alert_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error sending to PagerDuty: {e}")
            return False
    
    def shouldNotify(self, alert: Alert) -> bool:
        return alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]


class WebhookChannel(NotificationChannel):
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.url = config.get('url')
        self.method = config.get('method', 'POST')
        self.headers = config.get('headers', {})
    
    def send(self, alert: Alert) -> bool:
        try:
            payload = alert.toDict()
            
            response = requests.request(
                method=self.method,
                url=self.url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.info(f"Alert sent to webhook: {alert.alert_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error sending to webhook: {e}")
            return False
