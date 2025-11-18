"""
Unit Tests for Cloud Threat Detection Pipeline
"""

import unittest
from datetime import datetime

from normalization.schema import UnifiedEventSchema, EventType, Severity, OutcomeStatus, Actor
from detection.rules import Rule, RuleCondition, Operator
from alerting.alert import Alert, AlertSeverity


class TestUnifiedEventSchema(unittest.TestCase):
    
    def testEventCreation(self):
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin',
            severity=Severity.INFO
        )
        
        self.assertEqual(event.eventId, 'test-123')
        self.assertEqual(event.sourceProvider, 'aws')
        self.assertEqual(event.eventType, EventType.AUTHENTICATION)
    
    def testEventToDict(self):
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin'
        )
        
        eventDict = event.toDict()
        self.assertIsInstance(eventDict, dict)
        self.assertEqual(eventDict['eventId'], 'test-123')
        self.assertEqual(eventDict['eventType'], 'authentication')
    
    def testEventValidation(self):
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin'
        )
        
        self.assertTrue(event.validate())


class TestDetectionRules(unittest.TestCase):
    
    def test_rule_condition_equals(self):
        condition = RuleCondition(
            field='sourceProvider',
            operator=Operator.EQUALS,
            value='aws'
        )
        
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin'
        )
        
        self.assertTrue(condition.evaluate(event))
    
    def testRuleCondition(self):
        condition = RuleCondition(
            field='eventName',
            operator=Operator.CONTAINS,
            value='Login'
        )
        
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin'
        )
        
        self.assertTrue(condition.evaluate(event))
    
    def testRuleEvaluation(self):
        rule = Rule(
            id='test-rule',
            name='Test Rule',
            description='Test rule',
            severity='high',
            conditions=[
                RuleCondition('sourceProvider', Operator.EQUALS, 'aws'),
                RuleCondition('eventType', Operator.EQUALS, 'authentication')
            ],
            tags=['test']
        )
        
        event = UnifiedEventSchema(
            eventId='test-123',
            timestamp=datetime.utcnow(),
            sourceProvider='aws',
            sourceService='cloudtrail',
            eventType=EventType.AUTHENTICATION,
            eventName='ConsoleLogin'
        )
        
        self.assertTrue(rule.evaluate(event))


class TestAlerts(unittest.TestCase):
    
    def testAlertCreation(self):
        alert = Alert(
            alert_id='alert-123',
            title='Test Alert',
            description='Test alert description',
            severity=AlertSeverity.HIGH,
            eventId='event-123'
        )
        
        self.assertEqual(alert.alert_id, 'alert-123')
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertIsNotNone(alert.fingerprint)
    
    def testAlertFingerprint(self):
        alert1 = Alert(
            alert_id='alert-1',
            title='Test Alert',
            description='Test',
            severity=AlertSeverity.HIGH,
            eventId='event-1'
        )
        
        alert2 = Alert(
            alert_id='alert-2',
            title='Test Alert',
            description='Test',
            severity=AlertSeverity.HIGH,
            eventId='event-2'
        )
        
        self.assertEqual(alert1.fingerprint, alert2.fingerprint)
    
    def testAlertToMarkdown(self):
        alert = Alert(
            alert_id='alert-123',
            title='Test Alert',
            description='Test alert description',
            severity=AlertSeverity.HIGH,
            eventId='event-123',
            indicators=['indicator1', 'indicator2']
        )
        
        markdown = alert.toMarkdown()
        self.assertIn('Test Alert', markdown)
        self.assertIn('HIGH', markdown)
        self.assertIn('indicator1', markdown)


if __name__ == '__main__':
    unittest.main()
