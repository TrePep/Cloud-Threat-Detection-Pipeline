# Huristic-based threat detection module
# Implements statistical and heuristic techniques for threat detection.

from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import statistics

from normalization.schema import UnifiedEventSchema


class HeuristicDetector:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.enabled = config.get('enabled', True)
        
        #Statistical thresholds
        self.z_score_threshold = config.get('statistical', {}).get('z_score_threshold', 3.0)
        self.rolling_window_hours = config.get('statistical', {}).get('rolling_window_hours', 24)
        
        #Behavioral baselines
        self.baseline_window_days = config.get('behavioral', {}).get('baseline_window_days', 7)
        self.deviation_threshold = config.get('behavioral', {}).get('deviation_threshold', 2.5)
        
        #Event tracking for frequency analysis
        self.event_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.user_baselines: Dict[str, Dict[str, Any]] = {}
        self.resource_baselines: Dict[str, Dict[str, Any]] = {}
    
    def detect(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        if not self.enabled:
            return {'isSuspicious': False, 'indicators': [], 'score': 0.0}
        
        indicators = []
        scores = []
        
        try:
            # Frequency-based 
            freqResult = self._detectFrequencyAnomalies(event)
            if freqResult['isSuspicious']:
                indicators.extend(freqResult['indicators'])
                scores.append(freqResult['score'])
            
            # Failed login 
            if event.eventType.value == 'authentication':
                loginResult = self._detectSuspiciousAuthentication(event)
                if loginResult['isSuspicious']:
                    indicators.extend(loginResult['indicators'])
                    scores.append(loginResult['score'])
            
            # Unusual time 
            timeResult = self._detectUnusualTime(event)
            if timeResult['isSuspicious']:
                indicators.extend(timeResult['indicators'])
                scores.append(timeResult['score'])
            
            # Behavioral baseline deviation
            behaviorResult = self._detectBehavioralDeviation(event)
            if behaviorResult['isSuspicious']:
                indicators.extend(behaviorResult['indicators'])
                scores.append(behaviorResult['score'])
            
            # High-value resource access
            resourceResult = self._detectSensitiveResourceAccess(event)
            if resourceResult['isSuspicious']:
                indicators.extend(resourceResult['indicators'])
                scores.append(resourceResult['score'])
            
            # Track event for future analysis
            self._trackEvent(event)
            
            # Calculate overall score
            overallScore = max(scores) if scores else 0.0
            
            return {
                'isSuspicious': len(indicators) > 0,
                'indicators': indicators,
                'score': overallScore,
                'method': 'heuristic'
            }
        
        except Exception as e:
            self.logger.error(f"Error in heuristic detection: {e}", exc_info=True)
            return {'isSuspicious': False, 'indicators': [f'Error: {str(e)}'], 'score': 0.0}
    
    def _detectFrequencyAnomalies(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        indicators = []
        score = 0.0
        if event.actor and event.actor.username:
            user_key = f"user:{event.actor.username}:{event.eventName}"
            recent_events = self.event_history.get(user_key, deque())
            
            cutoff_time = datetime.utcnow() - timedelta(minutes=5)
            recent_count = sum(1 for ts in recent_events if ts > cutoff_time)
            
            if recent_count > 20:  
                indicators.append(f"High frequency of {event.eventName} by {event.actor.username}")
                score = min(recent_count / 50.0, 1.0)
        
        # Track by IP address
        if event.actor and event.actor.ipAddress:
            ip_key = f"ip:{event.actor.ipAddress}:{event.eventName}"
            recent_events = self.event_history.get(ip_key, deque())
            
            cutoff_time = datetime.utcnow() - timedelta(minutes=5)
            recent_count = sum(1 for ts in recent_events if ts > cutoff_time)
            
            if recent_count > 30:
                indicators.append(f"High frequency from IP {event.actor.ipAddress}")
                score = max(score, min(recent_count / 60.0, 1.0))
        
        return {
            'isSuspicious': len(indicators) > 0,
            'indicators': indicators,
            'score': score
        }
    
    def _detectSuspiciousAuthentication(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        indicators = []
        score = 0.0
        
        # Failed login 
        if event.outcome.value == 'failure':
            if event.actor and event.actor.username:
                user_key = f"failed_login:{event.actor.username}"
                failed_attempts = self.event_history.get(user_key, deque())
                
                # Count recent failed attempts
                cutoff_time = datetime.utcnow() - timedelta(minutes=10)
                recent_failures = sum(1 for ts in failed_attempts if ts > cutoff_time)
                
                if recent_failures >= 5:
                    indicators.append(f"Multiple failed login attempts for {event.actor.username}")
                    score = min(recent_failures / 10.0, 1.0)
        
        # Login from new location
        if event.actor and event.actor.geo_location:
            user_key = event.actor.username or event.actor.userId
            if user_key:
                baseline = self.user_baselines.get(user_key, {})
                known_countries = baseline.get('countries', set())
                current_country = event.actor.geo_location.get('country')
                
                if current_country and known_countries and current_country not in known_countries:
                    indicators.append(f"Login from new location: {current_country}")
                    score = max(score, 0.6)
        
        return {
            'isSuspicious': len(indicators) > 0,
            'indicators': indicators,
            'score': score
        }
    
    def _detectUnusualTime(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        indicators = []
        score = 0.0
        
        hour = event.timestamp.hour
        dayOfWeek = event.timestamp.weekday()
        
        # Weekend
        if dayOfWeek >= 5:  # Saturday or Sunday
            indicators.append("Activity during weekend")
            score = 0.3
        
        # Night (10 PM - 6 AM)
        if hour >= 22 or hour < 6:
            indicators.append(f"Activity during unusual hours ({hour:02d}:00)")
            score = max(score, 0.4)
        
        # Very early morning (2 AM - 5 AM)
        if 2 <= hour < 5:
            indicators.append("Activity during very early morning hours")
            score = max(score, 0.6)
        
        return {
            'isSuspicious': len(indicators) > 0,
            'indicators': indicators,
            'score': score
        }
    
    def _detectBehavioralDeviation(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        indicators = []
        score = 0.0
        
        # User behavior
        if event.actor and (event.actor.username or event.actor.userId):
            user_key = event.actor.username or event.actor.userId
            baseline = self.user_baselines.get(user_key, {})
            
            common_actions = baseline.get('common_actions', set())
            if common_actions and event.eventName not in common_actions and len(common_actions) > 10:
                indicators.append(f"Unusual action for user: {event.eventName}")
                score = 0.5
        
        #Resource access patterns
        if event.resource and event.resource.resourceId:
            resource_key = event.resource.resourceId
            baseline = self.resource_baselines.get(resource_key, {})
            
            # Unusual accessor
            common_users = baseline.get('common_users', set())
            current_user = event.actor.username if event.actor else None
            
            if current_user and common_users and current_user not in common_users and len(common_users) > 5:
                indicators.append(f"Unusual user accessing resource: {current_user}")
                score = max(score, 0.6)
        
        return {
            'isSuspicious': len(indicators) > 0,
            'indicators': indicators,
            'score': score
        }
    
    def _detectSensitiveResourceAccess(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        indicators = []
        score = 0.0
        
        sensitive_keywords = ['secret', 'key', 'password', 'credential', 'token', 
                            'admin', 'root', 'delete', 'destroy', 'terminate']
        
        eventNameLower = event.eventName.lower()
        
        for keyword in sensitive_keywords:
            if keyword in eventNameLower:
                indicators.append(f"Sensitive operation detected: {keyword}")
                score = 0.7
                break
        
        # Privileged actions
        if event.resource and event.resource.tags:
            criticality = event.resource.tags.get('criticality', '')
            if criticality in ['high', 'critical']:
                indicators.append("Access to high-criticality resource")
                score = max(score, 0.6)
        
        return {
            'isSuspicious': len(indicators) > 0,
            'indicators': indicators,
            'score': score
        }
    
    def _trackEvent(self, event: UnifiedEventSchema) -> None:
        timestamp = event.timestamp
        
        # By user
        if event.actor and event.actor.username:
            user_key = f"user:{event.actor.username}:{event.eventName}"
            self.event_history[user_key].append(timestamp)
            
            if event.eventType.value == 'authentication' and event.outcome.value == 'failure':
                failed_key = f"failed_login:{event.actor.username}"
                self.event_history[failed_key].append(timestamp)
            
            self._updateUserBaseline(event)
        
        # By IP
        if event.actor and event.actor.ipAddress:
            ip_key = f"ip:{event.actor.ipAddress}:{event.eventName}"
            self.event_history[ip_key].append(timestamp)
        
        if event.resource:
            self._updateResourceBaseline(event)
    
    def _updateUserBaseline(self, event: UnifiedEventSchema) -> None:
        if not event.actor:
            return
        
        user_key = event.actor.username or event.actor.userId
        if not user_key:
            return
        
        if user_key not in self.user_baselines:
            self.user_baselines[user_key] = {
                'common_actions': set(),
                'countries': set(),
                'typical_hours': []
            }
        
        baseline = self.user_baselines[user_key]
        baseline['common_actions'].add(event.eventName)
        baseline['typical_hours'].append(event.timestamp.hour)
        
        if event.actor.geo_location:
            country = event.actor.geo_location.get('country')
            if country:
                baseline['countries'].add(country)
    
    def _updateResourceBaseline(self, event: UnifiedEventSchema) -> None:
        if not event.resource or not event.resource.resourceId:
            return
        
        resource_key = event.resource.resourceId
        
        if resource_key not in self.resource_baselines:
            self.resource_baselines[resource_key] = {
                'common_users': set(),
                'access_count': 0
            }
        
        baseline = self.resource_baselines[resource_key]
        baseline['access_count'] += 1
        
        if event.actor and event.actor.username:
            baseline['common_users'].add(event.actor.username)
