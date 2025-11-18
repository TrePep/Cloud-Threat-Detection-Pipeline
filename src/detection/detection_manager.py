
# Detection Manager
#Coordinates all detection engines and aggregates results.


from typing import Dict, Any, List
import logging

from normalization.schema import UnifiedEventSchema
from detection.rules import RuleEngine
from detection.anomaly import AnomalyDetector
from detection.heuristic import HeuristicDetector


class DetectionResult:
    
    def __init__(self, event: UnifiedEventSchema):
        self.event = event
        self.matchedRules = []
        self.anomalyResult = {}
        self.heuristicResult = {}
        self.overallThreatDetected = False
        self.overallScore = 0.0
        self.detectionMethods = []
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'eventId': self.event.eventId,
            'threatDetected': self.overallThreatDetected,
            'overallScore': self.overallScore,
            'detectionMethods': self.detectionMethods,
            'matchedRules': [
                {
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description
                }
                for rule in self.matchedRules
            ],
            'anomaly_detection': self.anomalyResult,
            'heuristic_detection': self.heuristicResult
        }


class DetectionManager:
    # Manages all detection engines and coordinates threat detection. 
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize detection manager.
        
        Args:
            config: Configuration for all detection engines
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        detection_config = config.get('detection', {})
        
        self.ruleEngine = RuleEngine(detection_config.get('rules', {}))
        self.anomalyDetector = AnomalyDetector(detection_config.get('anomaly', {}))
        self.heuristicDetector = HeuristicDetector(detection_config.get('heuristic', {}))
        
        self.logger.info("Detection manager initialized")
    
    def detect(self, event: UnifiedEventSchema) -> DetectionResult:
        # Run all detection engines on an event.
        result = DetectionResult(event)
        
        try:
            matchedRules = self.ruleEngine.detect(event)
            result.matchedRules = matchedRules
            if matchedRules:
                result.detectionMethods.append('rules')
            
            anomalyResult = self.anomalyDetector.detect(event)
            result.anomalyResult = anomalyResult
            if anomalyResult.get('is_anomaly', False):
                result.detectionMethods.append('anomaly')
            
            heuristicResult = self.heuristicDetector.detect(event)
            result.heuristicResult = heuristicResult
            if heuristicResult.get('is_suspicious', False):
                result.detectionMethods.append('heuristic')
            
            self._aggregate_results(result)
            
        except Exception as e:
            self.logger.error(f"Error in detection: {e}", exc_info=True)
        
        return result
    
    def _aggregate_results(self, result: DetectionResult) -> None:
        scores = []
        
        # Rule-based score
        if result.matchedRules:
            severity_scores = {
                'critical': 1.0,
                'high': 0.8,
                'medium': 0.6,
                'low': 0.4,
                'info': 0.2
            }
            rule_score = max(
                severity_scores.get(rule.severity, 0.5)
                for rule in result.matchedRules
            )
            scores.append(rule_score)
        
        if result.anomalyResult.get('is_anomaly'):
            scores.append(result.anomalyResult.get('score', 0.5))
        
        if result.heuristicResult.get('is_suspicious'):
            scores.append(result.heuristicResult.get('score', 0.5))
        
        if scores:
            result.overallScore = max(scores) * 0.6 + (sum(scores) / len(scores)) * 0.4
            result.overallThreatDetected = True
        else:
            result.overallScore = 0.0
            result.overallThreatDetected = False
    
    def reload_rules(self) -> None:
        self.ruleEngine.reload_rules()
        self.logger.info("Detection rules reloaded")
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            'rules_loaded': len(self.ruleEngine.rules),
            'rules_enabled': len(self.ruleEngine.get_enabled_rules()),
            'anomaly_detector_enabled': self.anomalyDetector.enabled,
            'heuristic_detector_enabled': self.heuristicDetector.enabled
        }
