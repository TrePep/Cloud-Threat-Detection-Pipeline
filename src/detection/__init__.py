"""
Detection Module

Implements threat detection logic using multiple approaches:
- Rule-based detection using YAML-defined rules
- Anomaly detection using machine learning
- Heuristic detection using statistical analysis
"""

from .rules import RuleEngine, Rule
from .anomaly import AnomalyDetector
from .heuristic import HeuristicDetector
from .detection_manager import DetectionManager

__all__ = [
    'RuleEngine',
    'Rule',
    'AnomalyDetector',
    'HeuristicDetector',
    'DetectionManager',
]
