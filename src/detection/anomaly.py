"""
Anomaly Detection

Uses machine learning to detect unusual patterns and behaviors
that may indicate security threats.
"""

from typing import Dict, Any, List, Optional
import logging
import pickle
from pathlib import Path
import numpy as np
from datetime import datetime, timedelta

from normalization.schema import UnifiedEventSchema

# Machine learning imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class AnomalyDetector:
    # Anomaly detection using ML models
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        if not ML_AVAILABLE:
            self.logger.warning("scikit-learn not available, anomaly detection disabled")
            self.enabled = False
            return
        
        self.enabled = config.get('enabled', True)
        self.model_path = Path(config.get('model_path', 'models/anomalyDetector.pkl'))
        self.contamination = config.get('thresholds', {}).get('isolation_forest_contamination', 0.01)
        self.anomaly_threshold = config.get('thresholds', {}).get('anomaly_score_threshold', 0.8)
        self.isolation_forest: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None

        self.training_config = config.get('training', {})
        
        self._load_or_initialize_models()
    
    def _load_or_initialize_models(self) -> None:
        # Loads existing models or initializes new ones
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.isolation_forest = model_data['isolation_forest']
                    self.scaler = model_data['scaler']
                self.logger.info("Loaded anomaly detection models from disk")
            except Exception as e:
                self.logger.error(f"Error loading models: {e}")
                self._initialize_new_models()
        else:
            self._initialize_new_models()
    
    def _initialize_new_models(self) -> None:
        if not ML_AVAILABLE:
            return
        
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.logger.info("Initialized new anomaly detection models")
    
    def detect(self, event: UnifiedEventSchema) -> Dict[str, Any]:
        # Detect anomalies in an event.
        if not self.enabled or not ML_AVAILABLE:
            return {'isAnomaly': False, 'score': 0.0, 'reasons': []}
        
        try:
            features = self._extract_features(event)
            
            if not features:
                return {'isAnomaly': False, 'score': 0.0, 'reasons': ['No features extracted']}
            
            feature_vector = np.array([features])
            
            if not hasattr(self.isolation_forest, 'estimators_'):
                return {
                    'isAnomaly': False,
                    'score': 0.0,
                    'reasons': ['Model not yet trained']
                }
            
            scaled_features = self.scaler.transform(feature_vector)
            
            prediction = self.isolation_forest.predict(scaled_features)[0]
            anomaly_score = self.isolation_forest.score_samples(scaled_features)[0]
            
            normalized_score = 1.0 / (1.0 + np.exp(anomaly_score))
            
            isAnomaly = prediction == -1 or normalized_score > self.anomaly_threshold
            
            reasons = self._identify_anomaly_reasons(event, features, normalized_score)
            
            return {
                'isAnomaly': bool(isAnomaly),
                'score': float(normalized_score),
                'reasons': reasons,
                'method': 'isolation_forest'
            }
        
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}", exc_info=True)
            return {'isAnomaly': False, 'score': 0.0, 'reasons': [f'Error: {str(e)}']}
    
    def _extract_features(self, event: UnifiedEventSchema) -> List[float]:
        # Extract numerical features from the event for anomaly detection.
        features = []
        
        hour = event.timestamp.hour
        day_of_week = event.timestamp.weekday()
        features.extend([hour, day_of_week])
        
        event_types = ['authentication', 'authorization', 'resource_access', 
                      'network_traffic', 'configuration_change', 'data_access',
                      'security_alert', 'administrative_action']
        event_type_encoded = [1.0 if event.eventType.value == et else 0.0 
                              for et in event_types]
        features.extend(event_type_encoded)
        
        severity_map = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        features.append(severity_map.get(event.severity.value, 0))
        
        outcome_success = 1.0 if event.outcome.value == 'success' else 0.0
        features.append(outcome_success)
        
        if event.network:
            features.append(float(event.network.source_port or 0))
            features.append(float(event.network.destinationPort or 0))
            features.append(float(event.network.bytesSent or 0))
            features.append(float(event.network.bytesReceived or 0))
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        features.append(float(event.risk_score or 0.0))
        
        features.append(float(len(event.threatIndicators)))
        
        return features
    
    def _identify_anomaly_reasons(
        self,
        event: UnifiedEventSchema,
        features: List[float],
        score: float
    ) -> List[str]:
        # Identify reasons contributing to the anomaly score.
        reasons = []
        
        if score > 0.9:
            reasons.append("Highly unusual event pattern")
        elif score > self.anomaly_threshold:
            reasons.append("Unusual event characteristics")
        
        #Unusual time?
        if event.timestamp.hour < 6 or event.timestamp.hour > 22:
            reasons.append("Activity during unusual hours")
        
        if event.risk_score and event.risk_score > 0.7:
            reasons.append("High risk score")
        
        if len(event.threatIndicators) > 0:
            reasons.append(f"Threat indicators present: {len(event.threatIndicators)}")
        
        return reasons if reasons else ["Anomalous feature combination"]
    
    def train(self, events: List[UnifiedEventSchema]) -> bool:
        # Train the anomaly detection model on historical events.
        if not self.enabled or not ML_AVAILABLE:
            return False
        
        try:
            self.logger.info(f"Training anomaly detection model on {len(events)} events")
            
            feature_matrix = []
            for event in events:
                features = self._extract_features(event)
                if features:
                    feature_matrix.append(features)
            
            if len(feature_matrix) < 10:
                self.logger.warning("Not enough events for training")
                return False
            
            X = np.array(feature_matrix)
            
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            self.isolation_forest.fit(X_scaled)
            self._save_models()
            
            self.logger.info("Anomaly detection model training completed")
            return True
        
        except Exception as e:
            self.logger.error(f"Error training model: {e}", exc_info=True)
            return False
    
    def _save_models(self) -> None:
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'config': self.config,
                'trained_at': datetime.utcnow().isoformat()
            }
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Saved models to {self.model_path}")
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
