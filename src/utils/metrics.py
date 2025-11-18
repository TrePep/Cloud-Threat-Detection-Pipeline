from typing import Dict, Any
from collections import defaultdict
from datetime import datetime
import logging


class MetricsCollector:
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reset()
    
    def reset(self) -> None:
        self.startTime = datetime.utcnow()
        
        self.events_ingested = 0
        self.events_normalized = 0
        self.events_processed = 0
        
        self.detections_by_method = defaultdict(int)
        self.detections_by_severity = defaultdict(int)
        
        self.alerts_generated = 0
        self.alerts_dispatched = 0
        self.alerts_deduplicated = 0
        self.alerts_throttled = 0
        
        self.errors = defaultdict(int)
        
        self.processing_times = []
    
    def recordEventIngested(self) -> None:
        self.events_ingested += 1
    
    def recordEventNormalized(self) -> None:
        self.events_normalized += 1
    
    def recordEventProcessed(self) -> None:
        self.events_processed += 1
    
    def recordDetection(self, method: str, severity: str) -> None:
        self.detections_by_method[method] += 1
        self.detections_by_severity[severity] += 1
    
    def recordAlertGenerated(self) -> None:
        self.alerts_generated += 1
    
    def recordAlertDispatched(self) -> None:
        self.alerts_dispatched += 1
    
    def recordAlertDeduplicated(self) -> None:
        self.alerts_deduplicated += 1
    
    def recordAlertThrottled(self) -> None:
        self.alerts_throttled += 1
    
    def record_error(self, component: str) -> None:
        self.errors[component] += 1
    
    def record_processing_time(self, duration_seconds: float) -> None:
        self.processing_times.append(duration_seconds)
    
    def getMetrics(self) -> Dict[str, Any]:
        runtimeSeconds = (datetime.utcnow() - self.startTime).total_seconds()
        
        metrics = {
            'runtimeSeconds': runtimeSeconds,
            'events': {
                'ingested': self.events_ingested,
                'normalized': self.events_normalized,
                'processed': self.events_processed,
                'events_per_second': self.events_processed / runtimeSeconds if runtimeSeconds > 0 else 0
            },
            'detections': {
                'by_method': dict(self.detections_by_method),
                'by_severity': dict(self.detections_by_severity),
                'total': sum(self.detections_by_method.values())
            },
            'alerts': {
                'generated': self.alerts_generated,
                'dispatched': self.alerts_dispatched,
                'deduplicated': self.alerts_deduplicated,
                'throttled': self.alerts_throttled
            },
            'errors': dict(self.errors),
            'performance': {
                'avg_processing_time_ms': sum(self.processing_times) / len(self.processing_times) * 1000 if self.processing_times else 0,
                'min_processing_time_ms': min(self.processing_times) * 1000 if self.processing_times else 0,
                'max_processing_time_ms': max(self.processing_times) * 1000 if self.processing_times else 0
            }
        }
        
        return metrics
    
    def log_metrics(self) -> None:
        metrics = self.getMetrics()
        
        self.logger.info("=== Pipeline Metrics ===")
        self.logger.info(f"Runtime: {metrics['runtimeSeconds']:.2f} seconds")
        self.logger.info(f"Events ingested: {metrics['events']['ingested']}")
        self.logger.info(f"Events normalized: {metrics['events']['normalized']}")
        self.logger.info(f"Events processed: {metrics['events']['processed']}")
        self.logger.info(f"Processing rate: {metrics['events']['events_per_second']:.2f} events/sec")
        self.logger.info(f"Total detections: {metrics['detections']['total']}")
        self.logger.info(f"Alerts generated: {metrics['alerts']['generated']}")
        self.logger.info(f"Alerts dispatched: {metrics['alerts']['dispatched']}")
        
        if metrics['errors']:
            self.logger.warning(f"Errors: {metrics['errors']}")
