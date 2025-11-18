"""
Cloud Threat Detection Pipeline

Main orchestration module that coordinates all components of the threat detection pipeline.
"""

import sys
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import time
import click

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.config_loader import ConfigLoader
from utils.logger import setup_logging
from utils.metrics import MetricsCollector
from ingestion.ingestion_manager import IngestionManager
from normalization.normalizer import LogNormalizer
from detection.detection_manager import DetectionManager
from alerting.alert_manager import AlertManager


class ThreatDetectionPipeline:
    """
    Main pipeline orchestrator.
    
    Coordinates:
    1. Log ingestion from cloud providers
    2. Schema normalization
    3. Threat detection (rules, anomaly, heuristic)
    4. Alert generation and dispatch
    """
    
    def __init__(self, config_path: str):
        """
        Initialize the pipeline.
        
        Args:
            config_path: Path to configuration file
            
        Raises:
            FileNotFoundError: If config file not found
            ValueError: If config validation fails
            Exception: If component initialization fails
        """
        try:
            # Load configuration
            self.config_loader = ConfigLoader(config_path)
            self.config = self.config_loader.load()
            
            # Setup logging
            setup_logging(self.config)
            self.logger = logging.getLogger(self.__class__.__name__)
            
            # Initialize metrics
            self.metrics = MetricsCollector()
            
            # Initialize components
            self.logger.info("Initializing pipeline components...")
            
            try:
                self.ingestion_manager = IngestionManager(self.config)
            except Exception as e:
                self.logger.error(f"Failed to initialize ingestion manager: {e}")
                raise
            
            try:
                self.normalizer = LogNormalizer(self.config.get('normalization', {}))
            except Exception as e:
                self.logger.error(f"Failed to initialize normalizer: {e}")
                raise
            
            try:
                self.detection_manager = DetectionManager(self.config)
            except Exception as e:
                self.logger.error(f"Failed to initialize detection manager: {e}")
                raise
            
            try:
                self.alert_manager = AlertManager(self.config)
            except Exception as e:
                self.logger.error(f"Failed to initialize alert manager: {e}")
                raise
            
            self.logger.info("Pipeline initialized successfully")
            
        except FileNotFoundError as e:
            print(f"Error: Configuration file not found - {e}", file=sys.stderr)
            raise
        except ValueError as e:
            print(f"Error: Invalid configuration - {e}", file=sys.stderr)
            raise
        except Exception as e:
            print(f"Error: Pipeline initialization failed - {e}", file=sys.stderr)
            raise
    
    def run_once(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> None:
        """
        Run the pipeline once.
        
        Args:
            start_time: Start time for log retrieval
            end_time: End time for log retrieval
        """
        self.logger.info("Starting pipeline execution...")
        
        try:
            # Set default time range if not provided
            if not end_time:
                end_time = datetime.utcnow()
            if not start_time:
                # Default to last hour
                start_time = end_time - timedelta(hours=1)
            
            self.logger.info(f"Processing logs from {start_time} to {end_time}")
            
            # Step 1: Ingest logs
            self.logger.info("Step 1: Ingesting logs...")
            logs = self.ingestion_manager.fetch_all_logs(start_time, end_time)
            
            # Step 2-4: Process each log
            for raw_event in logs:
                self.metrics.record_event_ingested()
                
                try:
                    process_start = time.time()
                    
                    # Step 2: Normalize
                    normalized_event = self.normalizer.normalize(raw_event)
                    
                    if not normalized_event:
                        self.logger.debug("Event normalization failed, skipping")
                        continue
                    
                    self.metrics.record_event_normalized()
                    
                    # Step 3: Detect threats
                    detection_result = self.detection_manager.detect(normalized_event)
                    
                    # Record detection metrics
                    if detection_result.overall_threat_detected:
                        for method in detection_result.detection_methods:
                            self.metrics.record_detection(
                                method,
                                normalized_event.severity.value
                            )
                    
                    # Step 4: Generate and dispatch alerts
                    if detection_result.overall_threat_detected:
                        alert = self.alert_manager.createAlert(
                            detection_result,
                            normalized_event
                        )
                        
                        if alert:
                            self.metrics.record_alert_generated()
                            dispatched = self.alert_manager.processAlert(alert)
                            
                            if dispatched:
                                self.metrics.record_alert_dispatched()
                            else:
                                self.metrics.record_alert_deduplicated()
                    
                    self.metrics.record_event_processed()
                    
                    # Record processing time
                    process_duration = time.time() - process_start
                    self.metrics.record_processing_time(process_duration)
                
                except Exception as e:
                    self.logger.error(f"Error processing event: {e}", exc_info=True)
                    self.metrics.record_error('processing')
            
            self.logger.info("Pipeline execution completed")
            
        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}", exc_info=True)
            self.metrics.record_error('pipeline')
        
        finally:
            # Log metrics
            self.metrics.log_metrics()
    
    def run_continuous(self, poll_interval: int = 300) -> None:
        """
        Run the pipeline continuously with polling.
        
        Args:
            poll_interval: Polling interval in seconds (default: 5 minutes)
        """
        self.logger.info(f"Starting continuous pipeline execution (poll interval: {poll_interval}s)")
        
        last_poll_time = datetime.utcnow() - timedelta(seconds=poll_interval)
        
        try:
            while True:
                try:
                    current_time = datetime.utcnow()
                    
                    # Run pipeline for time since last poll
                    self.run_once(start_time=last_poll_time, end_time=current_time)
                    
                    last_poll_time = current_time
                    
                    # Wait for next interval
                    self.logger.info(f"Waiting {poll_interval} seconds until next poll...")
                    time.sleep(poll_interval)
                
                except KeyboardInterrupt:
                    self.logger.info("Received interrupt signal, shutting down...")
                    break
                except Exception as e:
                    self.logger.error(f"Error in continuous execution: {e}", exc_info=True)
                    time.sleep(poll_interval)
        
        finally:
            self.logger.info("Pipeline stopped")
            self.metrics.log_metrics()
    
    def test_connections(self) -> bool:
        """
        Test connectivity to all configured services.
        
        Returns:
            True if all connections successful
        """
        self.logger.info("Testing connections...")
        
        results = self.ingestion_manager.test_all_connections()
        
        all_successful = True
        for connector, status in results.items():
            status_str = "✓ OK" if status else "✗ FAILED"
            self.logger.info(f"{connector}: {status_str}")
            if not status:
                all_successful = False
        
        return all_successful
    
    def get_status(self) -> dict:
        """
        Get current pipeline status.
        
        Returns:
            Status dictionary
        """
        return {
            'ingestion': self.ingestion_manager.get_status(),
            'detection': self.detection_manager.get_statistics(),
            'metrics': self.metrics.get_metrics()
        }


@click.command()
@click.option(
    '--config',
    default='config/config.yaml',
    help='Path to configuration file'
)
@click.option(
    '--continuous',
    is_flag=True,
    help='Run continuously with polling'
)
@click.option(
    '--poll-interval',
    default=300,
    type=int,
    help='Polling interval in seconds (default: 300)'
)
@click.option(
    '--test-connections',
    is_flag=True,
    help='Test connections and exit'
)
@click.option(
    '--dry-run',
    is_flag=True,
    help='Run without dispatching alerts'
)
def cli(config, continuous, poll_interval, test_connections, dry_run):
    """Cloud Threat Detection Pipeline"""
    
    try:
        # Initialize pipeline
        pipeline = ThreatDetectionPipeline(config)
        
        # Test connections mode
        if test_connections:
            success = pipeline.test_connections()
            sys.exit(0 if success else 1)
        
        # Continuous mode
        if continuous:
            pipeline.run_continuous(poll_interval)
        else:
            # Single run
            pipeline.run_once()
    
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    cli()
