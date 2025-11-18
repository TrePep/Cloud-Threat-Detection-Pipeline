from typing import Dict, Any, List, Iterator
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseIngestion
from .aws_ingestion import AWSIngestion
from .azure_ingestion import AzureIngestion
from .gcp_ingestion import GCPIngestion


class IngestionManager:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.connectors: List[BaseIngestion] = []
        self._initializeConnectors()
    
    def _initializeConnectors(self) -> None:
        ingestionConfig = self.config.get('ingestion', {})
        
        # Initialize AWS
        if ingestionConfig.get('aws', {}).get('enabled', False):
            try:
                awsConnector = AWSIngestion(ingestionConfig['aws'])
                if awsConnector.validateConfig():
                    self.connectors.append(awsConnector)
                    self.logger.info("AWS ingestion connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize AWS connector: {e}")
        
        # Initialize Azure
        if ingestionConfig.get('azure', {}).get('enabled', False):
            try:
                azureConnector = AzureIngestion(ingestionConfig['azure'])
                if azureConnector.validateConfig():
                    self.connectors.append(azureConnector)
                    self.logger.info("Azure ingestion connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Azure connector: {e}")
        
        # Initialize GCP 
        if ingestionConfig.get('gcp', {}).get('enabled', False):
            try:
                gcpConnector = GCPIngestion(ingestionConfig['gcp'])
                if gcpConnector.validateConfig():
                    self.connectors.append(gcpConnector)
                    self.logger.info("GCP ingestion connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize GCP connector: {e}")
        
        self.logger.info(f"Initialized {len(self.connectors)} ingestion connectors")
    
    def fetchAllLogs(
        self,
        startTime: datetime = None,
        endTime: datetime = None,
        parallel: bool = True
    ) -> Iterator[Dict[str, Any]]:
        if parallel and len(self.connectors) > 1:
            yield from self._fetchParallel(startTime, endTime)
        else:
            yield from self._fetchSequential(startTime, endTime)
    
    def _fetchSequential(
        self,
        startTime: datetime,
        endTime: datetime
    ) -> Iterator[Dict[str, Any]]:
        for connector in self.connectors:
            try:
                self.logger.info(f"Fetching logs from {connector.__class__.__name__}")
                for log in connector.fetchLogs(startTime, endTime):
                    yield log
            except Exception as e:
                self.logger.error(f"Error fetching from {connector.__class__.__name__}: {e}")
    
    def _fetchParallel(
        self,
        startTime: datetime,
        endTime: datetime
    ) -> Iterator[Dict[str, Any]]:

        with ThreadPoolExecutor(max_workers=len(self.connectors)) as executor:
            # Submit fetch tasks
            futures = {
                executor.submit(
                    self._fetch_from_connector,
                    connector,
                    startTime,
                    endTime
                ): connector for connector in self.connectors
            }
            
            # Yield results as they complete
            for future in as_completed(futures):
                connector = futures[future]
                try:
                    logs = future.result()
                    for log in logs:
                        yield log
                except Exception as e:
                    self.logger.error(f"Error fetching from {connector.__class__.__name__}: {e}")
    
    def _fetch_from_connector(
        self,
        connector: BaseIngestion,
        startTime: datetime,
        endTime: datetime
    ) -> List[Dict[str, Any]]:
        logs = []
        try:
            self.logger.info(f"Fetching logs from {connector.__class__.__name__}")
            for log in connector.fetchLogs(startTime, endTime):
                logs.append(log)
        except Exception as e:
            self.logger.error(f"Error in {connector.__class__.__name__}: {e}")
        return logs
    
    def testAllConnections(self) -> Dict[str, bool]:
        results = {}
        for connector in self.connectors:
            connectorName = connector.__class__.__name__
            results[connectorName] = connector.testConnection()
        return results
    
    def getStatus(self) -> Dict[str, Any]:
        return {
            'total_connectors': len(self.connectors),
            'connectors': [connector.getStatus() for connector in self.connectors]
        }
