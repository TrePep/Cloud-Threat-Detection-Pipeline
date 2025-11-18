# Base ingestion class

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Iterator
from datetime import datetime
import logging


class BaseIngestion(ABC):  
    def __init__(self, config: Dict[str, Any]):

        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.lastIngestionTime: Optional[datetime] = None
        self._initializeClient()
    
    @abstractmethod
    def _initializeClient(self) -> None:
        pass
    
    @abstractmethod
    def fetchLogs(
        self,
        startTime: Optional[datetime] = None,
        endTime: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Iterator[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def testConnection(self) -> bool:
        pass
    
    def validateConfig(self) -> bool:
        requiredFields = self.getRequiredFields()
        missingFields = [field for field in requiredFields if field not in self.config]
        
        if missingFields:
            self.logger.error(f"Missing required configuration fields: {missingFields}")
            return False
        
        return True
    
    @abstractmethod
    def getRequiredFields(self) -> List[str]:
        pass
    
    def handleError(self, error: Exception, context: str) -> None:
        self.logger.error(f"Error in {context}: {str(error)}", exc_info=True)
    
    def getStatus(self) -> Dict[str, Any]:
        return {
            'connector': self.__class__.__name__,
            'lastIngestionTime': self.lastIngestionTime,
            'configValid': self.validateConfig(),
            'connected': self.testConnection()
        }
