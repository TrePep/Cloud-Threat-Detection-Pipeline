import logging
import sys
from pathlib import Path
from typing import Dict, Any
import json
from datetime import datetime


class JSONFormatter(logging.Formatter):
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data)


class TextFormatter(logging.Formatter):
    
    def __init__(self):
        fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        datefmt = '%Y-%m-%d %H:%M:%S'
        super().__init__(fmt=fmt, datefmt=datefmt)


def setupLogging(config: Dict[str, Any]) -> None:
    logging_config = config.get('logging', {})
    
    log_level = logging_config.get('level', 'INFO')
    log_format = logging_config.get('format', 'text')  # json or text
    log_output = logging_config.get('output', 'file')  # file, stdout, or both
    log_file_path = logging_config.get('file_path', 'logs/threat_detection.log')
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    root_logger.handlers = []
    
    if log_format == 'json':
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()
    
    if log_output in ['file', 'both']:
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    if log_output in ['stdout', 'both']:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('azure').setLevel(logging.WARNING)
    logging.getLogger('google').setLevel(logging.WARNING)
    
    root_logger.info("Logging configured successfully")
