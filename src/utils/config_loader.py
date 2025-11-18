"""
Configuration Loader

Loads and validates configuration from YAML files with environment variable substitution.
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any
import re
import logging


class ConfigLoader:
    """
    Loads configuration from YAML files with environment variable support.
    
    Supports:
    - Environment variable substitution ${VAR_NAME}
    - Multiple config file merging
    - Validation
    """
    
    def __init__(self, config_path: str):
        """
        Initialize config loader.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config: Dict[str, Any] = {}
    
    def load(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                content = f.read()
            
            # Substitute environment variables
            content = self._substituteEnvVars(content)
            
            # Parse YAML
            self.config = yaml.safe_load(content)
            
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return self.config
        
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise
    
    def _substituteEnvVars(self, content: str) -> str:
        """
        Substitute environment variables in format ${VAR_NAME}.
        
        Args:
            content: File content with variables
            
        Returns:
            Content with substituted values
        """
        pattern = r'\$\{([^}]+)\}'
        
        def replacer(match):
            var_name = match.group(1)
            value = os.environ.get(var_name)
            if value is None:
                self.logger.warning(f"Environment variable not found: {var_name}")
                return match.group(0)  # Keep original if not found
            return value
        
        return re.sub(pattern, replacer, content)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def validate(self) -> bool:
        """
        Validate configuration structure.
        
        Returns:
            True if valid
        """
        required_sections = ['ingestion', 'normalization', 'detection', 'alerting']
        
        for section in required_sections:
            if section not in self.config:
                self.logger.error(f"Missing required configuration section: {section}")
                return False
        
        return True
