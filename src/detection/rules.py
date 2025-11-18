# Rule-based detection engine for cloud threat detection pipeline

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import logging
import yaml
from pathlib import Path
import re

from normalization.schema import UnifiedEventSchema


class Operator(Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class RuleCondition:
    field: str
    operator: Operator
    value: Any
    
    def evaluate(self, event: UnifiedEventSchema) -> bool:
        fieldValue = self._get_field_value(event, self.field)
        
        if self.operator == Operator.EQUALS:
            return fieldValue == self.value
        elif self.operator == Operator.NOT_EQUALS:
            return fieldValue != self.value
        elif self.operator == Operator.CONTAINS:
            return self.value in str(fieldValue) if fieldValue else False
        elif self.operator == Operator.NOT_CONTAINS:
            return self.value not in str(fieldValue) if fieldValue else True
        elif self.operator == Operator.IN:
            return fieldValue in self.value if isinstance(self.value, list) else False
        elif self.operator == Operator.NOT_IN:
            return fieldValue not in self.value if isinstance(self.value, list) else True
        elif self.operator == Operator.REGEX:
            return bool(re.search(self.value, str(fieldValue))) if fieldValue else False
        elif self.operator == Operator.GREATER_THAN:
            return fieldValue > self.value if fieldValue is not None else False
        elif self.operator == Operator.LESS_THAN:
            return fieldValue < self.value if fieldValue is not None else False
        elif self.operator == Operator.EXISTS:
            return fieldValue is not None
        elif self.operator == Operator.NOT_EXISTS:
            return fieldValue is None
        
        return False
    
    def _get_field_value(self, event: UnifiedEventSchema, fieldPath: str) -> Any:
        try:
            parts = fieldPath.split('.')
            value = event
            
            for part in parts:
                if hasattr(value, part):
                    value = getattr(value, part)
                elif isinstance(value, dict):
                    value = value.get(part)
                else:
                    return None
            
            if hasattr(value, 'value'):
                return value.value
            
            return value
        except Exception:
            return None


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    conditions: List[RuleCondition]
    tags: List[str]
    enabled: bool = True
    
    def evaluate(self, event: UnifiedEventSchema) -> bool:
        if not self.enabled:
            return False
        
        return all(condition.evaluate(event) for condition in self.conditions)
    
    @classmethod
    def from_yaml(cls, rule_data: Dict[str, Any]) -> 'Rule':
        conditions = []
        for cond_data in rule_data.get('conditions', []):
            condition = RuleCondition(
                field=cond_data['field'],
                operator=Operator(cond_data.get('operator', 'equals')),
                value=cond_data['value']
            )
            conditions.append(condition)
        
        return cls(
            id=rule_data.get('id', rule_data.get('name', '')),
            name=rule_data['name'],
            description=rule_data.get('description', ''),
            severity=rule_data.get('severity', 'medium'),
            conditions=conditions,
            tags=rule_data.get('tags', []),
            enabled=rule_data.get('enabled', True)
        )


class RuleEngine:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rules: List[Rule] = []
        self._load_rules()
    
    def _load_rules(self) -> None:
        #Load rules from the rules directory.
        rules_dir = self.config.get('rules_directory', 'rules/')
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            self.logger.warning(f"Rules directory not found: {rules_dir}")
            return
        
        # Load all YAML files in rules directory
        rule_files = list(rules_path.glob('*.yaml')) + list(rules_path.glob('*.yml'))
        
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    rule_documents = yaml.safe_load_all(f)
                    
                    for rule_data in rule_documents:
                        if rule_data is None:
                            continue
                            
                        if isinstance(rule_data, list):
                            for rule_dict in rule_data:
                                rule = Rule.from_yaml(rule_dict)
                                self.rules.append(rule)
                        else:
                            rule = Rule.from_yaml(rule_data)
                            self.rules.append(rule)
                
                self.logger.info(f"Loaded rules from {rule_file.name}")
            
            except Exception as e:
                self.logger.error(f"Error loading rule file {rule_file}: {e}")
        
        self.logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def reload_rules(self) -> None:
        self.rules = []
        self._load_rules()
    
    def detect(self, event: UnifiedEventSchema) -> List[Rule]:
        matchedRules = []
        
        for rule in self.rules:
            try:
                if rule.evaluate(event):
                    matchedRules.append(rule)
                    self.logger.info(
                        f"Rule matched: {rule.name} for event {event.eventId}"
                    )
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.name}: {e}")
        
        return matchedRules
    
    def get_rules_by_tag(self, tag: str) -> List[Rule]:
        return [rule for rule in self.rules if tag in rule.tags]
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_enabled_rules(self) -> List[Rule]:
        return [rule for rule in self.rules if rule.enabled]
