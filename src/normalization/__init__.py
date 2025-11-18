"""
Schema Normalization Module

Normalizes logs from different cloud providers into a unified schema.
Enables consistent detection and analysis across heterogeneous log sources.

Features:
- Unified event schema
- Field mapping from provider-specific formats
- Data enrichment (GeoIP, threat intel, etc.)
- Validation and sanitization
"""

from .schema import UnifiedEventSchema
from .normalizer import LogNormalizer
from .field_mapper import FieldMapper
from .enrichment import EventEnricher

__all__ = [
    'UnifiedEventSchema',
    'LogNormalizer',
    'FieldMapper',
    'EventEnricher',
]
