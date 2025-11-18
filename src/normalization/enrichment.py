"""
Event Enrichment

Enriches normalized events with additional contextual information: GeoIP lookup for IP addresses, Threat intelligence feeds
Asset inventory correlation, and User behavior baselines.

"""

from typing import Dict, Any, Optional
import logging
import socket

from .schema import UnifiedEventSchema


class EventEnricher:
   
    def __init__(self, config: Dict[str, Any]): # Initialize the enricher with configuration
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.geoIpEnabled = config.get('geo_ip', False)
        self.threatIntelEnabled = config.get('threatIntel', False)
        self.assetInventoryEnabled = config.get('asset_inventory', False)
    
    def enrich(self, event: UnifiedEventSchema) -> None: # Enrich the event with additional context
        try:
            if self.geoIpEnabled:
                self._enrichGeoIp(event)
            
            if self.threatIntelEnabled:
                self._enrichThreatIntel(event)
            
            if self.assetInventoryEnabled:
                self._enrichAssetInventory(event)
            
            self._enrichDns(event)
            
        except Exception as e:
            self.logger.error(f"Error enriching event: {e}", exc_info=True)
    
    def _enrichGeoIp(self, event: UnifiedEventSchema) -> None: # Add GeoIP information for IP addresses in the event
        ipAddress = None
        if event.actor and event.actor.ipAddress:
            ipAddress = event.actor.ipAddress
        elif event.network and event.network.source_ip:
            ipAddress = event.network.source_ip
        
        if not ipAddress:
            return
        
        # TODO: Integrate with actual GeoIP service

        event.enrichment['geo_ip'] = {
            'ip': ipAddress,
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'isp': 'Unknown',
            'organization': 'Unknown'
        }
        
        if event.actor and event.actor.ipAddress == ipAddress:
            event.actor.geo_location = event.enrichment['geo_ip']
    
    def _enrichThreatIntel(self, event: UnifiedEventSchema) -> None:
        """
        Check IP addresses and indicators against threat intelligence feeds.
        
        Args:
            event: Event to enrich
        """
        threatIntel = {
            'indicators_found': [],
            'threat_level': 'none',
            'sources': []
        }
        
        ipsToCheck = []
        if event.actor and event.actor.ipAddress:
            ipsToCheck.append(event.actor.ipAddress)
        if event.network:
            if event.network.source_ip:
                ipsToCheck.append(event.network.source_ip)
            if event.network.destination_ip:
                ipsToCheck.append(event.network.destination_ip)
        
        for ip in ipsToCheck:
            isMalicious = self._checkThreatIntelPlaceholder(ip)
            if isMalicious:
                threatIntel['indicators_found'].append(ip)
                threatIntel['threat_level'] = 'high'
                threatIntel['sources'].append('threat_feed_placeholder')
                
                if ip not in event.threatIndicators:
                    event.threatIndicators.append(f"malicious_ip:{ip}")
        
        event.enrichment['threatIntel'] = threatIntel
        
        if threatIntel['threat_level'] == 'high':
            event.risk_score = (event.risk_score or 0.5) * 2.0
            event.risk_score = min(event.risk_score, 1.0)
    
    def _checkThreatIntelPlaceholder(self, ip: str) -> bool:
        suspiciousIps = ['192.0.2.1', '198.51.100.1', '203.0.113.1']
        return ip in suspiciousIps
    
    def _enrichAssetInventory(self, event: UnifiedEventSchema) -> None:
        if not event.resource:
            return
        
        event.enrichment['asset_inventory'] = {
            'resource_id': event.resource.resource_id,
            'owner': 'Unknown',
            'criticality': 'medium',
            'tags': event.resource.tags,
            'last_seen': None
        }
    
    def _enrichDns(self, event: UnifiedEventSchema) -> None:
        ipAddress = None
        if event.actor and event.actor.ipAddress:
            ipAddress = event.actor.ipAddress
        elif event.network and event.network.source_ip:
            ipAddress = event.network.source_ip
        
        if not ipAddress:
            return
        
        try:
            hostname = socket.gethostbyaddr(ipAddress)[0]
            event.enrichment['dns'] = {
                'ip': ipAddress,
                'hostname': hostname
            }
        except (socket.herror, socket.gaierror):
            pass
        except Exception as e:
            self.logger.debug(f"Error in DNS lookup for {ipAddress}: {e}")
