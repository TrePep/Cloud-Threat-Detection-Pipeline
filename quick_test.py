# Test the pipeline with sample data
import json
from pathlib import Path
from src.normalization.normalizer import LogNormalizer
from src.detection.detection_manager import DetectionManager
from src.alerting.alert_manager import AlertManager

def quick_test():    
    print("\n" + "="*70)
    print("CLOUD THREAT DETECTION PIPELINE - QUICK TEST")
    print("="*70)
    
    config = {
        'normalization': {
            'enrichment_enabled': False
        },
        'detection': {
            'rules': {
                'enabled': True,
                'rules_path': 'rules/'
            },
            'anomaly': {
                'enabled': False  
            },
            'heuristic': {
                'enabled': False  
            }
        },
        'alerting': {
            'enabled': False,  # No real alerts
            'deduplication_window': 300
        }
    }
    
    print("\nInitializing components...")
    normalizer = LogNormalizer(config)
    detector = DetectionManager(config)
    alertMgr = AlertManager(config)
    print("    Components initialized")
    
    print("\nLoading all sample log files...")
    sampleDir = Path('data/sample_logs')
    
    if not sampleDir.exists():
        print(f"    Sample directory not found: {sampleDir}")
        return
    
    logFiles = list(sampleDir.glob('*.json'))
    
    if not logFiles:
        print("    No sample log files found")
        return
    
    print(f"    Found {len(logFiles)} sample log file(s)")
    
    # Filenames to source identifiers
    sourceMap = {
        'aws_cloudtrail_sample.json': 'aws_cloudtrail',
        'aws_guardduty_sample.json': 'aws_guardduty',
        'azure_activity_logs_sample.json': 'azure_activity_logs',
        'gcp_audit_logs_sample.json': 'gcp_audit_logs',
        'sample_logs.json': 'mixed'  
    }
    
    # Load all events
    allEvents = []
    fileCounts = {}
    
    for logFile in sorted(logFiles):
        try:
            with open(logFile, 'r') as f:
                events = json.load(f)
                sourceId = sourceMap.get(logFile.name, 'unknown')
                
                for event in events:
                    if 'source' not in event:
                        event['source'] = sourceId
                    
                    event['_source_file'] = logFile.name
                
                allEvents.extend(events)
                fileCounts[logFile.name] = len(events)
                print(f"      • {logFile.name}: {len(events)} events")
        
        except Exception as e:
            print(f"      Error loading {logFile.name}: {e}")
    
    print(f"\n    Total events loaded: {len(allEvents)}")
    
    print("\nDetecting threats...")
    totalEvents = 0
    threatsDetected = 0
    alertsCreated = 0
    threatsByFile = {}
    
    for rawEvent in allEvents:
        sourceFile = rawEvent.get('_source_file', 'unknown')
        
        normalized = normalizer.normalize(rawEvent)
        
        if normalized:
            totalEvents += 1
            result = detector.detect(normalized)
            
            if result.overallThreatDetected:
                threatsDetected += 1
                threatsByFile[sourceFile] = threatsByFile.get(sourceFile, 0) + 1
                
                alert = alertMgr.createAlert(result, normalized)
                alertsCreated += 1
                
                eventName = (rawEvent.get('eventName') or 
                             rawEvent.get('operationName', {}).get('value') if isinstance(rawEvent.get('operationName'), dict) else rawEvent.get('operationName') or
                             rawEvent.get('protoPayload', {}).get('methodName') or
                             'Unknown')
                
                user = (rawEvent.get('userIdentity', {}).get('userName') or
                       rawEvent.get('userIdentity', {}).get('type') or
                       rawEvent.get('caller') or
                       rawEvent.get('identity', {}).get('userPrincipalName') or
                       rawEvent.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail') or
                       'Unknown')
                
                print(f"\nThreat #{threatsDetected}:")
                print(f"  File: {sourceFile}")
                print(f"  Event: {eventName}")
                print(f"  User: {user}")
                print(f"  Rules matched: {len(result.matchedRules)}")
                
                for rule in result.matchedRules:
                    print(f"- {rule.name} (Severity: {rule.severity})")
                
                print(f"  Alert: {alert.title}")
                print(f"  Severity: {alert.severity}")
    
    print("\nProcessing complete")
    
    print("\n" + "="*70)
    print("Test Summary:")
    print("="*70)
    print(f"  Files processed: {len(fileCounts)}")
    print(f"  Events processed: {totalEvents}")
    print(f"  Threats detected: {threatsDetected}")
    print(f"  Alerts created: {alertsCreated}")
    print(f"  Detection rate: {(threatsDetected/totalEvents*100):.1f}%")
    print("\n  Threats by file:")
    for filename in sorted(fileCounts.keys()):
        threat_count = threatsByFile.get(filename, 0)
        event_count = fileCounts[filename]
        rate = (threat_count/event_count*100) if event_count > 0 else 0
        print(f"    • {filename}: {threat_count}/{event_count} ({rate:.1f}%)")
    print("="*70)
    
    if threatsDetected > 0:
        print("\nSecurity Threats detected.")
    
if __name__ == '__main__':
    try:
        quick_test()
    except Exception as e:
        print(f"\ERROR: {e}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
