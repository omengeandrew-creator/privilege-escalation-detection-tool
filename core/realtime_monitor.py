# core/realtime_monitor.py
import time
import threading
from datetime import datetime
import psutil
import subprocess
import json

class RealTimeMonitor:
    def __init__(self, db):
        self.db = db
        self.monitoring = False
        self.monitor_thread = None
        self.alert_threshold = 5  # Number of events to trigger alert
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            return False
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        event_buffer = []
        
        while self.monitoring:
            try:
                # Monitor various system activities
                events = self.check_system_events()
                event_buffer.extend(events)
                
                # Check if we need to trigger alerts
                if len(event_buffer) >= self.alert_threshold:
                    self.trigger_alert(event_buffer)
                    event_buffer = []
                
                # Clear old events periodically
                event_buffer = [e for e in event_buffer if 
                               datetime.now().timestamp() - e['timestamp'] < 300]  # Keep 5 minutes
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(30)
    
    def check_system_events(self):
        """Check for suspicious system events"""
        events = []
        
        # Check for new processes with high privileges
        events.extend(self.check_privileged_processes())
        
        # Check for service changes
        events.extend(self.check_service_changes())
        
        # Check for registry modifications
        events.extend(self.check_registry_changes())
        
        # Check for file system changes in sensitive locations
        events.extend(self.check_file_system_changes())
        
        return events
    
    def check_privileged_processes(self):
        """Check for processes running with high privileges"""
        events = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    if proc.info['username'] and 'SYSTEM' in proc.info['username']:
                        # Check if this is a new SYSTEM process
                        event = {
                            'type': 'privileged_process',
                            'process_name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'username': proc.info['username'],
                            'timestamp': datetime.now().timestamp(),
                            'risk_level': 'medium'
                        }
                        events.append(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Process check error: {e}")
        
        return events
    
    def check_service_changes(self):
        """Check for service configuration changes"""
        events = []
        
        try:
            # Get current services
            result = subprocess.run([
                'sc', 'query', 'type=', 'service', 'state=', 'all'
            ], capture_output=True, text=True)
            
            # Simple check for service state changes
            # In a real implementation, this would compare with previous state
            if "RUNNING" in result.stdout:
                event = {
                    'type': 'service_activity',
                    'description': 'Service state change detected',
                    'timestamp': datetime.now().timestamp(),
                    'risk_level': 'low'
                }
                events.append(event)
                
        except Exception as e:
            print(f"Service check error: {e}")
        
        return events
    
    def check_registry_changes(self):
        """Check for registry modifications in sensitive locations"""
        events = []
        
        # Monitor common privilege escalation registry keys
        registry_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        
        for key in registry_keys:
            try:
                result = subprocess.run([
                    'reg', 'query', key
                ], capture_output=True, text=True)
                
                if result.returncode == 0 and "REG_SZ" in result.stdout:
                    event = {
                        'type': 'registry_modification',
                        'registry_key': key,
                        'timestamp': datetime.now().timestamp(),
                        'risk_level': 'medium'
                    }
                    events.append(event)
                    
            except Exception as e:
                continue
        
        return events
    
    def check_file_system_changes(self):
        """Check for file system changes in sensitive locations"""
        events = []
        
        sensitive_locations = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Program Files",
            "C:\\ProgramData"
        ]
        
        # This is a simplified check
        # Real implementation would use file system watchers
        for location in sensitive_locations:
            event = {
                'type': 'filesystem_monitoring',
                'location': location,
                'timestamp': datetime.now().timestamp(),
                'risk_level': 'low',
                'description': f'Monitoring sensitive location: {location}'
            }
            events.append(event)
        
        return events
    
    def trigger_alert(self, events):
        """Trigger alert for suspicious activities"""
        try:
            # Group events by type
            event_types = {}
            for event in events:
                event_type = event['type']
                if event_type not in event_types:
                    event_types[event_type] = []
                event_types[event_type].append(event)
            
            # Create alert record
            alert = {
                'alert_type': 'suspicious_activity',
                'events': events,
                'event_summary': event_types,
                'triggered_at': datetime.now(),
                'severity': self.calculate_alert_severity(events),
                'status': 'new',
                'acknowledged': False
            }
            
            # Store alert in database
            self.db.alerts.insert_one(alert)
            
            print(f"🚨 Security alert triggered: {len(events)} suspicious events detected")
            
        except Exception as e:
            print(f"Alert trigger error: {e}")
    
    def calculate_alert_severity(self, events):
        """Calculate overall alert severity"""
        risk_scores = {
            'low': 1,
            'medium': 3,
            'high': 5,
            'critical': 10
        }
        
        total_score = sum(risk_scores.get(event.get('risk_level', 'low'), 1) for event in events)
        average_score = total_score / len(events)
        
        if average_score >= 4:
            return 'high'
        elif average_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def get_recent_alerts(self, limit=10):
        """Get recent security alerts"""
        return list(self.db.alerts.find().sort('triggered_at', -1).limit(limit))
    
    def acknowledge_alert(self, alert_id):
        """Acknowledge a security alert"""
        self.db.alerts.update_one(
            {'_id': alert_id},
            {'$set': {'acknowledged': True, 'acknowledged_at': datetime.now()}}
        )