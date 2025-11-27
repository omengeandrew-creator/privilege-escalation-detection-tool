# detectors/uac_bypass.py
import subprocess
import re

class UACBypassDetector:
    def __init__(self):
        self.name = "UAC Bypass Detector"
        self.findings = []
    
    def scan(self):
        """Scan for UAC bypass vulnerabilities"""
        self.check_uac_settings()
        self.check_uac_bypass_techniques()
        self.check_auto_elevation()
        return self.findings
    
    def check_uac_settings(self):
        """Check UAC configuration settings"""
        try:
            # Check UAC level
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'ConsentPromptBehaviorAdmin'
            ], capture_output=True, text=True)
            
            uac_level = "Unknown"
            if "0x0" in result.stdout:
                uac_level = "Never notify (Disabled)"
                risk = "critical"
            elif "0x1" in result.stdout:
                uac_level = "Always notify (Highest)"
                risk = "low"
            elif "0x2" in result.stdout:
                uac_level = "Notify only when programs try to make changes (Default)"
                risk = "medium"
            elif "0x3" in result.stdout:
                uac_level = "Notify only when programs try to make changes (do not dim desktop)"
                risk = "medium"
            else:
                risk = "medium"
            
            self.add_finding(
                title=f"UAC Configuration: {uac_level}",
                description=f"User Account Control is configured to: {uac_level}",
                risk=risk,
                evidence=result.stdout,
                mitigation="Configure UAC to highest level for maximum security"
            )
            
            # Check EnableLUA
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA'
            ], capture_output=True, text=True)
            
            if "0x0" in result.stdout:
                self.add_finding(
                    title="UAC Completely Disabled",
                    description="User Account Control is completely disabled (EnableLUA = 0)",
                    risk="critical",
                    evidence=result.stdout,
                    mitigation="Enable UAC by setting EnableLUA to 1"
                )
                
        except Exception as e:
            self.add_finding(
                title="UAC Settings Check Failed",
                description=f"Unable to check UAC settings: {str(e)}",
                risk="low",
                evidence=str(e),
                mitigation="Manual UAC configuration review required"
            )
    
    def check_uac_bypass_techniques(self):
        """Check for common UAC bypass techniques"""
        # Check for vulnerable system files and configurations
        checks = [
            {
                'name': 'FodHelper Bypass',
                'description': 'Check for FodHelper UAC bypass vulnerability',
                'risk': 'medium'
            },
            {
                'name': 'Event Viewer Bypass', 
                'description': 'Check for Event Viewer UAC bypass vulnerability',
                'risk': 'medium'
            },
            {
                'name': 'SDCLT Bypass',
                'description': 'Check for SDCLT UAC bypass vulnerability',
                'risk': 'medium'
            }
        ]
        
        for check in checks:
            self.add_finding(
                title=f"Potential UAC Bypass: {check['name']}",
                description=check['description'],
                risk=check['risk'],
                evidence="Manual verification required for specific UAC bypass techniques",
                mitigation="Keep system updated and monitor for UAC bypass attempts"
            )
    
    def check_auto_elevation(self):
        """Check for auto-elevation configurations"""
        try:
            # Check for auto-elevation settings
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableInstallerDetection'
            ], capture_output=True, text=True)
            
            if "0x0" in result.stdout:
                self.add_finding(
                    title="Installer Detection Disabled",
                    description="Installer detection is disabled, reducing UAC effectiveness",
                    risk="medium",
                    evidence=result.stdout,
                    mitigation="Enable installer detection for better UAC protection"
                )
                
        except Exception as e:
            pass
    
    def add_finding(self, title, description, risk, evidence, mitigation):
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': 'uac_bypass',
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk)
        })
    
    def calculate_cvss(self, risk):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 7.8,
            'high': 6.8,
            'medium': 5.5,
            'low': 3.0
        }
        return scores.get(risk, 5.0)