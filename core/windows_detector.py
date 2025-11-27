# core/windows_detector.py
import subprocess
import os
import platform
import winreg
from datetime import datetime
from typing import List, Dict

class WindowsDetector:
    """Comprehensive Windows-specific privilege escalation detector"""
    
    def __init__(self):
        self.findings = []
        self.os_info = self.get_os_info()
    
    def get_os_info(self):
        """Get detailed Windows OS information"""
        return {
            'platform': platform.platform(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor()
        }
    
    def run_comprehensive_detection(self):
        """Run all Windows-specific detection methods"""
        self.detect_windows_specific_vectors()
        return self.findings
    
    def detect_windows_specific_vectors(self):
        """Detect Windows-specific privilege escalation vectors"""
        self.check_windows_features()
        self.check_group_policy()
        self.check_applocker()
        self.check_defender_settings()
        self.check_rdp_settings()
        self.check_shared_resources()
    
    def check_windows_features(self):
        """Check Windows features and optional components"""
        try:
            # Check if PowerShell v2 is enabled (common attack vector)
            result = subprocess.run([
                'powershell', 'Get-WindowsOptionalFeature', '-Online', '-FeatureName', 'MicrosoftWindowsPowerShellV2'
            ], capture_output=True, text=True)
            
            if "Enabled" in result.stdout:
                self.add_finding(
                    title="PowerShell v2 Enabled",
                    description="PowerShell version 2 is enabled, which can be used for downgrade attacks",
                    risk="medium",
                    category="windows_features",
                    evidence=result.stdout,
                    mitigation="Disable PowerShell v2 through Windows Features"
                )
        except Exception as e:
            pass
    
    def check_group_policy(self):
        """Check Group Policy settings for misconfigurations"""
        try:
            # Check for AlwaysInstallElevated policy
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', '/v', 'AlwaysInstallElevated'
            ], capture_output=True, text=True)
            
            if "0x1" in result.stdout:
                self.add_finding(
                    title="AlwaysInstallElevated Policy Enabled",
                    description="MSI packages can be installed with elevated privileges by non-admin users",
                    risk="high",
                    category="group_policy",
                    evidence=result.stdout,
                    mitigation="Disable AlwaysInstallElevated policy through Group Policy"
                )
        except Exception as e:
            pass
    
    def check_applocker(self):
        """Check AppLocker configuration"""
        try:
            result = subprocess.run([
                'powershell', 'Get-AppLockerPolicy', '-Effective', '-Xml'
            ], capture_output=True, text=True)
            
            if "Not defined" in result.stdout or result.returncode != 0:
                self.add_finding(
                    title="AppLocker Not Configured",
                    description="Application whitelisting is not enforced through AppLocker",
                    risk="medium",
                    category="application_control",
                    evidence="AppLocker policy not found or not enforced",
                    mitigation="Implement AppLocker policies to restrict unauthorized application execution"
                )
        except Exception as e:
            pass
    
    def check_defender_settings(self):
        """Check Windows Defender settings"""
        try:
            # Check if real-time protection is enabled
            result = subprocess.run([
                'powershell', 'Get-MpComputerStatus'
            ], capture_output=True, text=True)
            
            if "AntivirusEnabled : False" in result.stdout:
                self.add_finding(
                    title="Windows Defender Antivirus Disabled",
                    description="Real-time antivirus protection is disabled",
                    risk="high",
                    category="defender_settings",
                    evidence=result.stdout,
                    mitigation="Enable Windows Defender real-time protection"
                )
            
            if "AntispywareEnabled : False" in result.stdout:
                self.add_finding(
                    title="Windows Defender Antispyware Disabled",
                    description="Antispyware protection is disabled",
                    risk="high",
                    category="defender_settings",
                    evidence=result.stdout,
                    mitigation="Enable Windows Defender antispyware protection"
                )
        except Exception as e:
            pass
    
    def check_rdp_settings(self):
        """Check RDP configuration and security settings"""
        try:
            # Check if RDP is enabled
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections'
            ], capture_output=True, text=True)
            
            if "0x0" in result.stdout:
                self.add_finding(
                    title="Remote Desktop Enabled",
                    description="Remote Desktop Protocol is enabled, increasing attack surface",
                    risk="medium",
                    category="rdp_settings",
                    evidence=result.stdout,
                    mitigation="Disable RDP if not required, or implement Network Level Authentication"
                )
        except Exception as e:
            pass
    
    def check_shared_resources(self):
        """Check for insecure shared resources"""
        try:
            # Check for network shares
            result = subprocess.run(['net', 'share'], capture_output=True, text=True)
            
            shares = []
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('Share name'):
                    parts = line.split()
                    if len(parts) > 0:
                        shares.append(parts[0])
            
            if shares:
                self.add_finding(
                    title="Network Shares Detected",
                    description=f"Network shares found: {', '.join(shares[:3])}",
                    risk="low",
                    category="shared_resources",
                    evidence=f"Shares: {shares}",
                    mitigation="Review share permissions and restrict access as needed"
                )
        except Exception as e:
            pass
    
    def check_windows_firewall(self):
        """Check Windows Firewall status"""
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'show', 'allprofiles'
            ], capture_output=True, text=True)
            
            if "State                                 OFF" in result.stdout:
                self.add_finding(
                    title="Windows Firewall Disabled",
                    description="Windows Firewall is disabled on one or more profiles",
                    risk="high",
                    category="firewall_settings",
                    evidence=result.stdout,
                    mitigation="Enable Windows Firewall for all network profiles"
                )
        except Exception as e:
            pass
    
    def add_finding(self, title: str, description: str, risk: str, category: str, evidence: str, mitigation: str):
        """Add a security finding"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': category,
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk),
            'timestamp': datetime.now(),
            'detector': self.__class__.__name__
        })
    
    def calculate_cvss(self, risk: str):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return scores.get(risk, 5.0)