# core/scanner.py - ENHANCED INTEGRATION
import subprocess
import os
import platform
import psutil
from datetime import datetime
import json
import streamlit as st

# NEW: Import specialized detectors
from detectors.token_manipulation import TokenManipulationDetector
from detectors.service_vulnerabilities import ServiceVulnerabilityDetector
from detectors.registry_detector import RegistryDetector
from detectors.dll_hijacking import DLLHijackingDetector
from detectors.scheduled_tasks import ScheduledTasksDetector
from detectors.uac_bypass import UACBypassDetector
from detectors.kernel_exploits import KernelExploitDetector
from detectors.password_dumping import PasswordDumpingDetector

class WindowsPrivilegeScanner:
    def __init__(self, db):
        self.db = db
        self.findings = []
        # NEW: Specialized detectors for enhanced scanning
        self.detectors = {
            'Token Manipulation': TokenManipulationDetector(),
            'Service Vulnerabilities': ServiceVulnerabilityDetector(),
            'Registry Analysis': RegistryDetector(),
            'DLL Hijacking': DLLHijackingDetector(),
            'Scheduled Tasks': ScheduledTasksDetector(),
            'UAC Bypass': UACBypassDetector(),
            'Kernel Exploits': KernelExploitDetector(),
            'Password Dumping': PasswordDumpingDetector()
        }
    
    def run_comprehensive_scan(self, scan_config):
        """Enhanced comprehensive scan with progress tracking"""
        st.info("🔍 Starting comprehensive Windows privilege escalation scan...")
        
        # NEW: Progress tracking for better UX
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        total_modules = len(scan_config['modules'])
        
        for i, module in enumerate(scan_config['modules']):
            status_text.text(f"Scanning: {module}...")
            
            # Use specialized detectors if available, otherwise use built-in methods
            if module in self.detectors:
                try:
                    detector_findings = self.detectors[module].scan()
                    self.findings.extend(detector_findings)
                    st.success(f"✅ {module}: Found {len(detector_findings)} issues")
                except Exception as e:
                    st.error(f"❌ {module} detector failed: {str(e)}")
                    # Fallback to built-in method
                    self.run_builtin_scan(module)
            else:
                # Use your original built-in scanning methods
                self.run_builtin_scan(module)
            
            progress_bar.progress((i + 1) / total_modules)
        
        status_text.text("✅ Scan completed!")
        
        # NEW: AI analysis integration
        if scan_config.get('ai_analysis', True):
            self.enhance_with_ai_analysis()
        
        return self.findings
    
    def run_builtin_scan(self, module):
        """Your original scanning methods - preserved exactly"""
        if module == "Token Manipulation":
            self.scan_token_manipulation()
        elif module == "Service Vulnerabilities":
            self.scan_service_vulnerabilities()
        elif module == "Registry Analysis":
            self.scan_registry_misconfigurations()
        elif module == "DLL Hijacking":
            self.scan_dll_hijacking()
        elif module == "Scheduled Tasks":
            self.scan_scheduled_tasks()
        elif module == "UAC Bypass":
            self.scan_uac_bypass()
        elif module == "Kernel Exploits":
            self.scan_kernel_vulnerabilities()
        elif module == "Password Dumping":
            self.scan_password_dumping_opportunities()
    
    def run_targeted_scan(self, scan_config):
        """NEW: Targeted scan for specific modules only"""
        selected_modules = scan_config.get('modules', [])
        self.findings = []
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, module in enumerate(selected_modules):
            status_text.text(f"Scanning: {module}...")
            
            if module in self.detectors:
                try:
                    detector_findings = self.detectors[module].scan()
                    self.findings.extend(detector_findings)
                except Exception as e:
                    st.error(f"❌ {module} detector failed: {str(e)}")
                    self.run_builtin_scan(module)
            else:
                self.run_builtin_scan(module)
            
            progress_bar.progress((i + 1) / len(selected_modules))
        
        status_text.text("✅ Targeted scan completed!")
        return self.findings
    
    def enhance_with_ai_analysis(self):
        """NEW: Enhance findings with AI analysis"""
        try:
            from core.ai_engine import AIAnalysisEngine
            ai_engine = AIAnalysisEngine(self.db)
            
            for finding in self.findings:
                # Use AI to predict risk if not already set
                if finding.get('risk_level') == 'medium':  # Only enhance medium confidence findings
                    predicted_risk = ai_engine.predict_risk(finding)
                    if predicted_risk != finding['risk_level']:
                        finding['ai_enhanced_risk'] = predicted_risk
                        finding['ai_confidence'] = 0.85  # Placeholder confidence score
                        
        except Exception as e:
            # AI enhancement is optional, don't break the scan
            print(f"AI enhancement failed: {e}")
    
    # YOUR ORIGINAL METHODS - PRESERVED EXACTLY
    def scan_token_manipulation(self):
        """Scan for token manipulation vulnerabilities"""
        try:
            # Check for SeDebugPrivilege and other token privileges
            result = subprocess.run([
                'whoami', '/priv'
            ], capture_output=True, text=True)
            
            if "SeDebugPrivilege" in result.stdout:
                self.add_finding(
                    title="Debug Privileges Enabled",
                    description="Current user has SeDebugPrivilege which can be abused for token manipulation",
                    risk="high",
                    category="token_manipulation",
                    evidence=result.stdout,
                    mitigation="Remove unnecessary privileges through Group Policy",
                    cvss_score=7.8
                )
        except Exception as e:
            self.add_finding(
                title="Token Privilege Check Failed",
                description=f"Unable to check token privileges: {str(e)}",
                risk="medium",
                category="token_manipulation",
                evidence=str(e),
                mitigation="Manual verification required",
                cvss_score=5.0
            )
    
    def scan_service_vulnerabilities(self):
        """Scan for service permission vulnerabilities"""
        try:
            # Check services with weak permissions
            result = subprocess.run([
                'sc', 'query'
            ], capture_output=True, text=True)
            
            # Analyze service configurations
            services = self.analyze_service_permissions()
            
            for service in services:
                if service['risk'] == 'high':
                    self.add_finding(
                        title=f"Service Vulnerability: {service['name']}",
                        description=f"Service has weak permissions that could allow privilege escalation",
                        risk=service['risk'],
                        category="service_vulnerability",
                        evidence=service['evidence'],
                        mitigation=service['mitigation'],
                        cvss_score=8.0
                    )
                    
        except Exception as e:
            self.add_finding(
                title="Service Scan Failed",
                description=f"Unable to scan services: {str(e)}",
                risk="low",
                category="service_vulnerability",
                evidence=str(e),
                mitigation="Manual service analysis required",
                cvss_score=3.0
            )
    
    def scan_registry_misconfigurations(self):
        """Scan for registry-based privilege escalation vectors"""
        try:
            # Check common registry keys for weak permissions
            registry_checks = [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            ]
            
            for key in registry_checks:
                try:
                    result = subprocess.run([
                        'reg', 'query', key
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        # Analyze registry permissions
                        perm_result = subprocess.run([
                            'reg', 'fl', key, '/t', 'REG_SZ'
                        ], capture_output=True, text=True)
                        
                        if "Everyone" in perm_result.stdout or "Users" in perm_result.stdout:
                            self.add_finding(
                                title=f"Registry Key Weak Permissions: {key}",
                                description="Registry key has weak permissions allowing write access",
                                risk="high",
                                category="registry",
                                evidence=perm_result.stdout,
                                mitigation="Restrict registry key permissions",
                                cvss_score=7.2
                            )
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            self.add_finding(
                title="Registry Scan Failed",
                description=f"Unable to scan registry: {str(e)}",
                risk="low",
                category="registry",
                evidence=str(e),
                mitigation="Manual registry analysis required",
                cvss_score=3.0
            )
    
    def scan_dll_hijacking(self):
        """Scan for DLL hijacking opportunities"""
        try:
            # Check common DLL hijacking locations
            dll_paths = [
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                "C:\\Program Files",
                "C:\\Program Files (x86)"
            ]
            
            for path in dll_paths:
                if os.path.exists(path):
                    # Check for writable directories in system paths
                    if self.is_directory_writable(path):
                        self.add_finding(
                            title=f"Writable System Directory: {path}",
                            description="System directory is writable, enabling DLL hijacking attacks",
                            risk="critical",
                            category="dll_hijacking",
                            evidence=f"Directory {path} is writable by current user",
                            mitigation="Restrict directory permissions",
                            cvss_score=8.8
                        )
                        
        except Exception as e:
            self.add_finding(
                title="DLL Hijacking Scan Failed",
                description=f"Unable to scan for DLL hijacking: {str(e)}",
                risk="low",
                category="dll_hijacking",
                evidence=str(e),
                mitigation="Manual DLL analysis required",
                cvss_score=3.0
            )
    
    def scan_scheduled_tasks(self):
        """Scan for vulnerable scheduled tasks"""
        try:
            # Get scheduled tasks
            result = subprocess.run([
                'schtasks', '/query', '/fo', 'LIST'
            ], capture_output=True, text=True)
            
            if "SYSTEM" in result.stdout and "Users" in result.stdout:
                self.add_finding(
                    title="Scheduled Task Privilege Issues",
                    description="Scheduled tasks found running with elevated privileges",
                    risk="high",
                    category="scheduled_tasks",
                    evidence=result.stdout[:500],
                    mitigation="Review and secure scheduled tasks",
                    cvss_score=7.5
                )
                
        except Exception as e:
            self.add_finding(
                title="Scheduled Task Scan Failed",
                description=f"Unable to scan scheduled tasks: {str(e)}",
                risk="low",
                category="scheduled_tasks",
                evidence=str(e),
                mitigation="Manual task scheduler analysis required",
                cvss_score=3.0
            )
    
    def scan_uac_bypass(self):
        """Scan for UAC bypass vulnerabilities"""
        try:
            # Check UAC settings
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA'
            ], capture_output=True, text=True)
            
            if "0x1" in result.stdout:
                self.add_finding(
                    title="UAC Enabled but Bypassable",
                    description="UAC is enabled but may be bypassable using known techniques",
                    risk="medium",
                    category="uac_bypass",
                    evidence=result.stdout,
                    mitigation="Implement UAC highest level and monitor for bypass attempts",
                    cvss_score=6.5
                )
                
        except Exception as e:
            self.add_finding(
                title="UAC Scan Failed",
                description=f"Unable to check UAC settings: {str(e)}",
                risk="low",
                category="uac_bypass",
                evidence=str(e),
                mitigation="Manual UAC analysis required",
                cvss_score=3.0
            )
    
    def scan_kernel_vulnerabilities(self):
        """Scan for kernel-level vulnerabilities"""
        try:
            # Get OS version information
            os_info = platform.platform()
            
            # Check for known vulnerable kernel versions
            vulnerable_versions = [
                "Windows 10 1809", "Windows 10 1903", 
                "Windows Server 2016", "Windows Server 2019"
            ]
            
            for version in vulnerable_versions:
                if version in os_info:
                    self.add_finding(
                        title=f"Potential Kernel Vulnerability: {version}",
                        description="Operating system version may have known kernel vulnerabilities",
                        risk="critical",
                        category="kernel",
                        evidence=f"Detected OS: {os_info}",
                        mitigation="Apply latest security updates and patches",
                        cvss_score=9.0
                    )
                    break
                    
        except Exception as e:
            self.add_finding(
                title="Kernel Scan Failed",
                description=f"Unable to scan for kernel vulnerabilities: {str(e)}",
                risk="low",
                category="kernel",
                evidence=str(e),
                mitigation="Manual kernel analysis required",
                cvss_score=3.0
            )
    
    def scan_password_dumping_opportunities(self):
        """Scan for password dumping attack opportunities"""
        try:
            # Check for common password storage locations
            checks = [
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\SYSTEM",
                "C:\\Windows\\System32\\config\\SECURITY"
            ]
            
            for check in checks:
                if os.path.exists(check):
                    # Check file permissions
                    if self.is_file_writable(check):
                        self.add_finding(
                            title=f"Writable System File: {check}",
                            description="Critical system file is writable, enabling password dumping attacks",
                            risk="critical",
                            category="password_dumping",
                            evidence=f"File {check} is writable by current user",
                            mitigation="Restrict file system permissions",
                            cvss_score=9.1
                        )
                        
        except Exception as e:
            self.add_finding(
                title="Password Dumping Scan Failed",
                description=f"Unable to scan for password dumping vulnerabilities: {str(e)}",
                risk="low",
                category="password_dumping",
                evidence=str(e),
                mitigation="Manual credential storage analysis required",
                cvss_score=3.0
            )
    
    def analyze_service_permissions(self):
        """Analyze service permissions for vulnerabilities"""
        # This would contain detailed service analysis logic
        return [
            {
                'name': 'ExampleService',
                'risk': 'high',
                'evidence': 'Service configured with weak permissions',
                'mitigation': 'Harden service permissions'
            }
        ]
    
    def is_directory_writable(self, path):
        """Check if directory is writable"""
        try:
            test_file = os.path.join(path, 'test_write.tmp')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True
        except:
            return False
    
    def is_file_writable(self, filepath):
        """Check if file is writable"""
        try:
            with open(filepath, 'a') as f:
                f.write('')
            return True
        except:
            return False
    
    def add_finding(self, title, description, risk, category, evidence, mitigation, cvss_score=5.0):
        """Add a security finding to the results"""
        finding = {
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': category,
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': cvss_score,
            'timestamp': datetime.now(),
            'scanner': self.__class__.__name__
        }
        self.findings.append(finding)