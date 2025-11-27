# detectors/registry_detector.py
import subprocess
import re

class RegistryDetector:
    def __init__(self):
        self.name = "Registry Misconfiguration Detector"
        self.findings = []
    
    def scan(self):
        """Scan for registry-based privilege escalation vectors"""
        self.check_autorun_keys()
        self.check_service_registry_permissions()
        self.check_lsa_secrets()
        self.check_always_install_elevated()
        return self.findings
    
    def check_autorun_keys(self):
        """Check autorun registry keys for weak permissions"""
        autorun_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        
        for key in autorun_keys:
            try:
                # Check if key exists and get permissions
                result = subprocess.run([
                    'reg', 'query', key
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Check permissions
                    perm_result = subprocess.run([
                        'reg', 'fl', key
                    ], capture_output=True, text=True)
                    
                    if "Everyone" in perm_result.stdout or "BUILTIN\\Users" in perm_result.stdout:
                        self.add_finding(
                            title=f"Weak Registry Permissions: {key}",
                            description=f"Registry key {key} has weak permissions allowing potential privilege escalation",
                            risk="high",
                            evidence=perm_result.stdout,
                            mitigation=f"Restrict permissions on registry key: {key}"
                        )
                        
            except Exception as e:
                continue
    
    def check_service_registry_permissions(self):
        """Check service registry keys for weak permissions"""
        try:
            # Get service registry paths
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse service names from output
                services = re.findall(r'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\s]+)', result.stdout)
                
                for service in services[:5]:  # Check first 5 services
                    service_key = f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}"
                    self.check_registry_key_permissions(service_key, f"Service: {service}")
                    
        except Exception as e:
            self.add_finding(
                title="Service Registry Scan Failed",
                description=f"Unable to scan service registry: {str(e)}",
                risk="low",
                evidence=str(e),
                mitigation="Manual registry analysis required"
            )
    
    def check_registry_key_permissions(self, key_path, description):
        """Check permissions on specific registry key"""
        try:
            result = subprocess.run([
                'reg', 'fl', key_path
            ], capture_output=True, text=True)
            
            if "Everyone" in result.stdout or "BUILTIN\\Users" in result.stdout:
                if "WRITE" in result.stdout or "FULL" in result.stdout:
                    self.add_finding(
                        title=f"Writable Registry Key: {description}",
                        description=f"Registry key {key_path} is writable by non-admin users",
                        risk="critical",
                        evidence=result.stdout,
                        mitigation=f"Restrict write permissions on registry key: {key_path}"
                    )
                    
        except Exception as e:
            # Key might not exist or access denied
            pass
    
    def check_lsa_secrets(self):
        """Check for LSA secrets exposure"""
        try:
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SECURITY\\Policy\\Secrets'
            ], capture_output=True, text=True)
            
            # Just checking if we can access this key (should be restricted)
            if result.returncode == 0:
                self.add_finding(
                    title="LSA Secrets Accessible",
                    description="LSA secrets registry key is accessible, potential credential exposure",
                    risk="critical",
                    evidence="LSA secrets registry key query successful",
                    mitigation="Ensure proper permissions on HKLM\\SECURITY registry hive"
                )
                
        except Exception as e:
            # Expected - LSA secrets should not be accessible
            pass
    
    def check_always_install_elevated(self):
        """Check for AlwaysInstallElevated policy"""
        keys = [
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"
        ]
        
        for key in keys:
            try:
                result = subprocess.run([
                    'reg', 'query', key, '/v', 'AlwaysInstallElevated'
                ], capture_output=True, text=True)
                
                if result.returncode == 0 and "0x1" in result.stdout:
                    self.add_finding(
                        title="AlwaysInstallElevated Enabled",
                        description=f"AlwaysInstallElevated policy enabled in {key}, allowing non-admin MSI installation",
                        risk="high",
                        evidence=result.stdout,
                        mitigation="Disable AlwaysInstallElevated policy through Group Policy"
                    )
                    
            except Exception as e:
                continue
    
    def add_finding(self, title, description, risk, evidence, mitigation):
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': 'registry',
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk)
        })
    
    def calculate_cvss(self, risk):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.5,
            'low': 3.0
        }
        return scores.get(risk, 5.0)