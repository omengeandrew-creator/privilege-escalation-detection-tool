# detectors/password_dumping.py
import os
import subprocess

class PasswordDumpingDetector:
    def __init__(self):
        self.name = "Password Dumping Detector"
        self.findings = []
    
    def scan(self):
        """Scan for password dumping vulnerabilities"""
        self.check_sam_file_permissions()
        self.check_lsa_secrets_access()
        self.check_credential_files()
        self.check_wdigest_settings()
        return self.findings
    
    def check_sam_file_permissions(self):
        """Check SAM database file permissions"""
        sam_files = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\SECURITY"
        ]
        
        for sam_file in sam_files:
            if os.path.exists(sam_file):
                if self.is_file_accessible(sam_file):
                    self.add_finding(
                        title=f"Accessible SAM File: {sam_file}",
                        description=f"SAM database file is accessible: {sam_file}. This could enable password dumping attacks.",
                        risk="critical",
                        evidence=f"File {sam_file} is accessible",
                        mitigation=f"Restrict access to SAM database files"
                    )
    
    def check_lsa_secrets_access(self):
        """Check LSA secrets accessibility"""
        try:
            # Try to access LSA secrets registry key
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SECURITY\\Policy\\Secrets'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.add_finding(
                    title="LSA Secrets Accessible",
                    description="LSA secrets registry key is accessible, potential credential exposure",
                    risk="critical",
                    evidence="LSA secrets registry query successful",
                    mitigation="Ensure proper permissions on HKLM\\SECURITY registry hive"
                )
                
        except Exception as e:
            # Expected - LSA secrets should not be accessible
            pass
    
    def check_credential_files(self):
        """Check for credential files and weak permissions"""
        credential_locations = [
            "C:\\Windows\\System32\\config",
            "C:\\Users\\",
            "C:\\ProgramData\\Microsoft\\Credentials",
            "C:\\Windows\\Temp"
        ]
        
        for location in credential_locations:
            if os.path.exists(location):
                # Check for common credential file patterns
                if self.has_credential_files(location):
                    self.add_finding(
                        title=f"Potential Credential Files in {location}",
                        description=f"Potential credential files found in {location}",
                        risk="high",
                        evidence=f"Location: {location}",
                        mitigation=f"Secure and monitor credential storage locations"
                    )
    
    def check_wdigest_settings(self):
        """Check WDigest configuration for cleartext credentials"""
        try:
            result = subprocess.run([
                'reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest', '/v', 'UseLogonCredential'
            ], capture_output=True, text=True)
            
            if "0x1" in result.stdout:
                self.add_finding(
                    title="WDigest Cleartext Credentials Enabled",
                    description="WDigest is configured to store credentials in cleartext memory",
                    risk="critical",
                    evidence=result.stdout,
                    mitigation="Disable WDigest cleartext credential storage by setting UseLogonCredential to 0"
                )
                
        except Exception as e:
            # Key might not exist (good - means default secure configuration)
            pass
    
    def is_file_accessible(self, filepath):
        """Check if file is accessible/readable"""
        try:
            with open(filepath, 'rb') as f:
                f.read(1)  # Try to read one byte
            return True
        except:
            return False
    
    def has_credential_files(self, directory):
        """Check if directory contains potential credential files"""
        try:
            # Look for common credential file patterns
            credential_patterns = ['.cred', '.pwd', 'password', 'credential', 'hash', 'sam']
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if any(pattern in file.lower() for pattern in credential_patterns):
                        return True
                break  # Only check top level for performance
        except:
            pass
        
        return False
    
    def add_finding(self, title, description, risk, evidence, mitigation):
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': 'password_dumping',
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk)
        })
    
    def calculate_cvss(self, risk):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 9.1,
            'high': 7.8,
            'medium': 5.5,
            'low': 3.0
        }
        return scores.get(risk, 5.0)