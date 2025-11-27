# detectors/dll_hijacking.py
import os
import subprocess

class DLLHijackingDetector:
    def __init__(self):
        self.name = "DLL Hijacking Detector"
        self.findings = []
    
    def scan(self):
        """Scan for DLL hijacking vulnerabilities"""
        self.check_writable_system_paths()
        self.check_dll_search_order()
        self.check_application_directories()
        return self.findings
    
    def check_writable_system_paths(self):
        """Check for writable directories in system PATH"""
        try:
            # Get system PATH
            result = subprocess.run(['echo', '%PATH%'], shell=True, capture_output=True, text=True)
            path_dirs = result.stdout.strip().split(';')
            
            for path_dir in path_dirs:
                if os.path.exists(path_dir):
                    if self.is_directory_writable(path_dir):
                        self.add_finding(
                            title=f"Writable PATH Directory: {path_dir}",
                            description=f"Directory in system PATH is writable: {path_dir}. This enables DLL hijacking attacks.",
                            risk="critical",
                            evidence=f"Directory {path_dir} is writable by current user",
                            mitigation=f"Remove write permissions from system PATH directory: {path_dir}"
                        )
                        
        except Exception as e:
            self.add_finding(
                title="PATH Analysis Failed",
                description=f"Unable to analyze system PATH: {str(e)}",
                risk="low",
                evidence=str(e),
                mitigation="Manual PATH analysis required"
            )
    
    def check_dll_search_order(self):
        """Check DLL search order vulnerabilities"""
        # Common DLL hijacking locations
        hijack_locations = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64", 
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)"
        ]
        
        for location in hijack_locations:
            if os.path.exists(location):
                # Check for applications that load DLLs from current directory
                self.check_application_dll_loading(location)
    
    def check_application_dll_loading(self, directory):
        """Check for applications that might be vulnerable to DLL hijacking"""
        try:
            # Look for executable files
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.lower().endswith('.exe'):
                        exe_path = os.path.join(root, file)
                        
                        # Check if executable is in a writable directory
                        if self.is_directory_writable(root):
                            self.add_finding(
                                title=f"Potential DLL Hijacking: {file}",
                                description=f"Executable {file} is in a writable directory, making it vulnerable to DLL hijacking",
                                risk="high",
                                evidence=f"Executable path: {exe_path}",
                                mitigation=f"Move executable to non-writable directory or secure permissions"
                            )
                        break  # Only check first executable per directory
                break  # Only check top level for demonstration
                
        except Exception as e:
            # Access denied or other issues
            pass
    
    def check_application_directories(self):
        """Check application-specific directories for DLL hijacking"""
        common_app_paths = [
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Users\\Public",
            "C:\\Windows\\Temp"
        ]
        
        for app_path in common_app_paths:
            if os.path.exists(app_path):
                if self.is_directory_writable(app_path):
                    self.add_finding(
                        title=f"Writable Application Directory: {app_path}",
                        description=f"Application directory is writable: {app_path}",
                        risk="medium",
                        evidence=f"Directory {app_path} is writable",
                        mitigation=f"Restrict write permissions on application directory"
                    )
    
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
    
    def add_finding(self, title, description, risk, evidence, mitigation):
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': 'dll_hijacking',
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk)
        })
    
    def calculate_cvss(self, risk):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 8.8,
            'high': 7.5,
            'medium': 5.5,
            'low': 3.0
        }
        return scores.get(risk, 5.0)