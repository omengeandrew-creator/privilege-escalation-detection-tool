# detectors/service_vulnerabilities.py
import subprocess
import re

class ServiceVulnerabilityDetector:
    def __init__(self):
        self.name = "Service Vulnerability Detector"
        self.findings = []
    
    def scan(self):
        """Scan for service-related vulnerabilities"""
        self.check_service_permissions()
        self.check_unquoted_service_paths()
        self.check_service_binary_permissions()
        return self.findings
    
    def check_service_permissions(self):
        """Check services with weak permissions"""
        try:
            # Get all services
            result = subprocess.run([
                'sc', 'query'
            ], capture_output=True, text=True)
            
            services = self.parse_services(result.stdout)
            
            for service in services[:10]:  # Check first 10 services
                self.analyze_service_permissions(service)
                
        except Exception as e:
            self.add_finding(
                title="Service Permission Scan Failed",
                description=f"Unable to scan service permissions: {str(e)}",
                risk="low",
                evidence=str(e),
                mitigation="Manual service analysis required"
            )
    
    def parse_services(self, output):
        """Parse services from sc query output"""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            if 'SERVICE_NAME:' in line:
                service_name = line.split('SERVICE_NAME:')[1].strip()
                services.append(service_name)
        
        return services
    
    def analyze_service_permissions(self, service_name):
        """Analyze permissions for a specific service"""
        try:
            # Get service configuration
            result = subprocess.run([
                'sc', 'qc', service_name
            ], capture_output=True, text=True)
            
            # Check for common issues
            if "WORLD" in result.stdout or "Everyone" in result.stdout:
                self.add_finding(
                    title=f"Service with Weak Permissions: {service_name}",
                    description=f"Service {service_name} has permissions accessible to Everyone",
                    risk="high",
                    evidence=result.stdout,
                    mitigation=f"Restrict permissions for service {service_name}"
                )
            
            # Check for unquoted paths
            if self.has_unquoted_path(result.stdout):
                self.add_finding(
                    title=f"Unquoted Service Path: {service_name}",
                    description=f"Service {service_name} has unquoted path vulnerability",
                    risk="medium",
                    evidence=result.stdout,
                    mitigation=f"Add quotes to service path for {service_name}"
                )
                
        except Exception as e:
            # Service might not exist or access denied
            pass
    
    def has_unquoted_path(self, service_config):
        """Check if service has unquoted path vulnerability"""
        # Look for paths without quotes that contain spaces
        path_pattern = r'BINARY_PATH_NAME\s*:\s*([^\r\n]+)'
        match = re.search(path_pattern, service_config)
        
        if match:
            path = match.group(1).strip()
            if ' ' in path and not path.startswith('"'):
                return True
        
        return False
    
    def check_unquoted_service_paths(self):
        """Check for unquoted service paths"""
        try:
            result = subprocess.run([
                'wmic', 'service', 'get', 'name,pathname'
            ], capture_output=True, text=True)
            
            lines = result.stdout.split('\n')
            for line in lines:
                if '.exe' in line and 'C:\\' in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        service_name = parts[0]
                        path = ' '.join(parts[1:])
                        
                        if ' ' in path and not path.startswith('"'):
                            self.add_finding(
                                title=f"Unquoted Service Path: {service_name}",
                                description=f"Service {service_name} has unquoted path with spaces",
                                risk="medium",
                                evidence=f"Path: {path}",
                                mitigation=f"Add quotes to service path: \"{path}\""
                            )
                            
        except Exception as e:
            print(f"Unquoted path check error: {e}")
    
    def check_service_binary_permissions(self):
        """Check permissions on service binary files"""
        # This would check file permissions on service executables
        # Implementation would require detailed file system analysis
        pass
    
    def add_finding(self, title, description, risk, evidence, mitigation):
        """Add a finding to the results"""
        self.findings.append({
            'title': title,
            'description': description,
            'risk_level': risk,
            'category': 'service_vulnerability',
            'evidence': evidence,
            'mitigation': mitigation,
            'cvss_score': self.calculate_cvss(risk)
        })
    
    def calculate_cvss(self, risk):
        """Calculate CVSS score based on risk level"""
        scores = {
            'critical': 8.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return scores.get(risk, 5.0)