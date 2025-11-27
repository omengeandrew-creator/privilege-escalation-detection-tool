# detectors/scheduled_tasks.py
import subprocess
import re
import os

class ScheduledTasksDetector:
    def __init__(self):
        self.name = "Scheduled Tasks Detector"
        self.findings = []
    
    def scan(self):
        """Scan for scheduled task vulnerabilities"""
        self.check_task_permissions()
        self.check_unquoted_task_paths()
        self.check_task_privileges()
        return self.findings
    
    def check_task_permissions(self):
        """Check scheduled tasks with weak permissions"""
        try:
            # Get all scheduled tasks
            result = subprocess.run([
                'schtasks', '/query', '/fo', 'LIST', '/v'
            ], capture_output=True, text=True)
            
            tasks = self.parse_scheduled_tasks(result.stdout)
            
            for task in tasks:
                self.analyze_task_vulnerabilities(task)
                
        except Exception as e:
            self.add_finding(
                title="Scheduled Task Scan Failed",
                description=f"Unable to scan scheduled tasks: {str(e)}",
                risk="low",
                evidence=str(e),
                mitigation="Manual scheduled task analysis required"
            )
    
    def parse_scheduled_tasks(self, output):
        """Parse scheduled tasks from schtasks output"""
        tasks = []
        current_task = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('TaskName:'):
                if current_task:
                    tasks.append(current_task)
                current_task = {'TaskName': line.split(':', 1)[1].strip()}
            elif line.startswith('Run As User:'):
                current_task['RunAsUser'] = line.split(':', 1)[1].strip()
            elif line.startswith('Task To Run:'):
                current_task['Command'] = line.split(':', 1)[1].strip()
            elif line.startswith('Start In:'):
                current_task['StartIn'] = line.split(':', 1)[1].strip()
        
        if current_task:
            tasks.append(current_task)
        
        return tasks
    
    def analyze_task_vulnerabilities(self, task):
        """Analyze individual task for vulnerabilities"""
        task_name = task.get('TaskName', 'Unknown')
        run_as_user = task.get('RunAsUser', '')
        command = task.get('Command', '')
        
        # Check for SYSTEM privileges
        if 'SYSTEM' in run_as_user or 'NT AUTHORITY\\SYSTEM' in run_as_user:
            self.add_finding(
                title=f"Scheduled Task Running as SYSTEM: {task_name}",
                description=f"Scheduled task '{task_name}' runs with SYSTEM privileges",
                risk="high",
                evidence=f"Run As User: {run_as_user}",
                mitigation=f"Review and downgrade privileges for task: {task_name}"
            )
        
        # Check for unquoted paths
        if self.has_unquoted_path(command):
            self.add_finding(
                title=f"Unquoted Task Path: {task_name}",
                description=f"Scheduled task '{task_name}' has unquoted path in command",
                risk="medium",
                evidence=f"Command: {command}",
                mitigation=f"Add quotes to task command path: {command}"
            )
        
        # Check for writable task directories
        start_in = task.get('StartIn', '')
        if start_in and os.path.exists(start_in):
            if self.is_directory_writable(start_in):
                self.add_finding(
                    title=f"Writable Task Directory: {task_name}",
                    description=f"Scheduled task '{task_name}' starts in writable directory",
                    risk="high",
                    evidence=f"Start In: {start_in}",
                    mitigation=f"Restrict permissions on directory: {start_in}"
                )
    
    def check_unquoted_task_paths(self):
        """Check for unquoted paths in scheduled tasks"""
        try:
            # Use PowerShell for more detailed task information
            ps_script = """
            Get-ScheduledTask | ForEach-Object {
                $task = $_
                $action = $task.Actions[0]
                if ($action -and $action.Execute) {
                    Write-Output "$($task.TaskName)|$($action.Execute)|$($action.WorkingDirectory)"
                }
            }
            """
            
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if '|' in line:
                    task_name, execute, working_dir = line.split('|')
                    if self.has_unquoted_path(execute):
                        self.add_finding(
                            title=f"Unquoted Task Path: {task_name}",
                            description=f"Scheduled task has unquoted path: {execute}",
                            risk="medium",
                            evidence=f"Task: {task_name}, Command: {execute}",
                            mitigation=f"Add quotes to task path: \"{execute}\""
                        )
                        
        except Exception as e:
            # PowerShell might not be available
            pass
    
    def check_task_privileges(self):
        """Check for privileged scheduled tasks"""
        try:
            # Check for tasks with high privileges
            result = subprocess.run([
                'schtasks', '/query', '/fo', 'CSV'
            ], capture_output=True, text=True)
            
            # Look for tasks with elevated privileges
            if "SYSTEM" in result.stdout:
                self.add_finding(
                    title="Privileged Scheduled Tasks Detected",
                    description="Scheduled tasks found running with elevated privileges",
                    risk="high",
                    evidence="SYSTEM privileges found in scheduled tasks",
                    mitigation="Review all scheduled tasks and downgrade privileges where possible"
                )
                
        except Exception as e:
            print(f"Task privilege check error: {e}")
    
    def has_unquoted_path(self, path):
        """Check if path is unquoted and contains spaces"""
        if not path:
            return False
        
        path = path.strip()
        if ' ' in path and not path.startswith('"'):
            return True
        
        return False
    
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
            'category': 'scheduled_tasks',
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