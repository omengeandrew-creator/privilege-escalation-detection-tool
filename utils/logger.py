# utils/logger.py
import logging
import os
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        # Create log file with timestamp
        log_file = os.path.join(log_dir, f"security_platform_{datetime.now().strftime('%Y%m%d')}.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('PrivilegedRapper')
    
    def log_login(self, username, success=True):
        """Log login attempts"""
        if success:
            self.logger.info(f"Successful login: {username}")
        else:
            self.logger.warning(f"Failed login attempt: {username}")
    
    def log_scan(self, user_id, scan_type, target_system):
        """Log scan activities"""
        self.logger.info(f"Scan initiated - User: {user_id}, Type: {scan_type}, Target: {target_system}")
    
    def log_finding(self, finding_id, risk_level):
        """Log security findings"""
        self.logger.warning(f"Security finding - ID: {finding_id}, Risk: {risk_level}")
    
    def log_mitigation(self, finding_id, user_id, action):
        """Log mitigation actions"""
        self.logger.info(f"Mitigation action - Finding: {finding_id}, User: {user_id}, Action: {action}")
    
    def log_error(self, error_message, module=None):
        """Log error messages"""
        if module:
            self.logger.error(f"Error in {module}: {error_message}")
        else:
            self.logger.error(f"Error: {error_message}")
    
    def log_audit(self, user_id, action, resource, details=None):
        """Log audit trail"""
        audit_message = f"Audit - User: {user_id}, Action: {action}, Resource: {resource}"
        if details:
            audit_message += f", Details: {details}"
        self.logger.info(audit_message)