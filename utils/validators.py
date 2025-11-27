# utils/validators.py
import re
import ipaddress
from datetime import datetime

class Validators:
    @staticmethod
    def validate_email(email):
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_ip_address(ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_hostname(hostname):
        """Validate hostname format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, hostname))
    
    @staticmethod
    def validate_date_range(start_date, end_date):
        """Validate that start date is before end date"""
        if start_date and end_date:
            return start_date <= end_date
        return True
    
    @staticmethod
    def validate_risk_level(risk_level):
        """Validate risk level value"""
        valid_levels = ['low', 'medium', 'high', 'critical']
        return risk_level.lower() in valid_levels
    
    @staticmethod
    def validate_scan_type(scan_type):
        """Validate scan type"""
        valid_types = ['comprehensive', 'quick', 'targeted', 'custom']
        return scan_type.lower() in valid_types
    
    @staticmethod
    def validate_cvss_score(score):
        """Validate CVSS score range"""
        try:
            score_float = float(score)
            return 0.0 <= score_float <= 10.0
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to remove dangerous characters"""
        # Remove path traversal characters and other dangerous chars
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        return sanitized
    
    @staticmethod
    def validate_file_extension(filename, allowed_extensions):
        """Validate file extension"""
        if not filename:
            return False
        
        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
        return file_ext in allowed_extensions