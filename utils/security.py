# utils/security.py
import bcrypt
import re
from datetime import datetime, timedelta

class SecurityUtils:
    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    @staticmethod
    def verify_password(password, hashed_password):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    @staticmethod
    def generate_session_token():
        """Generate secure session token"""
        import secrets
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def sanitize_input(user_input):
        """Sanitize user input to prevent injection attacks"""
        if not user_input:
            return user_input
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[;\"\']', '', str(user_input))
        return sanitized.strip()
    
    @staticmethod
    def check_rate_limit(user_id, action_type, db, limit=10, window_minutes=5):
        """Check if user has exceeded rate limit for an action"""
        window_start = datetime.now() - timedelta(minutes=window_minutes)
        
        count = db.rate_limits.count_documents({
            'user_id': user_id,
            'action_type': action_type,
            'timestamp': {'$gte': window_start}
        })
        
        return count < limit
    
    @staticmethod
    def record_rate_limit(user_id, action_type, db):
        """Record rate limit attempt"""
        db.rate_limits.insert_one({
            'user_id': user_id,
            'action_type': action_type,
            'timestamp': datetime.now()
        })