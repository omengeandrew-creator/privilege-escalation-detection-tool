# app/auth.py
import bcrypt
from datetime import datetime

class AuthenticationSystem:
    def __init__(self, db_manager):
        self.db = db_manager.db
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        user = self.db.users.find_one({'username': username, 'is_active': True})
        
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            # Update last login
            self.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': datetime.now()}}
            )
            return True
        return False
    
    def get_user_info(self, username):
        """Get user information without password"""
        user = self.db.users.find_one({'username': username})
        if user:
            return {
                'user_id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'profile': user.get('profile', {}),
                'permissions': user.get('permissions', [])
            }
        return None