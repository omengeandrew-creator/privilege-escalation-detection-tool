# app/database.py
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os
from datetime import datetime
import bcrypt
from dotenv import load_dotenv

load_dotenv()

class MongoDBManager:
    def __init__(self):
        self.client = None
        self.db = None
        self.connect()
        self.initialize_database()
    
    def connect(self):
        """Connect to MongoDB"""
        try:
            # For VS Code development - using local MongoDB
            self.client = MongoClient('mongodb://localhost:27017/')
            self.db = self.client['privileged_rapper_db']
            
            # Define collection references - ADD THIS SECTION
            self.users = self.db.users
            self.findings = self.db.findings
            self.scans = self.db.scans
            self.mitigation_actions = self.db.mitigation_actions
            self.alerts = self.db.alerts  # ADD THIS LINE - FIXES THE ERROR
            self.systems = self.db.systems
            
            print("✅ Connected to MongoDB successfully")
        except ConnectionFailure as e:
            print(f"❌ MongoDB connection failed: {e}")
    
    def initialize_database(self):
        """Initialize database with default data"""
        if self.db.users.count_documents({}) == 0:
            self.create_default_users()
        
        # Create indexes for better performance - ADD THIS METHOD
        self._create_indexes()
    
    def _create_indexes(self):
        """Create database indexes for better performance"""
        # Index for alerts collection
        self.alerts.create_index([("triggered_at", -1)])
        self.alerts.create_index([("severity", 1)])
        self.alerts.create_index([("status", 1)])
        
        # Index for findings collection
        self.findings.create_index([("created_at", -1)])
        self.findings.create_index([("risk_level", 1)])
        self.findings.create_index([("status", 1)])
        
        # Index for scans collection
        self.scans.create_index([("start_time", -1)])
        self.scans.create_index([("status", 1)])
        
        print("✅ Database indexes created")
    
    def create_default_users(self):
        """Create default admin, analyst, and user accounts"""
        default_users = [
            {
                'username': 'admin',
                'email': 'admin@privilegedrapper.com',
                'password_hash': bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode(),
                'role': 'admin',
                'profile': {
                    'full_name': 'System Administrator',
                    'phone': '+1-555-0001',
                    'department': 'IT Security'
                },
                'is_active': True,
                'created_at': datetime.now(),
                'permissions': ['all']
            },
            {
                'username': 'analyst',
                'email': 'analyst@privilegedrapper.com',
                'password_hash': bcrypt.hashpw('analyst123'.encode(), bcrypt.gensalt()).decode(),
                'role': 'security_analyst',
                'profile': {
                    'full_name': 'Security Analyst',
                    'phone': '+1-555-0002',
                    'department': 'Security Operations'
                },
                'is_active': True,
                'created_at': datetime.now(),
                'permissions': ['scan', 'analyze', 'mitigate', 'report']
            },
            {
                'username': 'user1',
                'email': 'user1@company.com',
                'password_hash': bcrypt.hashpw('user123'.encode(), bcrypt.gensalt()).decode(),
                'role': 'user',
                'profile': {
                    'full_name': 'John Doe',
                    'phone': '+1-555-0003',
                    'department': 'Engineering'
                },
                'is_active': True,
                'created_at': datetime.now(),
                'permissions': ['view_own_scans', 'update_profile']
            }
        ]
        
        self.db.users.insert_many(default_users)
        print("✅ Default users created")