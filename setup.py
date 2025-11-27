# setup.py
import os
import sys
import subprocess
import time

def setup_privileged_rapper():
    print("🚀 Setting up Privileged Rapper Inc. Security Platform...")
    
    # Create necessary directories
    directories = [
        'reports',
        'logs',
        'assets/images',
        'assets/css',
        'data/ai_training',
        'configuration'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    # Install requirements
    print("📦 Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    print("""
    🎉 Setup completed successfully!
    
    Next steps:
    1. Ensure MongoDB is running on localhost:27017
    2. Run the application: python run.py
    3. Access at: http://localhost:8501
    
    Default login credentials:
    - Admin: admin / admin123
    - Analyst: analyst / analyst123  
    - User: user1 / user123
    
    🔒 Remember to change default passwords after first login!
    """)

if __name__ == "__main__":
    setup_privileged_rapper()