# utils/file_handlers.py
import os
import csv
import json
from datetime import datetime
import pandas as pd

class FileHandler:
    @staticmethod
    def ensure_directory(directory):
        """Ensure directory exists"""
        os.makedirs(directory, exist_ok=True)
    
    @staticmethod
    def save_json(data, filename, directory="exports"):
        """Save data as JSON file"""
        FileHandler.ensure_directory(directory)
        filepath = os.path.join(directory, f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath
    
    @staticmethod
    def save_csv(data, filename, directory="exports"):
        """Save data as CSV file"""
        FileHandler.ensure_directory(directory)
        filepath = os.path.join(directory, f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        if isinstance(data, list) and data:
            # Convert list of dictionaries to CSV
            df = pd.DataFrame(data)
            df.to_csv(filepath, index=False, encoding='utf-8')
        elif isinstance(data, pd.DataFrame):
            data.to_csv(filepath, index=False, encoding='utf-8')
        
        return filepath
    
    @staticmethod
    def load_json(filepath):
        """Load data from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    @staticmethod
    def backup_database_collection(db, collection_name, backup_dir="backups"):
        """Backup MongoDB collection to JSON"""
        FileHandler.ensure_directory(backup_dir)
        
        collection = db[collection_name]
        data = list(collection.find({}))
        
        # Convert ObjectId to string for JSON serialization
        for item in data:
            if '_id' in item:
                item['_id'] = str(item['_id'])
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{collection_name}_backup_{timestamp}.json"
        filepath = os.path.join(backup_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return filepath
    
    @staticmethod
    def cleanup_old_files(directory, days_old=30):
        """Clean up files older than specified days"""
        cutoff_time = datetime.now().timestamp() - (days_old * 24 * 60 * 60)
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                if os.path.getmtime(filepath) < cutoff_time:
                    os.remove(filepath)