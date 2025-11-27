# utils/config_loader.py
import yaml
import os

class ConfigLoader:
    def __init__(self):
        self.config = {}
        self.load_configurations()
    
    def load_configurations(self):
        """Load all configuration files"""
        config_files = {
            'app': 'configuration/config.yaml',
            'database': 'configuration/mongodb_config.yaml',
            'scanning': 'configuration/scan_config.yaml'
        }
        
        for config_type, file_path in config_files.items():
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as file:
                        self.config[config_type] = yaml.safe_load(file)
                else:
                    print(f"Warning: Config file not found: {file_path}")
                    self.config[config_type] = self.get_default_config(config_type)
            except Exception as e:
                print(f"Error loading config {file_path}: {e}")
                self.config[config_type] = self.get_default_config(config_type)
    
    def get_default_config(self, config_type):
        """Get default configuration for each type"""
        defaults = {
            'app': {
                'name': 'Privileged Rapper Inc.',
                'version': '1.0.0',
                'debug': False
            },
            'database': {
                'host': 'localhost',
                'port': 27017,
                'name': 'privileged_rapper_db'
            },
            'scanning': {
                'default_scan_type': 'comprehensive',
                'max_concurrent_scans': 3
            }
        }
        return defaults.get(config_type, {})
    
    def get(self, key, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def update_config(self, config_type, new_config):
        """Update configuration and save to file"""
        if config_type in self.config:
            self.config[config_type].update(new_config)
            
            # Save to file
            file_path = f'configuration/{config_type}.yaml'
            with open(file_path, 'w') as file:
                yaml.dump(self.config[config_type], file)