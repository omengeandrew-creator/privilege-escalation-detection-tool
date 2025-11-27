// mongo-init.js
db = db.getSiblingDB('privileged_rapper_db');

// Create collections
db.createCollection('users');
db.createCollection('scans');
db.createCollection('findings');
db.createCollection('systems');
db.createCollection('reports');
db.createCollection('alerts');
db.createCollection('ai_models');
db.createCollection('audit_logs');
db.createCollection('rate_limits');

// Create indexes
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.scans.createIndex({ "initiated_by": 1 });
db.scans.createIndex({ "start_time": -1 });
db.findings.createIndex({ "scan_id": 1 });
db.findings.createIndex({ "risk_level": 1 });
db.findings.createIndex({ "created_at": -1 });
db.alerts.createIndex({ "triggered_at": -1 });

print('✅ MongoDB initialized for Privileged Rapper Inc.');