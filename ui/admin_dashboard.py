# ui/admin_dashboard.py
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

class AdminDashboard:
    def __init__(self, db, user_info):
        self.db = db.db
        self.user_info = user_info
    
    def show_dashboard(self):
        """Display admin dashboard"""
        st.title("🏠 Admin Dashboard")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        total_users = self.db.users.count_documents({})
        active_scans = self.db.scans.count_documents({'status': 'running'})
        critical_findings = self.db.findings.count_documents({'risk_level': 'critical'})
        total_systems = self.db.systems.count_documents({})
        
        with col1:
            st.metric("Total Users", total_users)
        with col2:
            st.metric("Active Scans", active_scans)
        with col3:
            st.metric("Critical Findings", critical_findings)
        with col4:
            st.metric("Managed Systems", total_systems)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            self.show_user_role_chart()
        with col2:
            self.show_risk_distribution_chart()
        
        # Recent activity
        st.subheader("Recent Activity")
        self.show_recent_activity()
    
    def show_user_role_chart(self):
        """Display user role distribution chart"""
        pipeline = [
            {"$group": {"_id": "$role", "count": {"$sum": 1}}}
        ]
        role_data = list(self.db.users.aggregate(pipeline))
        
        if role_data:
            df = pd.DataFrame(role_data)
            fig = px.pie(df, names='_id', values='count', title="User Role Distribution")
            st.plotly_chart(fig, use_container_width=True)
    
    def show_risk_distribution_chart(self):
        """Display risk distribution chart"""
        pipeline = [
            {"$group": {"_id": "$risk_level", "count": {"$sum": 1}}}
        ]
        risk_data = list(self.db.findings.aggregate(pipeline))
        
        if risk_data:
            df = pd.DataFrame(risk_data)
            fig = px.bar(df, x='_id', y='count', title="Risk Level Distribution",
                        color='_id', color_discrete_map={
                            'critical': 'red',
                            'high': 'orange',
                            'medium': 'yellow',
                            'low': 'green'
                        })
            st.plotly_chart(fig, use_container_width=True)
    
    def show_recent_activity(self):
        """Display recent system activity"""
        recent_scans = list(self.db.scans.find().sort('start_time', -1).limit(10))
        
        if recent_scans:
            scan_data = []
            for scan in recent_scans:
                scan_data.append({
                    'Scan ID': str(scan['_id'])[:8],
                    'Target': scan.get('target_system', 'Unknown'),
                    'Type': scan.get('scan_type', 'Unknown'),
                    'Status': scan.get('status', 'Unknown'),
                    'Findings': scan.get('findings_count', 0),
                    'Started': scan.get('start_time', datetime.now()).strftime('%Y-%m-%d %H:%M')
                })
            
            df = pd.DataFrame(scan_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No recent scan activity")
    
    def show_user_management(self):
        """Display user management interface"""
        st.title("👥 User Management")
        
        # Add new user
        with st.expander("Add New User", expanded=False):
            with st.form("add_user_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    new_username = st.text_input("Username")
                    new_email = st.text_input("Email")
                    new_password = st.text_input("Password", type="password")
                
                with col2:
                    new_role = st.selectbox("Role", ["admin", "security_analyst", "user"])
                    new_fullname = st.text_input("Full Name")
                    new_department = st.text_input("Department")
                
                if st.form_submit_button("Create User"):
                    self.create_user(new_username, new_email, new_password, new_role, new_fullname, new_department)
        
        # User list with management options
        st.subheader("User Accounts")
        users = list(self.db.users.find({}, {'password_hash': 0}))
        
        if users:
            user_data = []
            for user in users:
                user_data.append({
                    'Username': user['username'],
                    'Email': user['email'],
                    'Role': user['role'],
                    'Full Name': user.get('profile', {}).get('full_name', ''),
                    'Department': user.get('profile', {}).get('department', ''),
                    'Status': 'Active' if user.get('is_active', True) else 'Inactive',
                    'Last Login': user.get('last_login', 'Never')
                })
            
            df = pd.DataFrame(user_data)
            st.dataframe(df, use_container_width=True)
            
            # User actions
            col1, col2, col3 = st.columns(3)
            
            with col1:
                user_to_edit = st.selectbox("Select User", [user['username'] for user in users])
            
            with col2:
                new_role = st.selectbox("New Role", ["admin", "security_analyst", "user"])
                if st.button("Update Role"):
                    self.update_user_role(user_to_edit, new_role)
            
            with col3:
                if st.button("Deactivate User", type="secondary"):
                    self.toggle_user_status(user_to_edit, False)
                if st.button("Activate User", type="primary"):
                    self.toggle_user_status(user_to_edit, True)
    
    def create_user(self, username, email, password, role, full_name, department):
        """Create a new user"""
        import bcrypt
        
        if self.db.users.find_one({'username': username}):
            st.error("Username already exists")
            return
        
        user_data = {
            'username': username,
            'email': email,
            'password_hash': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            'role': role,
            'profile': {
                'full_name': full_name,
                'department': department
            },
            'is_active': True,
            'created_at': datetime.now(),
            'permissions': self.get_default_permissions(role)
        }
        
        self.db.users.insert_one(user_data)
        st.success(f"User {username} created successfully!")
    
    def get_default_permissions(self, role):
        """Get default permissions for each role"""
        permissions = {
            'admin': ['all'],
            'security_analyst': ['scan', 'analyze', 'mitigate', 'report', 'view_all_scans'],
            'user': ['view_own_scans', 'update_profile']
        }
        return permissions.get(role, [])
    
    def update_user_role(self, username, new_role):
        """Update user role"""
        result = self.db.users.update_one(
            {'username': username},
            {'$set': {
                'role': new_role,
                'permissions': self.get_default_permissions(new_role)
            }}
        )
        if result.modified_count > 0:
            st.success(f"Updated {username} role to {new_role}")
        else:
            st.error("Failed to update user role")
    
    def toggle_user_status(self, username, status):
        """Activate/deactivate user"""
        result = self.db.users.update_one(
            {'username': username},
            {'$set': {'is_active': status}}
        )
        if result.modified_count > 0:
            action = "activated" if status else "deactivated"
            st.success(f"User {username} {action} successfully")
        else:
            st.error("Failed to update user status")
    
    def show_system_overview(self):
        """Display system overview"""
        st.title("🔧 System Overview")
        # Implementation for system overview
        st.info("System overview functionality to be implemented")
    
    def show_reports(self):
        """Display reporting interface"""
        st.title("📊 Reports")
        # Implementation for reports
        st.info("Reporting functionality to be implemented")
    
    def show_settings(self):
        """Display system settings"""
        st.title("⚙️ Settings")
        # Implementation for settings
        st.info("Settings functionality to be implemented")