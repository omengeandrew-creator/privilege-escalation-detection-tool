# ui/user_dashboard.py
import streamlit as st
import pandas as pd
from datetime import datetime

class UserDashboard:
    def __init__(self, db, user_info):
        self.db = db.db
        self.user_info = user_info
    
    def show_dashboard(self):
        """Display user dashboard"""
        st.title("👤 My Security Dashboard")
        
        st.info(f"Welcome back, {self.user_info['profile'].get('full_name', 'User')}!")
        
        # User's recent scan results
        st.subheader("My Recent Scan Results")
        
        # Get scans that include this user's systems
        user_scans = list(self.db.scans.find({
            'scan_config.target_users': self.user_info['user_id']
        }).sort('start_time', -1).limit(5))
        
        if user_scans:
            for scan in user_scans:
                with st.expander(f"Scan on {scan['target_system']} - {scan['start_time'].strftime('%Y-%m-%d')}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Findings", scan.get('findings_count', 0))
                    with col2:
                        st.metric("Risk Score", f"{scan.get('risk_score', 0)}/10")
                    with col3:
                        status = scan.get('status', 'unknown')
                        if status == 'completed':
                            st.success("Completed")
                        elif status == 'running':
                            st.warning("Running")
                        else:
                            st.info(status.title())
                    
                    # Show relevant findings for this user
                    user_findings = list(self.db.findings.find({
                        'scan_id': scan['_id'],
                        'affected_users': self.user_info['user_id']
                    }).limit(3))
                    
                    if user_findings:
                        st.write("**Relevant Findings:**")
                        for finding in user_findings:
                            risk_color = {
                                'critical': 'red', 'high': 'orange', 
                                'medium': 'yellow', 'low': 'green'
                            }
                            risk_level = finding.get('risk_level', 'low')
                            st.markdown(
                                f"- <span style='color: {risk_color[risk_level]};'>{risk_level.upper()}</span>: "
                                f"{finding['title']}",
                                unsafe_allow_html=True
                            )
                    else:
                        st.success("No findings affecting your account")
        else:
            st.info("No scan results available for your account yet.")
        
        # Security tips
        st.subheader("🔒 Security Best Practices")
        tips = [
            "Use strong, unique passwords for all accounts",
            "Enable multi-factor authentication where available",
            "Keep your system and applications updated",
            "Be cautious of suspicious emails and links",
            "Report any unusual system behavior to security team"
        ]
        
        for tip in tips:
            st.write(f"• {tip}")
    
    def show_scan_results(self):
        """Display user's scan results"""
        st.title("📊 My Scan Results")
        
        # Filter options
        col1, col2 = st.columns(2)
        
        with col1:
            time_filter = st.selectbox(
                "Time Period",
                ["Last 30 days", "Last 90 days", "Last year", "All time"]
            )
        
        with col2:
            risk_filter = st.multiselect(
                "Risk Level",
                ["critical", "high", "medium", "low"],
                default=["critical", "high"]
            )
        
        # Get user's findings
        query = {'affected_users': self.user_info['user_id']}
        if risk_filter:
            query['risk_level'] = {'$in': risk_filter}
        
        user_findings = list(self.db.findings.find(query).sort('created_at', -1))
        
        if user_findings:
            st.subheader(f"Found {len(user_findings)} Findings Affecting Your Account")
            
            # Summary statistics
            critical_count = len([f for f in user_findings if f['risk_level'] == 'critical'])
            high_count = len([f for f in user_findings if f['risk_level'] == 'high'])
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Findings", len(user_findings))
            with col2:
                st.metric("Critical", critical_count, delta=f"{critical_count} urgent")
            with col3:
                st.metric("High", high_count)
            
            # Detailed findings
            for finding in user_findings:
                self.display_user_finding(finding)
        else:
            st.success("🎉 No security findings affecting your account!")
    
    def display_user_finding(self, finding):
        """Display finding for user view"""
        risk_color = {
            'critical': '#ff4444', 'high': '#ff6b6b',
            'medium': '#ffa726', 'low': '#66bb6a'
        }
        
        with st.container():
            st.markdown(f"""
            <div style='border-left: 5px solid {risk_color[finding['risk_level']]}; 
                        padding: 10px; margin: 10px 0; background-color: #f8f9fa;'>
                <h4 style='margin: 0;'>{finding['title']}</h4>
                <p style='margin: 5px 0; color: #666;'>{finding['description']}</p>
                <div style='display: flex; justify-content: space-between;'>
                    <span><strong>Risk:</strong> {finding['risk_level'].upper()}</span>
                    <span><strong>Found:</strong> {finding['created_at'].strftime('%Y-%m-%d')}</span>
                    <span><strong>Status:</strong> {finding.get('status', 'open')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Show mitigation status
            if finding.get('status') == 'resolved':
                st.success("✅ This issue has been resolved by the security team.")
            else:
                st.info("🛡️ The security team is working on mitigating this issue.")
    
    def show_profile(self):
        """Display and edit user profile"""
        st.title("👤 My Profile")
        
        # Get current user data
        user_data = self.db.users.find_one({'username': self.user_info['username']})
        profile = user_data.get('profile', {})
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Personal Information")
            
            with st.form("profile_form"):
                full_name = st.text_input("Full Name", value=profile.get('full_name', ''))
                email = st.text_input("Email", value=user_data.get('email', ''))
                phone = st.text_input("Phone Number", value=profile.get('phone', ''))
                department = st.text_input("Department", value=profile.get('department', ''))
                
                # Password change
                st.subheader("Change Password")
                current_password = st.text_input("Current Password", type="password")
                new_password = st.text_input("New Password", type="password")
                confirm_password = st.text_input("Confirm New Password", type="password")
                
                if st.form_submit_button("💾 Update Profile"):
                    self.update_profile(
                        full_name, email, phone, department,
                        current_password, new_password, confirm_password
                    )
        
        with col2:
            st.subheader("Account Information")
            
            st.write(f"**Username:** {user_data['username']}")
            st.write(f"**Role:** {user_data['role'].title()}")
            st.write(f"**Account Created:** {user_data['created_at'].strftime('%Y-%m-%d')}")
            st.write(f"**Last Login:** {user_data.get('last_login', 'Never')}")
            
            st.subheader("Security Settings")
            enable_2fa = st.checkbox("Enable Two-Factor Authentication", value=False)
            email_alerts = st.checkbox("Email Security Alerts", value=True)
            
            if st.button("Save Security Settings"):
                self.update_security_settings(enable_2fa, email_alerts)
                st.success("Security settings updated!")
    
    def update_profile(self, full_name, email, phone, department, current_pwd, new_pwd, confirm_pwd):
        """Update user profile information"""
        import bcrypt
        
        update_data = {
            'profile.full_name': full_name,
            'email': email,
            'profile.phone': phone,
            'profile.department': department
        }
        
        # Handle password change if requested
        if current_pwd and new_pwd:
            if new_pwd != confirm_pwd:
                st.error("New passwords do not match!")
                return
            
            # Verify current password
            user_data = self.db.users.find_one({'username': self.user_info['username']})
            if not bcrypt.checkpw(current_pwd.encode(), user_data['password_hash'].encode()):
                st.error("Current password is incorrect!")
                return
            
            # Update password
            update_data['password_hash'] = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
            st.success("Password updated successfully!")
        
        # Update profile in database
        result = self.db.users.update_one(
            {'username': self.user_info['username']},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            st.success("Profile updated successfully!")
            # Update session state
            st.session_state['user_info']['profile'].update({
                'full_name': full_name,
                'phone': phone,
                'department': department
            })
        else:
            st.info("No changes detected or update failed.")
    
    def update_security_settings(self, enable_2fa, email_alerts):
        """Update user security settings"""
        # Implementation for security settings
        # This would typically update database with user preferences
        pass