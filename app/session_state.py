# app/session_state.py
import streamlit as st
from datetime import datetime, timedelta

class SessionManager:
    def __init__(self):
        self.initialize_session_state()
    
    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'user_info' not in st.session_state:
            st.session_state.user_info = {}
        if 'last_activity' not in st.session_state:
            st.session_state.last_activity = datetime.now()
        if 'current_page' not in st.session_state:
            st.session_state.current_page = 'login'
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = None
        if 'selected_finding' not in st.session_state:
            st.session_state.selected_finding = None
        if 'mitigating_finding' not in st.session_state:
            st.session_state.mitigating_finding = None
    
    def update_activity(self):
        """Update last activity timestamp"""
        st.session_state.last_activity = datetime.now()
    
    def check_session_timeout(self):
        """Check if session has timed out"""
        if not st.session_state.authenticated:
            return False
        
        timeout_minutes = 60  # 1 hour timeout
        last_activity = st.session_state.last_activity
        time_since_activity = datetime.now() - last_activity
        
        if time_since_activity > timedelta(minutes=timeout_minutes):
            self.clear_session()
            return True
        
        return False
    
    def clear_session(self):
        """Clear session state"""
        st.session_state.authenticated = False
        st.session_state.user_info = {}
        st.session_state.last_activity = datetime.now()
        st.session_state.current_page = 'login'
        st.session_state.scan_results = None
        st.session_state.selected_finding = None
        st.session_state.mitigating_finding = None
    
    def set_user_session(self, user_info):
        """Set user session after login"""
        st.session_state.authenticated = True
        st.session_state.user_info = user_info
        st.session_state.last_activity = datetime.now()
        st.session_state.current_page = 'dashboard'
    
    def get_user_role(self):
        """Get current user role"""
        return st.session_state.user_info.get('role', 'user')
    
    def has_permission(self, permission):
        """Check if user has specific permission"""
        user_permissions = st.session_state.user_info.get('permissions', [])
        return 'all' in user_permissions or permission in user_permissions