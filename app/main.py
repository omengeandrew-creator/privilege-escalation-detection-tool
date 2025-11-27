# app/main.py - ENHANCED INTEGRATION
import streamlit as st
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.auth import AuthenticationSystem
from app.database import MongoDBManager
from app.session_state import SessionManager  # NEW: Session management
from ui.admin_dashboard import AdminDashboard
from ui.analyst_dashboard import SecurityAnalystDashboard
from ui.user_dashboard import UserDashboard
from ui.realtime_dashboard import RealTimeDashboard  # NEW: Real-time monitoring
from utils.logger import SecurityLogger
from utils.config_loader import ConfigLoader  # NEW: Configuration management
from core.realtime_monitor import RealTimeMonitor  # NEW: Real-time engine

class PrivilegedRapperApp:
    def __init__(self):
        self.config = ConfigLoader()  # NEW: Enhanced config
        self.db = MongoDBManager()
        self.auth = AuthenticationSystem(self.db)
        self.session = SessionManager()  # NEW: Session management
        self.logger = SecurityLogger()
        self.monitor = RealTimeMonitor(self.db)  # NEW: Real-time monitoring
        
        # NEW: Enhanced session state initialization
        self.initialize_session_state()
        self.setup_custom_css()
        
    def initialize_session_state(self):
        """Enhanced session state initialization"""
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'user_info' not in st.session_state:
            st.session_state.user_info = {}
        if 'current_page' not in st.session_state:
            st.session_state.current_page = 'Dashboard'
        if 'scan_results' not in st.session_state:
            st.session_state.scan_results = None
            
    def setup_custom_css(self):
        """Enhanced CSS with professional styling"""
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            color: #1f77b4;
            text-align: center;
            margin-bottom: 2rem;
            font-weight: bold;
        }
        .privileged-footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            background-color: #1f77b4;
            color: white;
            text-align: center;
            padding: 10px;
            font-size: 0.8rem;
            z-index: 999;
        }
        .risk-critical { 
            background-color: #ff4444; 
            color: white; 
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        .risk-high { 
            background-color: #ff6b6b; 
            color: white; 
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        .risk-medium { 
            background-color: #ffa726; 
            color: white; 
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        .risk-low { 
            background-color: #66bb6a; 
            color: white; 
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        /* NEW: Enhanced styling */
        .security-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #1f77b4;
        }
        
        .metric-card {
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            background: white;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .stButton>button {
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .stButton>button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        </style>
        """, unsafe_allow_html=True)
    
    def show_login_page(self):
        """Enhanced login page with better UX"""
        st.markdown("<h1 class='main-header'>🛡️ Privileged Rapper Inc.</h1>", unsafe_allow_html=True)
        st.markdown("### Enterprise Privilege Escalation Detection Platform")
        
        col1, col2, col3 = st.columns([1,2,1])
        
        with col2:
            with st.form("login_form"):
                username = st.text_input("👤 Username", placeholder="Enter your username")
                password = st.text_input("🔒 Password", type="password", placeholder="Enter your password")
                login_btn = st.form_submit_button("🚀 Login")
                
                if login_btn:
                    if username and password:
                        if self.auth.authenticate_user(username, password):
                            user_info = self.auth.get_user_info(username)
                            st.session_state.authenticated = True
                            st.session_state.user_info = user_info
                            self.session.set_user_session(user_info)  # NEW: Enhanced session
                            self.logger.log_login(username, success=True)
                            st.rerun()
                        else:
                            self.logger.log_login(username, success=False)
                            st.error("❌ Invalid credentials")
                    else:
                        st.warning("⚠️ Please enter both username and password")
        
        # NEW: Feature highlights
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            ### 🔍 Advanced Detection
            - Windows privilege escalation
            - AI-powered analysis
            - Real-time monitoring
            """)
        
        with col2:
            st.markdown("""
            ### 🛡️ Enterprise Security  
            - Role-based access control
            - Comprehensive auditing
            - Professional reporting
            """)
        
        with col3:
            st.markdown("""
            ### 📊 Professional Reports
            - PDF & CSV exports
            - Executive summaries  
            - Technical documentation
            """)
    
    def show_main_app(self):
        """Enhanced main application with session management"""
        # NEW: Session timeout check
        if self.session.check_session_timeout():
            st.warning("Session timed out. Please login again.")
            st.rerun()
            
        user_info = st.session_state.get('user_info', {})
        role = user_info.get('role', 'user')
        
        # Enhanced sidebar
        with st.sidebar:
            st.image("assets/images/logo.png", width=100)
            st.markdown(f"### Welcome, {user_info.get('username', 'User')}")
            st.markdown(f"**Role:** {role.title()}")
            st.markdown(f"**Department:** {user_info.get('profile', {}).get('department', 'N/A')}")
            st.markdown("---")
            
            # Enhanced navigation with real-time monitoring
            if role == "admin":
                menu_options = ["Dashboard", "User Management", "System Overview", "Reports", "Settings", "Analytics"]
            elif role == "security_analyst":
                menu_options = ["Dashboard", "Scan Systems", "Findings", "AI Analysis", "Reports", "Real-time Monitor"]  # NEW: Added Real-time Monitor
            else:  # user
                menu_options = ["My Dashboard", "Scan Results", "Profile"]
            
            menu = st.selectbox("Navigation", menu_options)
            st.session_state.current_page = menu
            
            st.markdown("---")
            
            # NEW: Quick actions
            if role in ["admin", "security_analyst"]:
                st.markdown("### Quick Actions")
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("📊 Report", use_container_width=True):
                        st.session_state.current_page = "Reports"
                        st.rerun()
                
                with col2:
                    if role == "security_analyst" and st.button("🖥️ Monitor", use_container_width=True):
                        st.session_state.current_page = "Real-time Monitor"
                        st.rerun()
            
            st.markdown("---")
            
            # Enhanced logout with session info
            st.markdown(f"**Session:** {datetime.now().strftime('%H:%M:%S')}")
            if st.button("🚪 Logout", use_container_width=True):
                self.session.clear_session()
                st.rerun()
        
        # Main content area - UPDATED to use session state
        current_page = st.session_state.current_page
        
        if role == "admin":
            self.show_admin_interface(current_page, user_info)
        elif role == "security_analyst":
            self.show_analyst_interface(current_page, user_info)
        else:
            self.show_user_interface(current_page, user_info)
    
    def show_admin_interface(self, menu, user_info):
        """Enhanced admin interface"""
        admin_ui = AdminDashboard(self.db, user_info)
        
        if menu == "Dashboard":
            admin_ui.show_dashboard()
        elif menu == "User Management":
            admin_ui.show_user_management()
        elif menu == "System Overview":
            admin_ui.show_system_overview()
        elif menu == "Reports":
            admin_ui.show_reports()
        elif menu == "Settings":
            admin_ui.show_settings()
        elif menu == "Analytics":  # NEW: Analytics page
            admin_ui.show_analytics()
    
    def show_analyst_interface(self, menu, user_info):
        """Enhanced analyst interface with real-time monitoring"""
        analyst_ui = SecurityAnalystDashboard(self.db, user_info)
        
        if menu == "Dashboard":
            analyst_ui.show_dashboard()
        elif menu == "Scan Systems":
            analyst_ui.show_scan_interface()
        elif menu == "Findings":
            analyst_ui.show_findings_management()
        elif menu == "AI Analysis":
            analyst_ui.show_ai_analysis()
        elif menu == "Reports":
            analyst_ui.show_reports()
        elif menu == "Real-time Monitor":  # FIXED: Use the built-in realtime monitor from SecurityAnalystDashboard
            analyst_ui.show_realtime_monitor()
    
    def show_user_interface(self, menu, user_info):
        """User interface remains the same"""
        user_ui = UserDashboard(self.db, user_info)
        
        if menu == "My Dashboard":
            user_ui.show_dashboard()
        elif menu == "Scan Results":
            user_ui.show_scan_results()
        else:
            user_ui.show_profile()
    
    def run(self):
        """Enhanced main application runner with error handling"""
        try:
            if not st.session_state.get('authenticated', False):
                self.show_login_page()
            else:
                self.show_main_app()
            
            
            
        except Exception as e:
            st.error(f"Application error: {str(e)}")
            self.logger.log_error(str(e), "MainApplication")

if __name__ == "__main__":
    app = PrivilegedRapperApp()
    app.run()