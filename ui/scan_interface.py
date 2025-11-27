# ui/scan_interface.py
import streamlit as st
import pandas as pd
from datetime import datetime
import time

class ScanInterface:
    def __init__(self, db, user_info):
        self.db = db.db
        self.user_info = user_info
    
    def show_scan_interface(self):
        """Display scanning interface"""
        st.title("🖥️ System Scanning")
        
        # Scan configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Scan Configuration")
            
            scan_type = st.selectbox(
                "Scan Type",
                ["Comprehensive", "Quick", "Targeted", "Custom"],
                help="Comprehensive: All modules | Quick: Critical only | Targeted: Selected modules"
            )
            
            target_system = st.text_input(
                "Target System", 
                "localhost",
                help="Hostname or IP address of the system to scan"
            )
            
            scan_depth = st.select_slider(
                "Scan Depth",
                options=["Light", "Standard", "Deep", "Intrusive"],
                value="Standard",
                help="Light: Basic checks | Standard: Recommended | Deep: Thorough | Intrusive: May impact performance"
            )
        
        with col2:
            st.subheader("Scan Modules")
            
            # Default selections based on scan type
            if scan_type == "Comprehensive":
                default_modules = True
            elif scan_type == "Quick":
                default_modules = ["Token Manipulation", "Service Vulnerabilities", "Password Dumping"]
            elif scan_type == "Targeted":
                default_modules = []
            else:  # Custom
                default_modules = True
            
            modules = {
                "Token Manipulation": st.checkbox(
                    "Token Manipulation", 
                    value=default_modules if isinstance(default_modules, bool) else "Token Manipulation" in default_modules,
                    help="Detect token privilege manipulation vulnerabilities"
                ),
                "Service Vulnerabilities": st.checkbox(
                    "Service Vulnerabilities", 
                    value=default_modules if isinstance(default_modules, bool) else "Service Vulnerabilities" in default_modules,
                    help="Find service permission and configuration issues"
                ),
                "Registry Analysis": st.checkbox(
                    "Registry Analysis", 
                    value=default_modules if isinstance(default_modules, bool) else "Registry Analysis" in default_modules,
                    help="Check registry for misconfigurations and weak permissions"
                ),
                "DLL Hijacking": st.checkbox(
                    "DLL Hijacking", 
                    value=default_modules if isinstance(default_modules, bool) else "DLL Hijacking" in default_modules,
                    help="Identify DLL search order hijacking opportunities"
                ),
                "Scheduled Tasks": st.checkbox(
                    "Scheduled Tasks", 
                    value=default_modules if isinstance(default_modules, bool) else "Scheduled Tasks" in default_modules,
                    help="Find vulnerable scheduled tasks and permissions"
                ),
                "UAC Bypass": st.checkbox(
                    "UAC Bypass", 
                    value=default_modules if isinstance(default_modules, bool) else "UAC Bypass" in default_modules,
                    help="Check UAC configuration and bypass possibilities"
                ),
                "Kernel Exploits": st.checkbox(
                    "Kernel Exploits", 
                    value=default_modules if isinstance(default_modules, bool) else "Kernel Exploits" in default_modules,
                    help="Identify potential kernel-level vulnerabilities"
                ),
                "Password Dumping": st.checkbox(
                    "Password Dumping", 
                    value=default_modules if isinstance(default_modules, bool) else "Password Dumping" in default_modules,
                    help="Detect password storage and dumping vulnerabilities"
                )
            }
        
        # Advanced options
        with st.expander("🔧 Advanced Options"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                enable_ai = st.checkbox("Enable AI Analysis", True,
                    help="Use AI to enhance detection and risk assessment")
                max_threads = st.slider("Max Threads", 1, 10, 3,
                    help="Number of parallel scanning threads")
            
            with col2:
                simulate_attacks = st.checkbox("Simulate Attacks", False,
                    help="Run attack simulations to validate findings")
                save_evidence = st.checkbox("Save Evidence", True,
                    help="Store detailed evidence for each finding")
            
            with col3:
                auto_mitigate = st.checkbox("Auto-Mitigate Low Risk", False,
                    help="Automatically apply mitigations for low-risk findings")
                notify_on_complete = st.checkbox("Notify on Completion", True,
                    help="Send notification when scan completes")
        
        # Start scan button
        if st.button("🚀 Start Comprehensive Scan", type="primary", use_container_width=True):
            self.start_scan({
                'scan_type': scan_type,
                'target_system': target_system,
                'scan_depth': scan_depth,
                'modules': [k for k, v in modules.items() if v],
                'advanced_options': {
                    'enable_ai': enable_ai,
                    'max_threads': max_threads,
                    'simulate_attacks': simulate_attacks,
                    'save_evidence': save_evidence,
                    'auto_mitigate': auto_mitigate,
                    'notify_on_complete': notify_on_complete
                }
            })
    
    def start_scan(self, scan_config):
        """Start a new scan"""
        # Create scan record
        scan_id = self.db.scans.insert_one({
            'initiated_by': self.user_info['user_id'],
            'target_system': scan_config['target_system'],
            'scan_type': scan_config['scan_type'],
            'status': 'running',
            'start_time': datetime.now(),
            'scan_config': scan_config,
            'findings_count': 0,
            'risk_score': 0
        }).inserted_id
        
        # Show progress
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simulate scan progress (in real implementation, this would run actual scanners)
        for i in range(100):
            progress_bar.progress(i + 1)
            status_text.text(f"Scanning... {i + 1}% complete")
            time.sleep(0.05)  # Simulate work
        
        # Simulate findings
        simulated_findings = self.simulate_findings(scan_config)
        
        # Update scan record
        self.db.scans.update_one(
            {'_id': scan_id},
            {'$set': {
                'status': 'completed',
                'end_time': datetime.now(),
                'findings_count': len(simulated_findings),
                'risk_score': self.calculate_risk_score(simulated_findings)
            }}
        )
        
        # Store findings
        for finding in simulated_findings:
            finding['scan_id'] = scan_id
            finding['created_at'] = datetime.now()
            finding['status'] = 'open'
            finding['assigned_to'] = self.user_info['user_id']
            self.db.findings.insert_one(finding)
        
        status_text.text("✅ Scan completed!")
        st.success(f"Scan completed! Found {len(simulated_findings)} potential privilege escalation vectors.")
        
        # Show results
        self.show_scan_results(simulated_findings, scan_id)
    
    def simulate_findings(self, scan_config):
        """Simulate scan findings for demonstration"""
        findings = []
        
        # Simulate findings based on selected modules
        if "Token Manipulation" in scan_config['modules']:
            findings.append({
                'title': 'Debug Privileges Enabled',
                'description': 'Current user has SeDebugPrivilege which can be abused for token manipulation',
                'risk_level': 'high',
                'category': 'token_manipulation',
                'evidence': 'Privilege check shows SeDebugPrivilege is enabled for current user',
                'mitigation': 'Remove unnecessary privileges through Group Policy',
                'cvss_score': 7.8
            })
        
        if "Service Vulnerabilities" in scan_config['modules']:
            findings.append({
                'title': 'Weak Service Permissions',
                'description': 'Service configured with permissions accessible to non-admin users',
                'risk_level': 'critical',
                'category': 'service_vulnerability',
                'evidence': 'Service permissions allow modification by Users group',
                'mitigation': 'Harden service permissions and implement least privilege',
                'cvss_score': 8.5
            })
        
        if "Registry Analysis" in scan_config['modules']:
            findings.append({
                'title': 'Registry Key Weak Permissions',
                'description': 'Registry key has weak permissions allowing write access',
                'risk_level': 'medium',
                'category': 'registry',
                'evidence': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run permissions are too permissive',
                'mitigation': 'Restrict registry key permissions',
                'cvss_score': 7.2
            })
        
        if "DLL Hijacking" in scan_config['modules']:
            findings.append({
                'title': 'Writable System Directory',
                'description': 'System directory is writable, enabling DLL hijacking attacks',
                'risk_level': 'critical',
                'category': 'dll_hijacking',
                'evidence': 'C:\\Windows\\Temp directory is writable by current user',
                'mitigation': 'Restrict directory permissions',
                'cvss_score': 8.8
            })
        
        return findings
    
    def calculate_risk_score(self, findings):
        """Calculate overall risk score from findings"""
        risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_score = 0
        
        for finding in findings:
            total_score += risk_weights.get(finding.get('risk_level', 'low'), 1)
        
        return min(total_score / len(findings) if findings else 0, 10)
    
    def show_scan_results(self, findings, scan_id):
        """Display scan results"""
        st.subheader("📊 Scan Results Summary")
        
        # Risk distribution
        risk_counts = {}
        for finding in findings:
            risk = finding.get('risk_level', 'low')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Critical", risk_counts.get('critical', 0))
        with col2:
            st.metric("High", risk_counts.get('high', 0))
        with col3:
            st.metric("Medium", risk_counts.get('medium', 0))
        with col4:
            st.metric("Low", risk_counts.get('low', 0))
        
        # Top findings
        st.subheader("🔍 Top Security Findings")
        for i, finding in enumerate(findings[:5]):
            with st.expander(f"{i+1}. {finding['title']} - {finding['risk_level'].upper()}"):
                st.write(f"**Description:** {finding['description']}")
                st.write(f"**Evidence:** {finding.get('evidence', 'No evidence collected')}")
                st.write(f"**Mitigation:** {finding.get('mitigation', 'No mitigation provided')}")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Apply Mitigation", key=f"apply_{i}"):
                        st.info("Mitigation feature would be implemented here")
                with col2:
                    if st.button("Mark False Positive", key=f"false_{i}"):
                        st.info("False positive marking would be implemented here")
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📋 View All Findings", use_container_width=True):
                st.session_state.current_page = "Findings"
                st.rerun()
        
        with col2:
            if st.button("📄 Generate Report", use_container_width=True):
                st.session_state.current_page = "Reports"
                st.rerun()
        
        with col3:
            if st.button("🔄 New Scan", use_container_width=True):
                st.rerun()