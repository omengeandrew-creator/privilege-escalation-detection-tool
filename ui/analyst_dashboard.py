# ui/analyst_dashboard.py
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.scanner import WindowsPrivilegeScanner
from core.ai_engine import AIAnalysisEngine
from reporting.pdf_generator import PDFReportGenerator
from reporting.csv_generator import CSVReportGenerator
from ui.findings_manager import FindingsManager

class SecurityAnalystDashboard:
    def __init__(self, db, user_info):
        self.db = db.db
        self.user_info = user_info
        self.scanner = WindowsPrivilegeScanner(self.db)
        self.ai_engine = AIAnalysisEngine(self.db)
        self.findings_manager = FindingsManager(db, user_info)
    
    def show_dashboard(self):
        """Display security analyst dashboard"""
        st.title("🔍 Security Operations Dashboard")
        
        # Quick stats
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_findings = self.db.findings.count_documents({})
            st.metric("Total Findings", total_findings)
        
        with col2:
            critical_count = self.db.findings.count_documents({'risk_level': 'critical'})
            st.metric("Critical Findings", critical_count, delta=f"{critical_count} urgent")
        
        with col3:
            open_findings = self.db.findings.count_documents({'status': 'open'})
            st.metric("Open Findings", open_findings)
        
        with col4:
            systems_count = self.db.systems.count_documents({})
            st.metric("Managed Systems", systems_count)
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            self.show_findings_trend_chart()
        
        with col2:
            self.show_risk_heatmap()
        
        # Recent critical findings
        st.subheader("🚨 Recent Critical Findings")
        self.show_critical_findings()
    
    def show_findings_trend_chart(self):
        """Display findings trend over time"""
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$created_at"},
                        "month": {"$month": "$created_at"},
                        "day": {"$dayOfMonth": "$created_at"}
                    },
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"_id": 1}},
            {"$limit": 30}
        ]
        
        trend_data = list(self.db.findings.aggregate(pipeline))
        
        if trend_data:
            dates = []
            counts = []
            for item in trend_data:
                date_str = f"{item['_id']['month']}/{item['_id']['day']}/{item['_id']['year']}"
                dates.append(date_str)
                counts.append(item['count'])
            
            fig = px.line(x=dates, y=counts, title="Findings Trend (Last 30 Days)")
            fig.update_layout(xaxis_title="Date", yaxis_title="Number of Findings")
            st.plotly_chart(fig, use_container_width=True)
    
    def show_risk_heatmap(self):
        """Display risk heatmap by category"""
        pipeline = [
            {
                "$group": {
                    "_id": {"category": "$category", "risk": "$risk_level"},
                    "count": {"$sum": 1}
                }
            }
        ]
        
        heatmap_data = list(self.db.findings.aggregate(pipeline))
        
        if heatmap_data:
            categories = []
            risks = []
            counts = []
            
            for item in heatmap_data:
                categories.append(item['_id']['category'])
                risks.append(item['_id']['risk'])
                counts.append(item['count'])
            
            df = pd.DataFrame({
                'Category': categories,
                'Risk Level': risks,
                'Count': counts
            })
            
            fig = px.density_heatmap(df, x='Category', y='Risk Level', z='Count',
                                   title="Risk Distribution Heatmap")
            st.plotly_chart(fig, use_container_width=True)
    
    def show_critical_findings(self):
        """Display recent critical findings"""
        critical_findings = list(self.db.findings.find(
            {'risk_level': 'critical'}).sort('created_at', -1).limit(10))
        
        if critical_findings:
            for finding in critical_findings:
                with st.container():
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.write(f"**{finding['title']}**")
                        st.write(f"_{finding['description'][:100]}..._")
                    
                    with col2:
                        st.error(f"CVSS: {finding.get('cvss_score', 'N/A')}")
                    
                    with col3:
                        if st.button("Mitigate", key=f"mit_{finding['_id']}"):
                            self.show_mitigation_dialog(finding)
            
            if st.button("View All Critical Findings"):
                st.session_state['menu'] = "Findings"
                st.rerun()
        else:
            st.success("🎉 No critical findings detected!")
    
    def show_scan_interface(self):
        """Display scanning interface"""
        st.title("🖥️ System Scanning ")
        
        # Scan configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Scan Configuration")
            
            scan_type = st.selectbox(
                "Scan Type",
                ["Comprehensive", "Quick", "Targeted", "Custom"]
            )
            
            target_system = st.text_input("Target System", "localhost")
            
            scan_depth = st.select_slider(
                "Scan Depth",
                options=["Light", "Standard", "Deep", "Intrusive"],
                value="Standard"
            )
        
        with col2:
            st.subheader("Scan Modules")
            
            modules = {
                "Token Manipulation": st.checkbox("Token Manipulation", True),
                "Service Vulnerabilities": st.checkbox("Service Vulnerabilities", True),
                "Registry Analysis": st.checkbox("Registry Analysis", True),
                "DLL Hijacking": st.checkbox("DLL Hijacking", True),
                "Scheduled Tasks": st.checkbox("Scheduled Tasks", True),
                "UAC Bypass": st.checkbox("UAC Bypass", True),
                "Kernel Exploits": st.checkbox("Kernel Exploits", True),
                "Password Dumping": st.checkbox("Password Dumping", True)
            }
        
        # AI Analysis options
        st.subheader("AI Analysis Options")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            enable_ai = st.checkbox("Enable AI Analysis", True)
        with col2:
            simulate_attacks = st.checkbox("Simulate Attacks", False)
        with col3:
            auto_mitigate = st.checkbox("Auto-Mitigate Low Risk", False)
        
        # Start scan
        if st.button("🚀 Start Comprehensive Scan", type="primary"):
            with st.spinner("Initializing privilege escalation scan..."):
                scan_config = {
                    'scan_type': scan_type,
                    'target_system': target_system,
                    'scan_depth': scan_depth,
                    'modules': [k for k, v in modules.items() if v],
                    'ai_analysis': enable_ai,
                    'simulate_attacks': simulate_attacks,
                    'auto_mitigate': auto_mitigate
                }
                
                # Create scan record
                scan_id = self.db.scans.insert_one({
                    'initiated_by': self.user_info['user_id'],
                    'target_system': target_system,
                    'scan_type': scan_type,
                    'status': 'running',
                    'start_time': datetime.now(),
                    'scan_config': scan_config,
                    'findings_count': 0,
                    'risk_score': 0
                }).inserted_id
                
                # Run scan
                findings = self.scanner.run_comprehensive_scan(scan_config)
                
                # Update scan record
                self.db.scans.update_one(
                    {'_id': scan_id},
                    {'$set': {
                        'status': 'completed',
                        'end_time': datetime.now(),
                        'findings_count': len(findings),
                        'risk_score': self.calculate_risk_score(findings)
                    }}
                )
                
                # Store findings
                for finding in findings:
                    finding['scan_id'] = scan_id
                    finding['created_at'] = datetime.now()
                    finding['status'] = 'open'
                    finding['assigned_to'] = self.user_info['user_id']
                    self.db.findings.insert_one(finding)
                
                st.success(f"✅ Scan completed! Found {len(findings)} potential privilege escalation vectors.")
                
                # Show quick results
                if findings:
                    self.display_scan_summary(findings)
    
    def calculate_risk_score(self, findings):
        """Calculate overall risk score from findings"""
        risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_score = 0
        
        for finding in findings:
            total_score += risk_weights.get(finding.get('risk_level', 'low'), 1)
        
        return min(total_score / len(findings) if findings else 0, 10)
    
    def display_scan_summary(self, findings):
        """Display scan results summary"""
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
                        self.apply_mitigation(finding)
                with col2:
                    if st.button("Mark False Positive", key=f"false_{i}"):
                        self.mark_false_positive(finding)
    
    def show_findings_management(self):
        """Display findings management interface"""
        self.findings_manager.show_findings_management()
    
    def show_mitigation_dialog(self, finding):
        """Show mitigation options for a finding"""
        self.findings_manager.show_mitigation_dialog(finding)
    
    def apply_mitigation(self, finding):
        """Apply mitigation to a finding"""
        self.db.findings.update_one(
            {'_id': finding['_id']},
            {'$set': {
                'status': 'resolved',
                'resolved_at': datetime.now(),
                'resolved_by': self.user_info['user_id']
            }}
        )
        st.success(f"✅ Mitigation applied to: {finding['title']}")
        st.rerun()
    
    def mark_false_positive(self, finding):
        """Mark finding as false positive"""
        self.db.findings.update_one(
            {'_id': finding['_id']},
            {'$set': {
                'status': 'false_positive',
                'updated_at': datetime.now(),
                'updated_by': self.user_info['user_id']
            }}
        )
        st.success(f"✅ Marked as false positive: {finding['title']}")
        st.rerun()
    
    def display_finding_card(self, finding):
        """Display individual finding card"""
        self.findings_manager.display_finding_card(finding)
    
    def show_ai_analysis(self):
        """Display AI analysis interface"""
        st.title("🤖 AI-Powered Analysis")
        
        st.info("""
        **AI Analysis Features:**
        - Predictive risk scoring using machine learning
        - Automated mitigation recommendations
        - Attack pattern recognition
        - Behavioral anomaly detection
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Model Training")
            if st.button("Train Detection Model"):
                with st.spinner("Training AI model on historical data..."):
                    accuracy = self.ai_engine.train_detection_model()
                    st.success(f"Model trained with {accuracy:.2%} accuracy")
            
            if st.button("Generate Attack Simulations"):
                with st.spinner("Generating realistic attack scenarios..."):
                    simulations = self.ai_engine.generate_attack_simulations()
                    st.success(f"Generated {len(simulations)} attack simulations")
        
        with col2:
            st.subheader("AI Analysis")
            if st.button("Analyze Recent Findings"):
                with st.spinner("Running AI analysis on recent findings..."):
                    insights = self.ai_engine.analyze_findings_patterns()
                    st.success("Analysis completed!")
                    
                    for insight in insights[:3]:
                        st.write(f"• {insight}")
            
            if st.button("Predictive Risk Assessment"):
                with st.spinner("Calculating predictive risk scores..."):
                    predictions = self.ai_engine.predict_risk_trends()
                    st.success("Risk assessment completed!")
    
    def show_reports(self):
        """Display reporting interface"""
        st.title("📄 Professional Reporting")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Report Configuration")
            
            report_type = st.selectbox(
                "Report Type",
                ["Executive Summary", "Technical Detailed", "Comprehensive Analysis", "Compliance"]
            )
            
            time_range = st.selectbox(
                "Time Range",
                ["Last 7 days", "Last 30 days", "Last 90 days", "Custom", "All time"]
            )
            
            include_charts = st.checkbox("Include Charts & Graphs", True)
            include_ai_insights = st.checkbox("Include AI Insights", True)
        
        with col2:
            st.subheader("Export Options")
            
            format_choice = st.radio(
                "Export Format",
                ["PDF Report", "CSV Data", "Both"]
            )
            
            st.info("**Professional Features:**")
            st.write("• Privileged Rapper Inc. branding")
            st.write("• Executive summary with risk heat maps")
            st.write("• Detailed technical findings")
            st.write("• Mitigation action plans")
            st.write("• Compliance tracking")
        
        # Generate report
        if st.button("🖨️ Generate Professional Report", type="primary"):
            with st.spinner("Generating professional report with Privileged Rapper Inc. branding..."):
                # Calculate date range
                if time_range == "Last 7 days":
                    start_date = datetime.now() - timedelta(days=7)
                elif time_range == "Last 30 days":
                    start_date = datetime.now() - timedelta(days=30)
                elif time_range == "Last 90 days":
                    start_date = datetime.now() - timedelta(days=90)
                else:
                    start_date = None
                
                report_config = {
                    'report_type': report_type,
                    'start_date': start_date,
                    'include_charts': include_charts,
                    'include_ai_insights': include_ai_insights,
                    'generated_by': self.user_info['username']
                }
                
                # Generate reports based on format choice
                if format_choice in ["PDF Report", "Both"]:
                    pdf_generator = PDFReportGenerator(self.db)
                    pdf_path = pdf_generator.generate_comprehensive_report(report_config)
                    st.success(f"📊 PDF report generated: {pdf_path}")
                
                if format_choice in ["CSV Data", "Both"]:
                    csv_generator = CSVReportGenerator(self.db)
                    csv_path = csv_generator.generate_detailed_export(report_config)
                    st.success(f"📁 CSV data exported: {csv_path}")
                
                st.balloons()
                st.success("🎉 Professional reports generated with Privileged Rapper Inc. branding!")

    def show_realtime_monitor(self):
        """Display real-time security monitoring interface"""
        st.title("📡 Real-Time Security Monitor")
        
        # Check if realtime_monitor is available
        try:
            from core.realtime_monitor import RealTimeMonitor
            realtime_monitor = RealTimeMonitor(self.db)
        except Exception as e:
            st.error(f"❌ Real-time monitor initialization failed: {e}")
            return
        
        # Monitoring controls
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Start Real-Time Monitoring", type="primary"):
                if realtime_monitor.start_monitoring():
                    st.success("✅ Real-time monitoring started")
                else:
                    st.warning("⚠️ Monitoring is already running")
        
        with col2:
            if st.button("⏹️ Stop Monitoring"):
                realtime_monitor.stop_monitoring()
                st.info("🛑 Monitoring stopped")
        
        with col3:
            if st.button("🔄 Refresh Alerts"):
                st.rerun()
        
        st.markdown("---")
        
        # Display recent alerts
        st.subheader("🚨 Recent Security Alerts")
        
        try:
            # Get recent alerts - FIXED: Now using the alerts collection
            recent_alerts = list(self.db.alerts.find().sort('triggered_at', -1).limit(20))
            
            if recent_alerts:
                for alert in recent_alerts:
                    with st.container():
                        col1, col2, col3 = st.columns([3, 1, 1])
                        
                        with col1:
                            st.write(f"**{alert.get('alert_type', 'Unknown Alert')}**")
                            st.write(f"Triggered: {alert.get('triggered_at', 'Unknown time')}")
                            
                            # Show event summary
                            if 'event_summary' in alert:
                                event_types = list(alert['event_summary'].keys())
                                st.write(f"Events: {', '.join(event_types)}")
                        
                        with col2:
                            severity = alert.get('severity', 'unknown')
                            if severity == 'high':
                                st.error("HIGH")
                            elif severity == 'medium':
                                st.warning("MEDIUM")
                            else:
                                st.info(severity.upper())
                        
                        with col3:
                            if not alert.get('acknowledged', False):
                                if st.button("Acknowledge", key=f"ack_{alert['_id']}"):
                                    self.db.alerts.update_one(
                                        {'_id': alert['_id']},
                                        {'$set': {
                                            'acknowledged': True, 
                                            'acknowledged_at': datetime.now(),
                                            'acknowledged_by': self.user_info['user_id']
                                        }}
                                    )
                                    st.rerun()
                            else:
                                st.success("✅ Acknowledged")
                
                st.info(f"Showing {len(recent_alerts)} most recent alerts")
            else:
                st.success("🎉 No security alerts detected in real-time monitoring")
                
        except Exception as e:
            st.error(f"❌ Error loading alerts: {e}")
            st.info("This might be because the alerts collection is not yet initialized. Start monitoring to create alerts.")
        
        # System monitoring stats
        st.markdown("---")
        st.subheader("📊 Monitoring Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_alerts = self.db.alerts.count_documents({})
            st.metric("Total Alerts", total_alerts)
        
        with col2:
            high_severity = self.db.alerts.count_documents({'severity': 'high'})
            st.metric("High Severity", high_severity)
        
        with col3:
            unacknowledged = self.db.alerts.count_documents({'acknowledged': False})
            st.metric("Unacknowledged", unacknowledged)
        
        with col4:
            today_alerts = self.db.alerts.count_documents({
                'triggered_at': {'$gte': datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)}
            })
            st.metric("Today", today_alerts)