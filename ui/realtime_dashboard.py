# ui/realtime_dashboard.py
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

class RealTimeDashboard:
    def __init__(self, db, user_info, monitor):
        self.db = db.db
        self.user_info = user_info
        self.monitor = monitor
    
    def show_dashboard(self):
        """Display real-time monitoring dashboard"""
        st.title("🖥️ Real-time Security Monitor")
        
        # Monitor controls
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("▶️ Start Monitoring", type="primary", use_container_width=True):
                if self.monitor.start_monitoring():
                    st.success("Real-time monitoring started!")
                else:
                    st.warning("Monitoring is already running")
        
        with col2:
            if st.button("⏹️ Stop Monitoring", type="secondary", use_container_width=True):
                self.monitor.stop_monitoring()
                st.info("Real-time monitoring stopped")
        
        with col3:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        
        # Real-time metrics
        st.subheader("📊 Live System Metrics")
        self.show_live_metrics()
        
        # Recent alerts
        st.subheader("🚨 Recent Security Alerts")
        self.show_recent_alerts()
        
        # System activity
        st.subheader("📈 System Activity")
        self.show_system_activity()
    
    def show_live_metrics(self):
        """Display live monitoring metrics"""
        col1, col2, col3, col4 = st.columns(4)
        
        # Get recent activity counts
        recent_alerts = list(self.db.alerts.find({
            'triggered_at': {'$gte': datetime.now() - timedelta(hours=1)}
        }))
        
        with col1:
            st.metric(
                "Active Alerts (1h)", 
                len(recent_alerts),
                delta=f"{len(recent_alerts)} new"
            )
        
        with col2:
            critical_alerts = len([a for a in recent_alerts if a.get('severity') == 'high'])
            st.metric(
                "Critical Alerts",
                critical_alerts,
                delta=f"{critical_alerts} urgent" if critical_alerts > 0 else None,
                delta_color="inverse" if critical_alerts > 0 else "normal"
            )
        
        with col3:
            # Simulate system load
            import psutil
            cpu_percent = psutil.cpu_percent()
            st.metric(
                "System Load",
                f"{cpu_percent}%",
                delta=f"{cpu_percent}% utilization"
            )
        
        with col4:
            # Monitor status
            status = "Active" if self.monitor.monitoring else "Stopped"
            status_color = "normal" if self.monitor.monitoring else "off"
            st.metric(
                "Monitor Status",
                status,
                delta="Running" if self.monitor.monitoring else "Stopped",
                delta_color=status_color
            )
    
    def show_recent_alerts(self):
        """Display recent security alerts"""
        alerts = self.monitor.get_recent_alerts(limit=10)
        
        if alerts:
            for alert in alerts:
                with st.container():
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.write(f"**{alert['alert_type'].replace('_', ' ').title()}**")
                        st.write(f"Triggered: {alert['triggered_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                        
                        # Show event summary
                        if 'event_summary' in alert:
                            event_types = list(alert['event_summary'].keys())
                            st.write(f"Events: {', '.join(event_types[:3])}")
                    
                    with col2:
                        severity = alert.get('severity', 'medium')
                        if severity == 'high':
                            st.error("HIGH")
                        elif severity == 'medium':
                            st.warning("MEDIUM")
                        else:
                            st.info("LOW")
                    
                    with col3:
                        if not alert.get('acknowledged', False):
                            if st.button("Acknowledge", key=f"ack_{alert['_id']}"):
                                self.monitor.acknowledge_alert(alert['_id'])
                                st.rerun()
                        else:
                            st.success("✅ Acknowledged")
            
            if st.button("View All Alerts"):
                # Would navigate to detailed alerts page
                st.info("Detailed alerts view would be implemented here")
        else:
            st.success("🎉 No recent security alerts!")
    
    def show_system_activity(self):
        """Display system activity charts"""
        col1, col2 = st.columns(2)
        
        with col1:
            # Alert trend chart
            alerts = list(self.db.alerts.find({
                'triggered_at': {'$gte': datetime.now() - timedelta(days=7)}
            }))
            
            if alerts:
                # Group by day
                alert_dates = [alert['triggered_at'].strftime('%Y-%m-%d') for alert in alerts]
                date_counts = pd.Series(alert_dates).value_counts().sort_index()
                
                fig = px.line(
                    x=date_counts.index, 
                    y=date_counts.values,
                    title="Alert Trend (Last 7 Days)",
                    labels={'x': 'Date', 'y': 'Number of Alerts'}
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No alert data for trend analysis")
        
        with col2:
            # Alert type distribution
            if alerts:
                alert_types = [alert.get('alert_type', 'unknown') for alert in alerts]
                type_counts = pd.Series(alert_types).value_counts()
                
                fig = px.pie(
                    values=type_counts.values,
                    names=type_counts.index,
                    title="Alert Type Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No alert data for distribution analysis")