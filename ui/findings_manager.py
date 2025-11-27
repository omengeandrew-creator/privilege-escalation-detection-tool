# ui/findings_manager.py
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

class FindingsManager:
    def __init__(self, db, user_info):
        self.db = db.db
        self.user_info = user_info
    
    def show_findings_management(self):
        """Display findings management interface"""
        st.title("📋 Findings Management")
        
        # Filters and search
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            risk_filter = st.multiselect(
                "Risk Level",
                ["critical", "high", "medium", "low"],
                default=["critical", "high"]
            )
        
        with col2:
            status_filter = st.multiselect(
                "Status",
                ["open", "in_progress", "resolved", "false_positive"],
                default=["open", "in_progress"]
            )
        
        with col3:
            category_filter = st.multiselect(
                "Category",
                ["token_manipulation", "service_vulnerability", "registry", 
                 "dll_hijacking", "scheduled_tasks", "uac_bypass", 
                 "kernel", "password_dumping"]
            )
        
        with col4:
            assigned_filter = st.selectbox(
                "Assigned To",
                ["All", "Me", "Unassigned", "Others"]
            )
        
        # Search box
        search_query = st.text_input("🔍 Search findings...", placeholder="Search by title or description")
        
        # Build query
        query = {}
        if risk_filter:
            query['risk_level'] = {'$in': risk_filter}
        if status_filter:
            query['status'] = {'$in': status_filter}
        if category_filter:
            query['category'] = {'$in': category_filter}
        if assigned_filter == "Me":
            query['assigned_to'] = self.user_info['user_id']
        elif assigned_filter == "Unassigned":
            query['assigned_to'] = {'$exists': False}
        elif assigned_filter == "Others":
            query['assigned_to'] = {'$ne': self.user_info['user_id'], '$exists': True}
        
        if search_query:
            query['$or'] = [
                {'title': {'$regex': search_query, '$options': 'i'}},
                {'description': {'$regex': search_query, '$options': 'i'}}
            ]
        
        # Get findings
        findings = list(self.db.findings.find(query).sort('created_at', -1))
        
        if findings:
            st.subheader(f"📊 Found {len(findings)} Findings")
            
            # Summary statistics
            self.show_findings_summary(findings)
            
            # Findings list
            st.subheader("🔍 Detailed Findings")
            for finding in findings:
                self.display_finding_card(finding)
        else:
            st.info("🎉 No findings match the selected filters.")
    
    def show_findings_summary(self, findings):
        """Display findings summary statistics"""
        col1, col2, col3, col4 = st.columns(4)
        
        critical_count = len([f for f in findings if f['risk_level'] == 'critical'])
        high_count = len([f for f in findings if f['risk_level'] == 'high'])
        open_count = len([f for f in findings if f.get('status') == 'open'])
        assigned_to_me = len([f for f in findings if f.get('assigned_to') == self.user_info['user_id']])
        
        with col1:
            st.metric("Critical", critical_count, delta=f"{critical_count} urgent")
        with col2:
            st.metric("High", high_count)
        with col3:
            st.metric("Open", open_count)
        with col4:
            st.metric("Assigned to Me", assigned_to_me)
        
        # Risk distribution chart
        if findings:
            risk_counts = {}
            for finding in findings:
                risk = finding['risk_level']
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            fig = px.pie(
                values=list(risk_counts.values()),
                names=list(risk_counts.keys()),
                title="Risk Level Distribution",
                color=list(risk_counts.keys()),
                color_discrete_map={
                    'critical': '#d62728',
                    'high': '#ff7f0e',
                    'medium': '#ffbb78',
                    'low': '#2ca02c'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    def display_finding_card(self, finding):
        """Display individual finding card"""
        risk_color = {
            'critical': '#d62728',
            'high': '#ff7f0e',
            'medium': '#ffbb78',
            'low': '#2ca02c'
        }
        
        with st.container():
            st.markdown(f"""
            <div style='border-left: 5px solid {risk_color[finding['risk_level']]}; 
                        padding: 15px; margin: 10px 0; background-color: #f8f9fa;
                        border-radius: 5px;'>
                <div style='display: flex; justify-content: between; align-items: start;'>
                    <div style='flex: 1;'>
                        <h4 style='margin: 0; color: {risk_color[finding['risk_level']]};'>
                            {finding['title']}
                        </h4>
                        <p style='margin: 5px 0; color: #666;'>{finding['description']}</p>
                    </div>
                    <div style='text-align: right;'>
                        <div style='font-weight: bold; color: {risk_color[finding['risk_level']]};'>
                            {finding['risk_level'].upper()}
                        </div>
                        <div style='font-size: 0.8rem; color: #888;'>
                            CVSS: {finding.get('cvss_score', 'N/A')}
                        </div>
                    </div>
                </div>
                
                <div style='display: flex; justify-content: space-between; margin-top: 10px; font-size: 0.8rem;'>
                    <span><strong>Category:</strong> {finding.get('category', 'Unknown')}</span>
                    <span><strong>Status:</strong> {finding.get('status', 'open')}</span>
                    <span><strong>Found:</strong> {finding['created_at'].strftime('%Y-%m-%d')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # ENHANCEMENT: Show mitigation effectiveness if available
            try:
                effectiveness = self.get_mitigation_effectiveness(finding['_id'])
                if effectiveness > 0:
                    col_extra1, col_extra2 = st.columns(2)
                    with col_extra1:
                        st.progress(effectiveness, text=f"Mitigation Effectiveness: {effectiveness:.0%}")
            except Exception:
                pass  # Silently continue if method not available or fails
            
            # Action buttons
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button("📝 Edit", key=f"edit_{finding['_id']}", use_container_width=True):
                    self.show_edit_dialog(finding)
            
            with col2:
                if st.button("🛡️ Mitigate", key=f"mit_{finding['_id']}", use_container_width=True):
                    self.show_mitigation_dialog(finding)
            
            with col3:
                if finding.get('assigned_to') != self.user_info['user_id']:
                    if st.button("👤 Assign to Me", key=f"assign_{finding['_id']}", use_container_width=True):
                        self.assign_finding_to_me(finding)
                else:
                    st.success("✅ Assigned to you")
            
            with col4:
                if st.button("📋 Details", key=f"det_{finding['_id']}", use_container_width=True):
                    self.show_finding_details(finding)
            
            st.markdown("---")
    
    def show_edit_dialog(self, finding):
        """Show finding edit dialog"""
        st.session_state['editing_finding'] = str(finding['_id'])
        
        with st.form(f"edit_form_{finding['_id']}"):
            st.subheader(f"Edit Finding: {finding['title']}")
            
            new_status = st.selectbox(
                "Status",
                ["open", "in_progress", "resolved", "false_positive"],
                index=["open", "in_progress", "resolved", "false_positive"].index(finding.get('status', 'open'))
            )
            
            new_risk = st.selectbox(
                "Risk Level",
                ["low", "medium", "high", "critical"],
                index=["low", "medium", "high", "critical"].index(finding['risk_level'])
            )
            
            assigned_to = st.text_input("Assigned To", value=finding.get('assigned_to', ''))
            
            notes = st.text_area("Additional Notes", value=finding.get('notes', ''))
            
            if st.form_submit_button("💾 Save Changes"):
                self.update_finding(finding['_id'], {
                    'status': new_status,
                    'risk_level': new_risk,
                    'assigned_to': assigned_to,
                    'notes': notes,
                    'updated_at': datetime.now(),
                    'updated_by': self.user_info['user_id']
                })
                st.success("Finding updated successfully!")
                st.session_state['editing_finding'] = None
                st.rerun()
    
    def show_mitigation_dialog(self, finding):
        """Show mitigation options dialog"""
        st.session_state['mitigating_finding'] = str(finding['_id'])
        
        with st.form(f"mitigate_form_{finding['_id']}"):
            st.subheader(f"Mitigate: {finding['title']}")
            
            # ENHANCEMENT: Show mitigation history if available
            try:
                history = self.get_mitigation_history(finding['_id'])
                if history:
                    with st.expander("📜 Mitigation History"):
                        for attempt in history:
                            status_color = {
                                'completed': '🟢',
                                'in_progress': '🟡', 
                                'planned': '🔵',
                                'failed': '🔴'
                            }
                            st.write(f"{status_color.get(attempt.get('status', 'planned'), '⚪')} "
                                   f"{attempt.get('applied_at', datetime.now()).strftime('%Y-%m-%d')}: "
                                   f"{attempt.get('action_taken', 'No description')}")
            except Exception:
                pass  # Silently continue if method not available or fails
            
            st.write("**Recommended Mitigation:**")
            st.info(finding.get('mitigation', 'No mitigation provided'))
            
            action_taken = st.text_area("Action Taken", placeholder="Describe the mitigation actions you implemented...")
            
            mitigation_status = st.selectbox(
                "Mitigation Status",
                ["planned", "in_progress", "completed", "failed"]
            )
            
            effectiveness = st.slider(
                "Effectiveness Score",
                min_value=0.0,
                max_value=1.0,
                value=0.8,
                help="How effective is this mitigation? (0.0 = not effective, 1.0 = completely effective)"
            )
            
            if st.form_submit_button("✅ Apply Mitigation"):
                mitigation_data = {
                    'action_taken': action_taken,
                    'status': mitigation_status,
                    'effectiveness': effectiveness,
                    'applied_by': self.user_info['user_id'],
                    'applied_at': datetime.now()
                }
                
                self.record_mitigation(finding['_id'], mitigation_data)
                st.success("Mitigation recorded successfully!")
                st.session_state['mitigating_finding'] = None
                st.rerun()
    
    def show_finding_details(self, finding):
        """Show detailed finding view"""
        st.session_state['viewing_finding'] = str(finding['_id'])
        
        st.subheader(f"Finding Details: {finding['title']}")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Description:**")
            st.write(finding['description'])
            
            st.write("**Evidence:**")
            st.code(finding.get('evidence', 'No evidence collected'), language='text')
        
        with col2:
            st.write("**Metadata:**")
            st.write(f"- **Risk Level:** {finding['risk_level']}")
            st.write(f"- **Category:** {finding.get('category', 'Unknown')}")
            st.write(f"- **CVSS Score:** {finding.get('cvss_score', 'N/A')}")
            st.write(f"- **Status:** {finding.get('status', 'open')}")
            st.write(f"- **Created:** {finding['created_at'].strftime('%Y-%m-%d %H:%M')}")
            st.write(f"- **Assigned To:** {finding.get('assigned_to', 'Unassigned')}")
            
            # ENHANCEMENT: Show mitigation effectiveness in details
            try:
                effectiveness = self.get_mitigation_effectiveness(finding['_id'])
                if effectiveness > 0:
                    st.write(f"- **Mitigation Effectiveness:** {effectiveness:.0%}")
                    st.progress(effectiveness)
            except Exception:
                pass
        
        st.write("**Mitigation:**")
        st.info(finding.get('mitigation', 'No mitigation provided'))
        
        # ENHANCEMENT: Show detailed mitigation history
        try:
            history = self.get_mitigation_history(finding['_id'])
            if history:
                with st.expander("📜 Detailed Mitigation History"):
                    for i, attempt in enumerate(history):
                        st.write(f"**Attempt #{i+1}** ({attempt.get('applied_at', datetime.now()).strftime('%Y-%m-%d %H:%M')})")
                        st.write(f"**Action:** {attempt.get('action_taken', 'No description')}")
                        st.write(f"**Status:** {attempt.get('status', 'unknown')}")
                        st.write(f"**Effectiveness:** {attempt.get('effectiveness', 0.5):.0%}")
                        st.write(f"**By:** {attempt.get('applied_by', 'Unknown')}")
                        st.markdown("---")
        except Exception:
            pass
        
        if st.button("← Back to List"):
            st.session_state['viewing_finding'] = None
            st.rerun()
    
    def assign_finding_to_me(self, finding):
        """Assign finding to current user"""
        self.db.findings.update_one(
            {'_id': finding['_id']},
            {'$set': {
                'assigned_to': self.user_info['user_id'],
                'updated_at': datetime.now()
            }}
        )
        st.success("Finding assigned to you!")
        st.rerun()
    
    def update_finding(self, finding_id, updates):
        """Update finding information"""
        self.db.findings.update_one(
            {'_id': finding_id},
            {'$set': updates}
        )
    
    def record_mitigation(self, finding_id, mitigation_data):
        """Record mitigation action"""
        # Store in mitigations collection
        self.db.mitigation_actions.insert_one({
            'finding_id': finding_id,
            **mitigation_data
        })
        
        # Update finding status if mitigation completed
        if mitigation_data['status'] == 'completed':
            self.db.findings.update_one(
                {'_id': finding_id},
                {'$set': {'status': 'resolved'}}
            )
    
    # ===== ENHANCEMENTS =====
    # NEW METHODS ADDED BELOW - ALL EXISTING CODE ABOVE REMAINS UNCHANGED
    
    def get_mitigation_effectiveness(self, finding_id):
        """Calculate mitigation effectiveness score"""
        mitigations = list(self.db.mitigation_actions.find(
            {'finding_id': finding_id}
        ).sort('applied_at', -1))
        
        if not mitigations:
            return 0
        
        # Calculate average effectiveness
        total_effectiveness = sum(m.get('effectiveness', 0.5) for m in mitigations)
        return total_effectiveness / len(mitigations)
    
    def get_mitigation_history(self, finding_id):
        """Get complete mitigation history"""
        return list(self.db.mitigation_actions.find(
            {'finding_id': finding_id}
        ).sort('applied_at', -1))
    
    def get_mitigation_statistics(self):
        """Get overall mitigation statistics"""
        pipeline = [
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1},
                    "avg_effectiveness": {"$avg": "$effectiveness"}
                }
            }
        ]
        
        stats = list(self.db.mitigation_actions.aggregate(pipeline))
        return {stat['_id']: stat for stat in stats}