# core/attack_simulator.py
import random
import json
from datetime import datetime
from typing import List, Dict

class AttackSimulator:
    def __init__(self, db):
        self.db = db
        self.simulation_scenarios = self.load_simulation_scenarios()
    
    def load_simulation_scenarios(self):
        """Load attack simulation scenarios"""
        return {
            'token_manipulation': {
                'name': 'Token Privilege Escalation',
                'description': 'Simulates token manipulation attacks to gain SYSTEM privileges',
                'steps': [
                    'Check current token privileges',
                    'Identify SeDebugPrivilege availability',
                    'Attempt token duplication',
                    'Try privilege escalation'
                ],
                'success_rate': 0.75,
                'complexity': 'medium'
            },
            'service_hijacking': {
                'name': 'Service Permission Exploitation',
                'description': 'Exploits weak service permissions for privilege escalation',
                'steps': [
                    'Enumerate services with weak permissions',
                    'Check service binary permissions',
                    'Attempt service configuration modification',
                    'Try service restart with elevated privileges'
                ],
                'success_rate': 0.65,
                'complexity': 'low'
            },
            'dll_hijacking': {
                'name': 'DLL Search Order Hijacking',
                'description': 'Exploits DLL search order for code execution',
                'steps': [
                    'Identify applications with unquoted paths',
                    'Check writable directories in PATH',
                    'Create malicious DLL',
                    'Trigger application execution'
                ],
                'success_rate': 0.55,
                'complexity': 'medium'
            },
            'uac_bypass': {
                'name': 'UAC Bypass Attempt',
                'description': 'Attempts to bypass User Account Control',
                'steps': [
                    'Check UAC level',
                    'Identify auto-elevation opportunities',
                    'Try known UAC bypass techniques',
                    'Attempt elevation without prompt'
                ],
                'success_rate': 0.45,
                'complexity': 'high'
            }
        }
    
    def simulate_attack(self, attack_type: str, target_system: str = "localhost"):
        """Simulate a specific attack type"""
        if attack_type not in self.simulation_scenarios:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        scenario = self.simulation_scenarios[attack_type]
        
        simulation_result = {
            'scenario': scenario['name'],
            'description': scenario['description'],
            'target_system': target_system,
            'start_time': datetime.now(),
            'steps': [],
            'success': False,
            'risk_level': 'high',
            'evidence': []
        }
        
        # Simulate each step
        for step in scenario['steps']:
            step_result = self.simulate_step(step, scenario['success_rate'])
            simulation_result['steps'].append({
                'step': step,
                'success': step_result['success'],
                'evidence': step_result['evidence']
            })
            simulation_result['evidence'].extend(step_result['evidence'])
        
        # Determine overall success based on step success rates
        successful_steps = sum(1 for step in simulation_result['steps'] if step['success'])
        success_threshold = len(scenario['steps']) * 0.6  # 60% of steps must succeed
        
        simulation_result['success'] = successful_steps >= success_threshold
        simulation_result['end_time'] = datetime.now()
        
        # Store simulation result
        self.db.attack_simulations.insert_one(simulation_result)
        
        return simulation_result
    
    def simulate_step(self, step: str, success_rate: float):
        """Simulate individual attack step"""
        # Simulate step execution with random success based on success_rate
        success = random.random() < success_rate
        
        evidence = [
            f"Step '{step}' executed",
            f"Success: {success}",
            f"Simulated evidence collected for analysis"
        ]
        
        if not success:
            evidence.append("Step failed - simulated defensive measures detected the attempt")
        
        return {
            'success': success,
            'evidence': evidence
        }
    
    def run_comprehensive_simulation(self, target_system: str = "localhost"):
        """Run all attack simulations"""
        results = {}
        
        for attack_type in self.simulation_scenarios.keys():
            try:
                result = self.simulate_attack(attack_type, target_system)
                results[attack_type] = result
            except Exception as e:
                results[attack_type] = {
                    'error': str(e),
                    'success': False
                }
        
        # Generate simulation report
        report = self.generate_simulation_report(results)
        
        return {
            'simulation_results': results,
            'report': report,
            'overall_risk_score': self.calculate_overall_risk(results)
        }
    
    def generate_simulation_report(self, results: Dict):
        """Generate comprehensive simulation report"""
        total_simulations = len(results)
        successful_simulations = sum(1 for r in results.values() if r.get('success', False))
        
        report = {
            'summary': {
                'total_simulations': total_simulations,
                'successful_simulations': successful_simulations,
                'success_rate': successful_simulations / total_simulations if total_simulations > 0 else 0,
                'generated_at': datetime.now()
            },
            'detailed_results': results,
            'recommendations': self.generate_recommendations(results)
        }
        
        return report
    
    def generate_recommendations(self, results: Dict):
        """Generate security recommendations based on simulation results"""
        recommendations = []
        
        for attack_type, result in results.items():
            if result.get('success', False):
                scenario = self.simulation_scenarios[attack_type]
                
                if attack_type == 'token_manipulation':
                    recommendations.append({
                        'priority': 'high',
                        'category': 'privilege_management',
                        'description': 'Strengthen token privilege controls',
                        'action': 'Review and remove unnecessary privileges through Group Policy'
                    })
                
                elif attack_type == 'service_hijacking':
                    recommendations.append({
                        'priority': 'high',
                        'category': 'service_security',
                        'description': 'Harden service permissions',
                        'action': 'Implement least privilege for service accounts and regular permission reviews'
                    })
                
                elif attack_type == 'dll_hijacking':
                    recommendations.append({
                        'priority': 'medium',
                        'category': 'application_security',
                        'description': 'Secure DLL loading',
                        'action': 'Enable DLL search order hardening and application whitelisting'
                    })
                
                elif attack_type == 'uac_bypass':
                    recommendations.append({
                        'priority': 'medium',
                        'category': 'system_security',
                        'description': 'Strengthen UAC protections',
                        'action': 'Configure UAC to highest level and monitor for bypass attempts'
                    })
        
        return recommendations
    
    def calculate_overall_risk(self, results: Dict):
        """Calculate overall risk score from simulation results"""
        if not results:
            return 0
        
        risk_scores = {
            'token_manipulation': 9.0,
            'service_hijacking': 8.5,
            'dll_hijacking': 7.0,
            'uac_bypass': 6.5
        }
        
        total_risk = 0
        count = 0
        
        for attack_type, result in results.items():
            if result.get('success', False):
                total_risk += risk_scores.get(attack_type, 5.0)
                count += 1
        
        return total_risk / count if count > 0 else 0