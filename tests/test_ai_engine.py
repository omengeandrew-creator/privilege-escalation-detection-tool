# tests/test_ai_engine.py
import unittest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.ai_engine import AIAnalysisEngine
from app.database import MongoDBManager

class TestAIEngine(unittest.TestCase):
    
    def setUp(self):
        self.db = MongoDBManager()
        self.ai_engine = AIAnalysisEngine(self.db)
    
    def test_ai_engine_initialization(self):
        """Test AI engine initialization"""
        self.assertIsNotNone(self.ai_engine)
        self.assertIsNotNone(self.ai_engine.models)
    
    def test_risk_prediction(self):
        """Test risk prediction functionality"""
        test_finding = {
            'title': 'Test Finding',
            'description': 'This is a test finding for AI analysis',
            'risk_level': 'medium',
            'category': 'test',
            'evidence': 'Test evidence data',
            'mitigation': 'Test mitigation steps',
            'cvss_score': 5.0
        }
        
        predicted_risk = self.ai_engine.predict_risk(test_finding)
        
        self.assertIn(predicted_risk, ['low', 'medium', 'high', 'critical'])
    
    def test_attack_simulation_generation(self):
        """Test attack simulation generation"""
        simulations = self.ai_engine.generate_attack_simulations()
        
        self.assertIsInstance(simulations, list)
        self.assertGreater(len(simulations), 0)
        
        for simulation in simulations:
            self.assertIn('technique', simulation)
            self.assertIn('success_probability', simulation)
    
    def test_findings_pattern_analysis(self):
        """Test findings pattern analysis"""
        insights = self.ai_engine.analyze_findings_patterns()
        
        self.assertIsInstance(insights, list)
        
        # Should return list of strings (insights)
        for insight in insights:
            self.assertIsInstance(insight, str)
    
    def tearDown(self):
        """Clean up"""
        pass

if __name__ == '__main__':
    unittest.main()