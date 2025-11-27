# tests/test_detectors.py
import unittest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from detectors.token_manipulation import TokenManipulationDetector
from detectors.service_vulnerabilities import ServiceVulnerabilityDetector

class TestDetectors(unittest.TestCase):
    
    def test_token_manipulation_detector(self):
        """Test token manipulation detector"""
        detector = TokenManipulationDetector()
        findings = detector.scan()
        
        self.assertIsInstance(findings, list)
        
        for finding in findings:
            self.assertEqual(finding['category'], 'token_manipulation')
            self.assertIn(finding['risk_level'], ['low', 'medium', 'high', 'critical'])
    
    def test_service_vulnerability_detector(self):
        """Test service vulnerability detector"""
        detector = ServiceVulnerabilityDetector()
        findings = detector.scan()
        
        self.assertIsInstance(findings, list)
        
        for finding in findings:
            self.assertEqual(finding['category'], 'service_vulnerability')
            self.assertIn('evidence', finding)
    
    def test_detector_finding_structure(self):
        """Test that all detectors return properly structured findings"""
        detectors = [
            TokenManipulationDetector(),
            ServiceVulnerabilityDetector()
        ]
        
        required_fields = ['title', 'description', 'risk_level', 'category', 'evidence', 'mitigation', 'cvss_score']
        
        for detector in detectors:
            findings = detector.scan()
            
            for finding in findings:
                for field in required_fields:
                    self.assertIn(field, finding)

if __name__ == '__main__':
    unittest.main()