# tests/test_scanners.py
import unittest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.scanner import WindowsPrivilegeScanner
from app.database import MongoDBManager

class TestWindowsPrivilegeScanner(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.db = MongoDBManager()
        self.scanner = WindowsPrivilegeScanner(self.db)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(len(self.scanner.findings), 0)
    
    def test_add_finding(self):
        """Test adding a security finding"""
        initial_count = len(self.scanner.findings)
        
        self.scanner.add_finding(
            title="Test Finding",
            description="Test description",
            risk="medium",
            category="test",
            evidence="Test evidence",
            mitigation="Test mitigation",
            cvss_score=5.0
        )
        
        self.assertEqual(len(self.scanner.findings), initial_count + 1)
        
        finding = self.scanner.findings[-1]
        self.assertEqual(finding['title'], "Test Finding")
        self.assertEqual(finding['risk_level'], "medium")
    
    def test_risk_level_calculation(self):
        """Test CVSS score calculation based on risk level"""
        # Test critical risk
        self.scanner.add_finding(
            title="Critical Test",
            description="Test",
            risk="critical",
            category="test",
            evidence="Test",
            mitigation="Test"
        )
        
        critical_finding = self.scanner.findings[-1]
        self.assertGreaterEqual(critical_finding['cvss_score'], 9.0)
    
    def test_directory_writable_check(self):
        """Test directory writable check"""
        # Test with system directory (should not be writable)
        is_writable = self.scanner.is_directory_writable("C:\\Windows\\System32")
        self.assertFalse(is_writable)
    
    def test_comprehensive_scan_structure(self):
        """Test comprehensive scan returns proper structure"""
        scan_config = {
            'modules': ['Token Manipulation', 'Service Vulnerabilities'],
            'ai_analysis': False
        }
        
        findings = self.scanner.run_comprehensive_scan(scan_config)
        
        self.assertIsInstance(findings, list)
        
        if findings:
            for finding in findings:
                self.assertIn('title', finding)
                self.assertIn('risk_level', finding)
                self.assertIn('category', finding)
    
    def tearDown(self):
        """Clean up after tests"""
        self.scanner.findings = []

if __name__ == '__main__':
    unittest.main()