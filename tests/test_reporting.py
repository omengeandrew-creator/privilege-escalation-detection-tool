# tests/test_reporting.py
import unittest
import sys
import os
import tempfile
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from reporting.pdf_generator import PDFReportGenerator
from reporting.csv_generator import CSVReportGenerator
from app.database import MongoDBManager

class TestReporting(unittest.TestCase):
    
    def setUp(self):
        self.db = MongoDBManager()
        self.pdf_generator = PDFReportGenerator(self.db)
        self.csv_generator = CSVReportGenerator(self.db)
        self.test_config = {
            'report_type': 'Test Report',
            'generated_by': 'Test User',
            'period': 'Test Period'
        }
    
    def test_pdf_generation(self):
        """Test PDF report generation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock the reports directory
            import reporting.pdf_generator
            original_dir = reporting.pdf_generator.os.path.join
            reporting.pdf_generator.os.path.join = lambda *args: os.path.join(temp_dir, args[-1])
            
            try:
                filepath = self.pdf_generator.generate_comprehensive_report(self.test_config)
                self.assertTrue(os.path.exists(filepath))
                self.assertTrue(filepath.endswith('.pdf'))
            finally:
                reporting.pdf_generator.os.path.join = original_dir
    
    def test_csv_generation(self):
        """Test CSV report generation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock the reports directory
            import reporting.csv_generator
            original_dir = reporting.csv_generator.os.path.join
            reporting.csv_generator.os.path.join = lambda *args: os.path.join(temp_dir, args[-1])
            
            try:
                filepath = self.csv_generator.generate_detailed_export(self.test_config)
                self.assertTrue(os.path.exists(filepath))
                self.assertTrue(filepath.endswith('.csv'))
            finally:
                reporting.csv_generator.os.path.join = original_dir
    
    def test_report_config_validation(self):
        """Test report configuration validation"""
        # Test with minimal config
        minimal_config = {'generated_by': 'Test'}
        filepath = self.csv_generator.generate_detailed_export(minimal_config)
        self.assertIsNotNone(filepath)

if __name__ == '__main__':
    unittest.main()