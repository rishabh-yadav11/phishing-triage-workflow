import unittest
from parser import parse_eml
from ioc import extract_iocs
from analyzer import calculate_risk_score

class TestWorkflow(unittest.TestCase):
    def test_end_to_end(self):
        parsed = parse_eml('sample.eml')
        self.assertEqual(parsed['headers']['Subject'], 'URGENT: Your Account Has Been Suspended')
        
        iocs = extract_iocs(parsed)
        self.assertIn('http://bit.ly/3xyz789', iocs['urls'])
        self.assertEqual(len(iocs['mismatched_links']), 1)
        self.assertEqual(len(parsed['attachments']), 1)
        
        analysis = calculate_risk_score(parsed, iocs)
        self.assertEqual(analysis['total_score'], 100) # Capped at 100

if __name__ == '__main__':
    unittest.main()
