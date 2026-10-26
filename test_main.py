import unittest
from pathlib import Path
from main import parse_line, analyze

class TestLogSentry(unittest.TestCase):
    def test_valid_line(self):
        result = parse_line('2026-10-26 09:00:00 LOGIN_FAILED user=bob ip=192.0.2.20')
        self.assertEqual(result['user'], 'bob')
    def test_invalid_line(self):
        with self.assertRaises(ValueError):
            parse_line('broken log')
    def test_sample_alert(self):
        result = analyze(Path(__file__).parent / 'logs/sample.log')
        self.assertEqual(result[-1], {'bob': 5})
        self.assertEqual(len(result[1]), 1)

if __name__ == '__main__':
    unittest.main()
