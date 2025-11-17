# tests/test_scanner.py
import unittest
from nodehawk.core.scanner import check_website

class TestScanner(unittest.TestCase):
    def test_google(self):
        status = check_website("https://www.google.com")
        self.assertEqual(status, 200)

if __name__ == "__main__":
    unittest.main()
