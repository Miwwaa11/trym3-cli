"""Tests for revshell core logic."""

import unittest

from revshell.core import ALL_LANGS, generate_shell


class TestGenerate(unittest.TestCase):
    def test_all_langs_present(self):
        self.assertIn("bash", ALL_LANGS)
        self.assertIn("python", ALL_LANGS)
        self.assertIn("php", ALL_LANGS)

    def test_generate_all(self):
        shells = generate_shell("10.0.0.5", 4444)
        self.assertGreater(len(shells), 8)
        for s in shells:
            s.port = 4444
            self.assertIn("10.0.0.5", s.payload)
            self.assertIn("4444", s.payload)

    def test_generate_single_lang(self):
        shells = generate_shell("1.2.3.4", 1337, "python")
        self.assertTrue(shells)
        for s in shells:
            self.assertEqual(s.lang, "python")

    def test_unknown_lang(self):
        self.assertEqual(generate_shell("1.1.1.1", 1, "nope"), [])

    def test_payload_contains_ip_and_port(self):
        for s in generate_shell("192.168.1.20", 7777):
            self.assertIn("192.168.1.20", s.payload)
            self.assertIn("7777", s.payload)


if __name__ == "__main__":
    unittest.main()
