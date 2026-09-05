"""Tests for hashcrack core logic."""

import hashlib
import unittest

from hashcrack.core import (brute_force, crack_hash, identify_hash,
                            MAILCHIMP_LOOKUP)


class TestIdentify(unittest.TestCase):
    def test_md5(self):
        matches = identify_hash("5d41402abc4b2a76b9719d911017c592")
        self.assertIn("MD5", [m.name for m in matches])

    def test_sha256(self):
        matches = identify_hash(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertIn("SHA-256", [m.name for m in matches])

    def test_bcrypt(self):
        matches = identify_hash(
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
        self.assertIn("bcrypt", [m.name for m in matches])

    def test_no_match(self):
        self.assertEqual(identify_hash("xyz"), [])


class TestCrack(unittest.TestCase):
    def test_crack_md5(self):
        word = "password"
        h = hashlib.md5(word.encode()).hexdigest()
        self.assertEqual(crack_hash(h, ["foo", word, "bar"]), word)

    def test_crack_sha1(self):
        word = "letmein"
        h = hashlib.sha1(word.encode()).hexdigest()
        self.assertEqual(crack_hash(h, ["pass", word]), word)

    def test_crack_no_match(self):
        h = hashlib.md5(b"secret").hexdigest()
        self.assertIsNone(crack_hash(h, ["wrong", "words"]))

    def test_forced_type(self):
        word = "hello"
        h = hashlib.sha256(word.encode()).hexdigest()
        self.assertEqual(crack_hash(h, ["hello"], "SHA-256"), word)


class TestBruteForce(unittest.TestCase):
    def test_brute_small(self):
        h = hashlib.md5(b"ab").hexdigest()
        self.assertEqual(brute_force(h, "abcd", 2), "ab")


if __name__ == "__main__":
    unittest.main()
