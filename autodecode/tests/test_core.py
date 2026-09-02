"""Tests for the autodecode core logic."""

import base64
import unittest

from autodecode.core import (best_candidate, codec_likelihood, confidence,
                             decode_all, single_step)

import autodecode.core as core


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class TestCodecs(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(core._b64(b64("Hello CTF!")), "Hello CTF!")
        self.assertIsNone(core._b64("not base64!!!"))

    def test_base32(self):
        import base64 as b
        enc = b.b32encode(b"Hello CTF").decode()
        self.assertEqual(core._b32(enc), "Hello CTF")

    def test_hex(self):
        self.assertEqual(core._hex("48656c6c6f"), "Hello")

    def test_rot13(self):
        self.assertEqual(core._rot13("Uryyb"), "Hello")
        self.assertEqual(core._rot13("Hello CTF"), "Uryyb PGS")

    def test_rot47(self):
        self.assertEqual(core._rot47(core._rot47("abc123")), "abc123")

    def test_morse(self):
        self.assertEqual(core._morse("- .... . / --.- ..- .. -.-. -.-"),
                         "THE QUICK")
        self.assertEqual(core._morse(".... . .-.. .-.. ---"), "HELLO")

    def test_binary(self):
        self.assertEqual(
            core._binary("".join(format(ord(c), "08b") for c in "CTF Flag")),
            "CTF Flag")

    def test_url(self):
        self.assertEqual(core._url("Hello%20%26%26%20World"), "Hello && World")

    def test_caesar(self):
        self.assertEqual(core._caesar("Hello", 3), "Khoor")
        self.assertEqual(core._caesar("Khoor", 23), "Hello")


class TestConfidence(unittest.TestCase):
    def test_english_beats_noise(self):
        self.assertGreater(confidence("Hello World This Is A Flag"),
                           confidence("MAPmvA8aK1LACK=="))
        self.assertGreater(confidence("The quick brown fox jumps over the "
                                      "lazy dog"),
                           confidence("randomnoise=="))

    def test_flag_bonus(self):
        self.assertGreater(confidence("flag{th1s_1s_a_fl4g}"),
                           confidence("xzqkwqe"))


class TestChaining(unittest.TestCase):
    def test_single_base64(self):
        r = best_candidate(b64("Hello CTF!"))
        self.assertIsNotNone(r)
        self.assertEqual(r.text, "Hello CTF!")
        self.assertIn("base64", r.chain)

    def test_double_encoding(self):
        inner = "welcome ctf"
        hexed = inner.encode().hex()
        enc = b64(hexed)
        r = best_candidate(enc)
        self.assertIsNotNone(r)
        self.assertEqual(r.text, inner)
        self.assertEqual(r.chain, ["base64", "hex"])

    def test_morse_chain(self):
        r = best_candidate("- .... . / --.- ..- .. -.-. -.-")
        self.assertEqual(r.text, "THE QUICK")

    def test_binary_chain(self):
        s = "".join(format(ord(c), "08b") for c in "CTF Flag")
        r = best_candidate(s)
        self.assertEqual(r.text, "CTF Flag")

    def test_binary_detected_over_base64(self):
        s = "".join(format(ord(c), "08b") for c in "AB")
        top = codec_likelihood(s)[0]
        self.assertEqual(top[0], "binary")

    def test_caesar_readable(self):
        r = best_candidate("Khoor zruog wklv lv d iodj")
        self.assertIsNotNone(r)
        self.assertEqual(r.text, "Hello world this is a flag")

    def test_single_step_has_base64(self):
        methods = [s.method for s in single_step(b64("hi"))]
        self.assertIn("base64", methods)

    def test_decode_all_terminates(self):
        res = decode_all(b64("Hello CTF!"), max_depth=3)
        self.assertTrue(any(r.text == "Hello CTF!" for r in res))


if __name__ == "__main__":
    unittest.main()