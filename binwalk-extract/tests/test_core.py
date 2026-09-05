"""Tests for binwalk-extract core logic."""

import unittest
import zlib

from binwalk_extract.core import (carve, carve_all, extract_to_dir,
                                  find_magic)


def make_png_bytes() -> bytes:
    def chunk(name: bytes, payload: bytes) -> bytes:
        import struct
        crc = zlib.crc32(name + payload) & 0xffffffff
        return struct.pack(">I", len(payload)) + name + payload + \
            struct.pack(">I", crc)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", bytes.fromhex("00000001000000010802000000"))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


class TestFindMagic(unittest.TestCase):
    def test_find_png(self):
        data = b"junk" + make_png_bytes() + b"more junk"
        results = find_magic(data)
        pngs = [r for r in results if r.name == "PNG image"]
        self.assertTrue(pngs)
        self.assertEqual(pngs[0].offset, 4)

    def test_find_zip(self):
        data = b"prefix" + b"PK\x03\x04" + b"\x00" * 20
        results = find_magic(data)
        self.assertTrue(any(r.name == "ZIP archive" for r in results))

    def test_find_elf(self):
        data = b"\x00\x01" + b"\x7fELF" + b"\x00" * 10
        results = find_magic(data)
        self.assertTrue(any(r.name == "ELF executable" for r in results))

    def test_no_match(self):
        self.assertEqual(find_magic(b"\x00" * 64), [])


class TestCarve(unittest.TestCase):
    def test_carve_png(self):
        png = make_png_bytes()
        data = b"x" * 3 + png + b"y" * 3
        results = find_magic(data)
        p = [r for r in results if r.name == "PNG image"][0]
        out = carve(data, p.offset, bytes.fromhex(p.matched_magic))
        self.assertTrue(out.startswith(b"\x89PNG"))

    def test_carve_all(self):
        png = make_png_bytes()
        zipb = b"PK\x03\x04" + b"\x00" * 10 + b"PK\x05\x06" + b"\x00" * 18
        data = b"junk" + png + zipb
        carved = carve_all(data)
        self.assertGreaterEqual(len(carved), 2)


class TestExtract(unittest.TestCase):
    def test_extract_to_dir(self):
        import tempfile
        data = b"pre" + make_png_bytes() + b"post"
        with tempfile.TemporaryDirectory() as d:
            files = extract_to_dir(data, d)
            self.assertTrue(any(f.endswith(".png") for f in files))


if __name__ == "__main__":
    unittest.main()
