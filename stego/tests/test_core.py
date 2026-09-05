"""Tests for stego core logic."""

import io
import struct
import unittest
import zlib

from stego.core import (analyze_png_chunks, detect_format,
                        extract_extra_chunks, hidden_strings, list_extra_chunks,
                        lsb_extract, parse_gif_blocks, png_idat_verify,
                        stringscan)

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def make_png_with_extra(minimal: bool = True) -> bytes:
    """Build a minimal but structurally valid PNG with a custom extra
    chunk to verify extraction."""
    def chunk(name: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + name + payload +
                struct.pack(">I", zlib.crc32(name + payload) & 0xffffffff))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x00\x00")
    extra = b"steghide_payload_super_secret"
    return (sig + chunk(b"IHDR", ihdr) + chunk(b"sTeG", extra) +
            chunk(b"IDAT", idat) + chunk(b"IEND", b""))


class TestDetect(unittest.TestCase):
    def test_png(self):
        self.assertEqual(detect_format(b"\x89PNG\r\n\x1a\n..."), "png")

    def test_jpeg(self):
        self.assertEqual(detect_format(b"\xff\xd8\xff\xe0"), "jpeg")

    def test_gif(self):
        self.assertEqual(detect_format(b"GIF89a"), "gif")

    def test_bmp(self):
        self.assertEqual(detect_format(b"BM...."), "bmp")

    def test_unknown(self):
        self.assertIsNone(detect_format(b"\x00\x01\x02"))


class TestPNGChunks(unittest.TestCase):
    def test_analyze(self):
        data = make_png_with_extra()
        chunks = analyze_png_chunks(data)
        names = [c.name for c in chunks]
        self.assertIn("IHDR", names)
        self.assertIn("sTeG", names)
        self.assertIn("IDAT", names)
        self.assertIn("IEND", names)

    def test_extra_chunks(self):
        data = make_png_with_extra()
        extras = list_extra_chunks(data)
        self.assertEqual([c.name for c in extras], ["sTeG"])

    def test_extract_payload(self):
        data = make_png_with_extra()
        payloads = extract_extra_chunks(data)
        self.assertEqual(payloads["sTeG"], b"steghide_payload_super_secret")

    def test_idat_verify(self):
        data = make_png_with_extra()
        self.assertTrue(png_idat_verify(data))


class TestGIF(unittest.TestCase):
    def test_parse_blocks(self):
        data = (b"GIF89a\x00\x00\x00\x21\xff\x0b" +
                b"NETSCAPE2.0" + b"\x00\x3b")
        blocks = parse_gif_blocks(data)
        self.assertTrue(blocks)
        self.assertEqual(blocks[0][2], b"NETSCAPE2.0")


@unittest.skipUnless(HAS_PIL, "Pillow not installed")
class TestLSB(unittest.TestCase):
    def _make_lsb_image(self, message: bytes, size: int = 32) -> bytes:
        """Build a PNG with `message` hidden in the LSB of each RGB channel.

        Bits are embedded sequentially across the R,G,B channels of each pixel
        to exactly mirror the extraction order used by ``lsb_extract``.
        """
        pixels = [(0, 0, 0)] * (size * size)
        bitstream = "".join(f"{byte:08b}" for byte in message + b"\x00")
        mutated = list(pixels)
        for idx, bit_char in enumerate(bitstream):
            pixel_index = idx // 3
            if pixel_index >= len(mutated):
                break
            channel = idx % 3
            px = list(mutated[pixel_index])
            px[channel] = (px[channel] & 0xFE) | int(bit_char)
            mutated[pixel_index] = tuple(px)
        img = Image.new("RGB", (size, size))
        img.putdata(mutated)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def test_roundtrip_rgb(self):
        msg = b"flag{lsb_h1dd3n}"
        data = self._make_lsb_image(msg)
        self.assertEqual(lsb_extract(data, channel="rgb"), msg.decode())

    def test_no_message_none(self):
        img = Image.new("RGB", (16, 16), (10, 10, 10))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.assertIsNone(lsb_extract(buf.getvalue(), channel="rgb"))


class TestStrings(unittest.TestCase):
    def test_stringscan(self):
        data = b"hello\x00world\x00"
        self.assertEqual(stringscan(data, min_len=3), ["hello", "world"])

    def test_hidden_strings(self):
        data = b"random\x00flag{th1s_1s_1t}\x00more"
        self.assertTrue(any("flag{" in s for s in hidden_strings(data)))


if __name__ == "__main__":
    unittest.main()
