"""Core logic for stego: hidden data analysis & extraction from images."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:  # pragma: no cover
    HAS_PIL = False

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGIC = b"GIF8"
BMP_MAGIC = b"BM"

IMAGE_MAGICS = {
    "png": PNG_MAGIC,
    "jpeg": JPEG_MAGIC,
    "gif": GIF_MAGIC,
    "bmp": BMP_MAGIC,
}


@dataclass
class ChunkInfo:
    name: str
    offset: int
    size: int
    data_offset: int


@dataclass
class LSBResult:
    width: int
    height: int
    mode: str
    rgb_variance: float | None
    hidden_string: str | None
    lsb_plane_text_bit: str | None


def detect_format(data: bytes) -> str | None:
    """Detect image format from magic bytes."""
    for name, magic in IMAGE_MAGICS.items():
        if data.startswith(magic):
            return name
    return None


def analyze_png_chunks(data: bytes) -> list[ChunkInfo]:
    """Parse PNG chunk structure to find anomalies (extra/unknown chunks)."""
    if not data.startswith(PNG_MAGIC):
        return []
    chunks: list[ChunkInfo] = []
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        name = data[pos + 4:pos + 8].decode("latin-1", errors="replace")
        chunks.append(ChunkInfo(name=name, offset=pos,
                                size=length, data_offset=pos + 8))
        pos += 12 + length
        if name == "IEND":
            break
    return chunks


def list_extra_chunks(data: bytes) -> list[ChunkInfo]:
    """Return non-standard PNG chunks (often steganography payloads)."""
    standard = {"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "cHRM", "sRGB",
                "iCCP", "sBIT", "pHYs", "tEXt", "iTXt", "zTXt", "bKGD", "hIST",
                "sPLT", "tIME", "eXIf"}
    return [c for c in analyze_png_chunks(data) if c.name not in standard]


def extract_extra_chunks(data: bytes) -> dict[str, bytes]:
    """Extract the raw payload of non-standard PNG chunks."""
    result: dict[str, bytes] = {}
    for c in analyze_png_chunks(data):
        if c.name not in {"IEND", "IHDR", "IDAT", "PLTE"}:
            start = c.data_offset
            end = c.data_offset + c.size
            if end <= len(data):
                result[c.name] = data[start:end]
    return result


def parse_gif_blocks(data: bytes) -> list[tuple[int, int, bytes]]:
    """Return (offset, size, payload) for GIF application extension blocks,
    which are a common hiding spot."""
    blocks: list[tuple[int, int, bytes]] = []
    pos = data.find(b"\x21\xff")
    while pos != -1 and pos < len(data) - 3:
        size = data[pos + 2]
        payload = data[pos + 3: pos + 3 + size]
        blocks.append((pos, size, payload))
        pos = data.find(b"\x21\xff", pos + 1)
    return blocks


def lsb_extract(data: bytes, channel: str = "rgb",
                lsb_index: int = 0) -> str | None:
    """Extract LSB-hidden text from an image using Pillow.

    Each channel byte contributes one bit (bit `lsb_index`). Bytes are
    assembled in order and decoding stops at the first null (0x00) byte,
    which conventionally terminates the hidden payload.
    """
    if not HAS_PIL:
        return None
    import io
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return None

    bits: list[int] = []
    pixels = list(img.getdata())[:200_000]
    for px in pixels:
        values = px[:3] if channel == "rgb" else (px[2],)
        for v in values:
            bits.append((v >> lsb_index) & 1)
    return _bits_to_text(bits)


def _bits_to_text(bits: list[int]) -> str | None:
    chars: list[str] = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        if byte == 0:
            break
        chars.append(chr(byte))
    text = "".join(chars)
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    if text and printable / max(len(text), 1) > 0.8:
        return text
    return None


def png_idat_verify(data: bytes) -> bool:
    """Try to decompress concatenated IDAT streams to validate correctness."""
    try:
        idat = b"".join(
            data[c.data_offset:c.data_offset + c.size]
            for c in analyze_png_chunks(data) if c.name == "IDAT"
        )
        zlib.decompress(idat)
        return True
    except Exception:
        return False


def stringscan(data: bytes, min_len: int = 4) -> list[str]:
    """Find printable ASCII strings in binary data."""
    result = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def hidden_strings(data: bytes) -> list[str]:
    """Strings that look like flags or interesting payloads."""
    import re
    found = []
    for s in stringscan(data):
        if re.search(r"flag\{|ctf\{|secret|password|key\s*=|FLAG|picoCTF",
                     s, re.IGNORECASE):
            found.append(s)
    return found
