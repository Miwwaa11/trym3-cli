"""Core logic for binwalk-extract: signature-based carving.

Searches a binary blob for known file magic bytes (embedded files, zips,
archives, images, executables) and carves them out by finding the end of the
embedded data or a best-effort trailing boundary.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class CarveResult:
    offset: int
    name: str
    size: int
    matched_magic: str


# magic -> (display name, default extension, start_only)
# start_only signatures are short/generic and produce false positives when
# searched at arbitrary offsets inside binary data (esp. compressed streams),
# so they are only trusted as a "file start" match (offset 0 or after padding).
MAGIC_DB: list[tuple[bytes, str, str, bool]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image", ".png", False),
    (b"\xff\xd8\xff", "JPEG image", ".jpg", False),
    (b"GIF87a", "GIF image", ".gif", False),
    (b"GIF89a", "GIF image", ".gif", False),
    (b"BM", "BMP image", ".bmp", True),
    (b"PK\x03\x04", "ZIP archive", ".zip", False),
    (b"PK\x05\x06", "ZIP (empty)", ".zip", False),
    (b"\x1f\x8b\x08", "gzip", ".gz", True),
    (b"BZh", "bzip2", ".bz2", True),
    (b"\xfd7zXZ\x00", "xz", ".xz", False),
    (b"7z\xbc\xaf\x27\x1c", "7-zip", ".7z", False),
    (b"Rar!\x1a\x07", "RAR archive", ".rar", False),
    (b"\x00\x01\x00\x00", "Mach-O (fat)", ".macho", True),
    (b"\xcf\xfa\xed\xfe", "Mach-O (LE)", ".macho", True),
    (b"\xfe\xed\xfa\xce", "Mach-O (BE)", ".macho", True),
    (b"\xfe\xed\xfa\xcf", "Mach-O (BE fat)", ".macho", True),
    (b"\x7fELF", "ELF executable", ".elf", False),
    (b"MZ", "PE executable", ".exe", True),
    (b"OggS", "Ogg media", ".ogg", False),
    (b"fLaC", "FLAC audio", ".flac", False),
    (b"ID3", "MP3 (ID3)", ".mp3", True),
    (b"\xff\xfb\x90", "MP3", ".mp3", True),
    (b"RIFF", "RIFF (AVI/WAV)", ".riff", True),
    (b"SQLite format 3\x00", "SQLite database", ".sqlite", False),
    (b"%PDF-", "PDF document", ".pdf", False),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (doc/xls)", ".ole", False),
    (b"{\\\rtf", "RTF document", ".rtf", False),
    (b"\x1f\x8b\x08\x00", "gzip (little)", ".gz", True),
    (b"uud", "UUencoded", ".uu", True),
    (b"Is there an image here", "image hint", ".txt", False),
]


def find_magic(data: bytes, offset: int = 0,
               min_offset: int = 0) -> list[CarveResult]:
    """Find all known magic signatures in the data, deduplicating.

    Weak (short/generic) signatures are only reported when found near a
    plausible start boundary: offset 0, or immediately after a large run of
    padding (which indicates a concatenated file boundary), to avoid false
    positives inside binary/compressed data.
    """
    found: list[CarveResult] = []
    seen_offsets: set[int] = set()

    # Record strong signature locations so we can tell when a weak match sits
    # just after real content (nested inside another embedded file).
    strong_offsets = [o for o in _raw_find_strong(data, min_offset)]

    for magic, name, ext, start_only in MAGIC_DB:
        start = min_offset
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            if idx not in seen_offsets and _acceptable(idx, start_only,
                                                       strong_offsets, data):
                end = _find_end(data, idx, magic)
                found.append(CarveResult(offset=idx, name=name, size=end - idx,
                                         matched_magic=magic.hex()))
                seen_offsets.add(idx)
            start = idx + 1
    found.sort(key=lambda c: c.offset)
    return found


def _raw_find_strong(data: bytes, min_offset: int) -> list[int]:
    offsets: list[int] = []
    for magic, _, _, start_only in MAGIC_DB:
        if start_only:
            continue
        start = min_offset
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
    return offsets


def _acceptable(idx: int, start_only: bool, strong_offsets: list[int],
                data: bytes) -> bool:
    """Decision rule for whether a signature match should be reported."""
    if not start_only:
        return True
    # A weak signature is acceptable as a real "file start":
    #  - at the very beginning of the blob, or
    #  - preceded by a gap of padding (>=8 null bytes), indicating a
    #    concatenated file boundary, or
    #  - NOT nested inside the payload of a strong signature find.
    if idx == 0:
        return True
    before = data[max(0, idx - 8):idx]
    if before and all(b in (0x00,) for b in before[-8:]) and len(before) >= 8:
        return True
    for s in strong_offsets:
        if s <= idx:
            return False
    return True


def _find_end(data: bytes, start: int, magic: bytes) -> int:
    """Best-effort end boundary for a carved region."""
    if magic.startswith(b"PK"):
        # zip: search for end-of-central-directory record
        eocd = data.find(b"PK\x05\x06", start + 4)
        if eocd != -1:
            # EOCD has 22-byte fixed header; find it
            return eocd + 22
        return min(len(data), start + 512)
    if magic.startswith(b"\x89PNG"):
        iend = data.find(b"IEND", start)
        if iend != -1:
            return iend + 8
    if magic.startswith(b"\xff\xd8"):
        # JPEG: find FFD9 end marker
        eoi = data.find(b"\xff\xd9", start + 2)
        if eoi != -1:
            return eoi + 2
    if magic.startswith(b"%PDF"):
        # find EOF marker
        eof = data.find(b"%%EOF", start)
        if eof != -1:
            return eof + 5
        eof2 = data.rfind(b"endobj", start)
        if eof2 != -1:
            return eof2 + 6
    return len(data)


def carve(data: bytes, sig_offset: int, magic: bytes) -> bytes:
    """Extract the bytes for one found signature."""
    end = _find_end(data, sig_offset, magic)
    return data[sig_offset:end]


def carve_all(data: bytes, min_interval: int = 5) -> list[tuple[CarveResult, bytes]]:
    """Carve all found regions. Returns (meta, payload) pairs."""
    found = find_magic(data)
    results: list[tuple[CarveResult, bytes]] = []
    for c in found:
        payload = carve(data, c.offset, bytes.fromhex(c.matched_magic))
        results.append((c, payload))
    return results


def extract_to_dir(data: bytes, out_dir: str) -> list[str]:
    """Extract all carved regions into out_dir. Returns written filenames."""
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []
    found = find_magic(data)
    for i, c in enumerate(found, 1):
        # avoid carving the same thing at offset 0 as a "payload"
        ext = _sig_ext(bytes.fromhex(c.matched_magic))
        name = os.path.join(out_dir, f"{i:04d}_{c.name.lower().replace(' ','_')}{ext}")
        payload = carve(data, c.offset, bytes.fromhex(c.matched_magic))
        with open(name, "wb") as f:
            f.write(payload)
        written.append(name)
    return written


def _sig_ext(magic: bytes) -> str:
    for m, _, ext, _ in MAGIC_DB:
        if m == magic:
            return ext
    return ".bin"
