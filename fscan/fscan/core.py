"""Core logic: magic-byte database, matching, embedded-scan, and metadata."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

# --------------------------------------------------------------------------
# Signature database
# --------------------------------------------------------------------------

# Each entry: (name, mime, offset, bytes-pattern)
# offset may be None meaning "search anywhere for the pattern"
_SIGNATURES: list[tuple[str, str, Optional[int], bytes]] = [
    ("PNG image", "image/png", 0, b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", "image/jpeg", 0, b"\xff\xd8\xff"),
    ("GIF image", "image/gif", 0, b"GIF8"),
    ("BMP image", "image/bmp", 0, b"BM"),
    ("WEBP image", "image/webp", 8, b"WEBP"),
    ("ICO/cur icon", "image/x-icon", 0, b"\x00\x00\x01\x00"),
    ("TIFF image", "image/tiff", 0, b"II*\x00"),
    ("TIFF image", "image/tiff", 0, b"MM\x00*"),
    ("PSD image", "image/vnd.adobe.photoshop", 0, b"8BPS"),
    ("PDF document", "application/pdf", 0, b"%PDF-"),
    ("PostScript", "application/postscript", 0, b"%!PS"),
    ("ZIP archive", "application/zip", 0, b"PK\x03\x04"),
    ("ZIP archive (empty)", "application/zip", 0, b"PK\x05\x06"),
    ("Office OOXML (docx/xlsx/pptx)", "application/vnd.openxmlformats", 0,
     b"PK\x03\x04"),
    ("OLE2 / MS Office", "application/x-ole-storage", 0,
     b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("RAR archive", "application/x-rar", 0, b"Rar!\x1a\x07\x00"),
    ("RAR5 archive", "application/x-rar", 0, b"Rar!\x1a\x07\x01\x00"),
    ("7-Zip archive", "application/x-7z-compressed", 0, b"7z\xbc\xaf\x27\x1c"),
    ("gzip archive", "application/gzip", 0, b"\x1f\x8b"),
    ("bzip2 archive", "application/x-bzip2", 0, b"BZh"),
    ("xz archive", "application/x-xz", 0, b"\xfd7zXZ\x00"),
    ("Zstandard", "application/zstd", 0, b"\x28\xb5\x2f\xfd"),
    ("LZ4 archive", "application/x-lz4", 0, b"\x04\x22\x4d\x18"),
    ("tar archive", "application/x-tar", 257, b"ustar"),
    ("ISO 9660 disk image", "application/x-iso9660-image", 0x8001, b"CD001"),
    ("ELF executable", "application/x-executable", 0, b"\x7fELF"),
    ("PE executable", "application/x-dosexec", 0, b"MZ"),
    ("Mach-O binary", "application/x-mach-binary", 0, b"\xfe\xed\xfa\xce"),
    ("Mach-O 64 binary", "application/x-mach-binary", 0, b"\xfe\xed\xfa\xcf"),
    ("Mach-O binary (LE)", "application/x-mach-binary", 0, b"\xce\xfa\xed\xfe"),
    ("Mach-O 64 binary (LE)", "application/x-mach-binary", 0,
     b"\xcf\xfa\xed\xfe"),
    ("Java class", "application/java-vm", 0, b"\xca\xfe\xba\xbe"),
    ("DEX (Android)", "application/x-dex", 0, b"dex\n035\x00"),
    ("SQLite database", "application/x-sqlite3", 0, b"SQLite format 3\x00"),
    ("RIFF container", "application/riff", 0, b"RIFF"),
    ("WAV audio", "audio/wav", 8, b"WAVE"),
    ("AVI video", "video/x-msvideo", 8, b"AVI "),
    ("FLAC audio", "audio/flac", 0, b"fLaC"),
    ("MP3 audio (ID3)", "audio/mpeg", 0, b"ID3"),
    ("MP3 audio", "audio/mpeg", 0, b"\xff\xfb"),
    ("MP3 audio", "audio/mpeg", 0, b"\xff\xe3"),
    ("MP3 audio", "audio/mpeg", 0, b"\xff\xf3"),
    ("Ogg audio", "audio/ogg", 0, b"OggS"),
    ("MP4/MOV video", "video/mp4", 4, b"ftyp"),
    ("DICOM image", "application/dicom", 0x80, b"DICM"),
    ("MIDI file", "audio/midi", 0, b"MThd"),
    ("PCAP capture", "application/vnd.tcpdump.pcap", 0, b"\xd4\xc3\xb2\xa1"),
    ("PCAP capture (BE)", "application/vnd.tcpdump.pcap", 0, b"\xa1\xb2\xc3\xd4"),
    ("PCAPNG capture", "application/x-pcapng", 0, b"\x0a\x0d\x0d\x0a"),
    ("Java JAR (zip)", "application/java-archive", 0, b"PK\x03\x04"),
    ("Android APK (zip)", "application/vnd.android.package-archive", 0,
     b"PK\x03\x04"),
    ("Debian package (ar)", "application/vnd.debian.binary-package", 0,
     b"!<arch>\n"),
]

# Reliable embedded patterns (searched anywhere). Short/ambiguous patterns
# are excluded to avoid false positives inside random bytes.
_EMBED_SIGS: list[tuple[str, str, Optional[int], bytes]] = [
    ("PNG image", "image/png", None, b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", "image/jpeg", None, b"\xff\xd8\xff\xe0"),
    ("JPEG image", "image/jpeg", None, b"\xff\xd8\xff\xe1"),
    ("JPEG image", "image/jpeg", None, b"\xff\xd8\xff\xdb"),
    ("JPEG image", "image/jpeg", None, b"\xff\xd8\xff\xee"),
    ("GIF image", "image/gif", None, b"GIF89a"),
    ("GIF image", "image/gif", None, b"GIF87a"),
    ("PDF document", "application/pdf", None, b"%PDF-"),
    ("ZIP archive", "application/zip", None, b"PK\x03\x04"),
    ("RAR archive", "application/x-rar", None, b"Rar!\x1a\x07\x00"),
    ("7-Zip archive", "application/x-7z-compressed", None, b"7z\xbc\xaf\x27\x1c"),
    ("gzip archive", "application/gzip", None, b"\x1f\x8b\x08"),
    ("bzip2 archive", "application/x-bzip2", None, b"BZh"),
    ("xz archive", "application/x-xz", None, b"\xfd7zXZ\x00"),
    ("tar archive", "application/x-tar", None, b"ustar"),
    ("ELF executable", "application/x-executable", None, b"\x7fELF"),
    ("Mach-O binary", "application/x-mach-binary", None, b"\xfe\xed\xfa\xce"),
    ("Mach-O binary", "application/x-mach-binary", None, b"\xce\xfa\xed\xfe"),
    ("Mach-O 64", "application/x-mach-binary", None, b"\xfe\xed\xfa\xcf"),
    ("Mach-O 64", "application/x-mach-binary", None, b"\xcf\xfa\xed\xfe"),
    ("Java class", "application/java-vm", None, b"\xca\xfe\xba\xbe"),
    ("SQLite database", "application/x-sqlite3", None, b"SQLite format 3\x00"),
    ("FLAC audio", "audio/flac", None, b"fLaC"),
    ("Ogg audio", "audio/ogg", None, b"OggS"),
    ("MP4/MOV video", "video/mp4", None, b"ftyp"),
    ("PCAP capture", "application/vnd.tcpdump.pcap", None, b"\xd4\xc3\xb2\xa1"),
    ("PCAPNG capture", "application/x-pcapng", None, b"\x0a\x0d\x0d\x0a"),
    ("DOS/MBR boot sector", "application/x-disk-image", None,
     b"\x55\xaa\x00\x00"),
]


def detect_format(data: bytes, full_bytes: bool = False) -> list[tuple[str,
                                                                       str,
                                                                       int]]:
    """Return [(name, mime, offset)] for the first bytes of a buffer."""
    matches: list[tuple[str, str, int]] = []
    for name, mime, off, pat in _SIGNATURES:
        if off is None:
            continue
        if len(data) >= off + len(pat) and data[off:off + len(pat)] == pat:
            matches.append((name, mime, off))
    return matches


def detect_at_offset(data: bytes, sigs=None) -> list[tuple[int, str, str]]:
    """Find embedded signatures anywhere in `data`, deduping multiple
    patterns that hit the same offset (keep the longest/most specific)."""
    if sigs is None:
        sigs = _EMBED_SIGS
    hits: dict[int, tuple[int, str, str]] = {}
    for name, mime, off, pat in sigs:
        start = 0
        while True:
            idx = data.find(pat, start)
            if idx == -1:
                break
            prev = hits.get(idx)
            if prev is None or len(pat) > prev[0]:
                hits[idx] = (len(pat), name, mime)
            start = idx + 1
    return [(idx, name, mime) for idx, (_, name, mime) in sorted(hits.items())]


# --------------------------------------------------------------------------
# Extension expectation
# --------------------------------------------------------------------------

_EXPECTED_EXTS: dict[str, str] = {
    ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF",
    ".bmp": "BMP", ".webp": "WEBP", ".ico": "ICO/cur icon",
    ".tif": "TIFF", ".tiff": "TIFF", ".psd": "PSD", ".pdf": "PDF",
    ".zip": "ZIP", ".docx": "Office OOXML", ".xlsx": "Office OOXML",
    ".pptx": "Office OOXML", ".doc": "OLE2", ".xls": "OLE2", ".ppt": "OLE2",
    ".rar": "RAR", ".7z": "7-Zip", ".gz": "gzip", ".bz2": "bzip2",
    ".xz": "xz", ".zstd": "Zstandard", ".tar": "tar", ".iso": "ISO 9660",
    ".elf": "ELF", ".exe": "PE", ".dll": "PE", ".o": "ELF",
    ".so": "ELF", ".dex": "DEX", ".db": "SQLite", ".sqlite": "SQLite",
    ".wav": "WAV", ".avi": "AVI", ".flac": "FLAC", ".mp3": "MP3",
    ".ogg": "Ogg", ".mp4": "MP4/MOV", ".mov": "MP4/MOV", ".midi": "MIDI",
    ".mid": "MIDI", ".pcap": "PCAP", ".jar": "Java JAR", ".apk": "Android APK",
    ".json": None, ".txt": None, ".md": None, ".log": None,
}


@dataclass
class HiddenEmbed:
    offset: int
    name: str
    mime: str
    size: Optional[int] = None


@dataclass
class FileReport:
    path: str
    size: int
    detected: list[tuple[str, str, int]] = field(default_factory=list)
    mismatch: bool = False
    extension: str = ""
    expected: Optional[str] = None
    hidden: list[HiddenEmbed] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    exif: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def pretty_detected(self) -> str:
        return ", ".join(f"{n} (offset {o})" for n, _, o in self.detected) \
            if self.detected else "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "detected": [{"name": n, "mime": m, "offset": o}
                         for n, m, o in self.detected],
            "mismatch": self.mismatch,
            "extension": self.extension,
            "expected": self.expected,
            "hidden": [{"offset": h.offset, "name": h.name, "mime": h.mime}
                       for h in self.hidden],
            "strings": self.strings,
            "exif": self.exif,
            "metadata": self.metadata,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    return [m.decode("ascii", "ignore") for m in
            _STRING_RE.findall(data) if len(m) >= min_len]


def _host_signatures(data: bytes) -> set[tuple[int, str]]:
    """Identify the true signatures present at the very start of the file."""
    out = set()
    for name, mime, off, pat in _SIGNATURES:
        if off == 0 and data.startswith(pat):
            out.add((0, name))
    # PE check via MZ header + PE\0\0
    if data.startswith(b"MZ") and len(data) > 0x40:
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        if pe_off + 4 <= len(data) and \
                data[pe_off:pe_off + 4] == b"PE\x00\x00":
            out.add((0, "PE executable"))
    # RIFF subtypes
    if data.startswith(b"RIFF") and len(data) >= 12:
        sub = data[8:12]
        if sub == b"WAVE":
            out.add((0, "WAV audio"))
        elif sub == b"AVI ":
            out.add((0, "AVI video"))
    return out


def scan_bytes(data: bytes, filename: str, min_string_len: int = 6,
               with_strings: bool = True) -> FileReport:
    report = FileReport(path=filename, size=len(data))
    report.detected = detect_format(data)
    report.extension = os.path.splitext(filename)[1].lower()

    host = _host_signatures(data)

    # Independent embedded detection: signatures at offset > 0 (or text that
    # is not the host's own header).
    for idx, name, mime in detect_at_offset(data, sigs=_EMBED_SIGS):
        if (idx, name) in host:
            continue
        if any(d[2] == idx and d[0] == name for d in report.detected):
            continue
        report.hidden.append(HiddenEmbed(idx, name, mime))
    report.hidden.sort(key=lambda h: h.offset)

    # Mismatch: extension expectation vs detected real format
    report.expected = _EXPECTED_EXTS.get(report.extension)
    if report.expected is not None:
        real_names = {d[0] for d in report.detected}
        ok = False
        if real_names:
            expected_name = report.expected
            for real in real_names:
                if expected_name in real or real in expected_name:
                    ok = True
                    break
        report.mismatch = not ok

    if with_strings:
        for s in extract_strings(data, min_string_len):
            if s not in report.strings:
                report.strings.append(s)

    report.exif = extract_exif(data)
    report.metadata = extract_document_meta(data)
    return report


def scan_file(path: Path, min_string_len: int = 6, with_strings: bool = True,
              max_size: int = 512 * 1024 * 1024) -> Optional[FileReport]:
    """Stream-scan a single file; embedded-signature scan via chunk scanning
    with overlap so files up to 500MB stay low-memory."""
    size = path.stat().st_size
    if size > max_size:
        rep = FileReport(path=str(path), size=size)
        rep.notes.append(f"skipped: file > {max_size // (1024 * 1024)} MB")
        return rep

    if size <= 2 * 1024 * 1024:
        with path.open("rb") as f:
            data = f.read()
        return scan_bytes(data, str(path), min_string_len, with_strings)

    # streaming path: keep head for format detection + EXIF; scan body in
    # chunks for embedded signatures.
    head = bytearray()
    with path.open("rb") as f:
        head = bytearray(f.read(1 << 20))
        report = FileReport(path=str(path), size=size)
        report.detected = detect_format(bytes(head))
        report.extension = os.path.splitext(path.name)[1].lower()

        host = _host_signatures(bytes(head))
        found: dict[int, tuple[str, str]] = {}
        prev = b""
        chunk_sigs = set()
        skip = 0
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            window = prev + chunk
            base = skip - len(prev)
            for idx, name, mime in detect_at_offset(window, sigs=_EMBED_SIGS):
                pos = base + idx
                if pos < 0:
                    continue
                found.setdefault(pos, (name, mime))
            skip += len(chunk)
            prev = chunk[-64:]

        for pos, (name, mime) in sorted(found.items()):
            if pos == 0 and (name in {h[1] for h in host}):
                continue
            report.hidden.append(HiddenEmbed(pos, name, mime))

        report.expected = _EXPECTED_EXTS.get(report.extension)
        if report.expected is not None:
            real = {d[0] for d in report.detected}
            ok = False
            if real:
                for n in real:
                    if report.expected in n or n in report.expected:
                        ok = True
                        break
            report.mismatch = not ok

        if with_strings:
            report.strings = extract_strings(bytes(head), min_string_len)

        head = bytes(head)
        report.exif = extract_exif(head)
        report.metadata = extract_document_meta(head)
        return report


# --------------------------------------------------------------------------
# EXIF
# --------------------------------------------------------------------------


_PDF_META_FIELDS = [
    (b"Title", "Title"), (b"Author", "Author"), (b"Subject", "Subject"),
    (b"Creator", "Creator"), (b"Producer", "Producer"),
    (b"Keywords", "Keywords"),
]

_OOXML_META_FIELDS = [
    ("dc:title", "Title"), ("dc:creator", "Author"),
    ("dc:subject", "Subject"), ("dc:description", "Description"),
    ("dc:keywords", "Keywords"), ("cp:lastModifiedBy", "ModifiedBy"),
    ("Company", "Company"),
]


def extract_document_meta(data: bytes) -> dict:
    """Basic PDF / Office (OOXML) / OLE2 metadata, best-effort.

    Works on the file head (about 1MB) so it is safe on large files
    (streaming). Returns {} when the format is unknown or the metadata is
    empty.
    """
    try:
        if data.startswith(b"%PDF-"):
            meta = {"format": "PDF"}
            ver = re.search(rb"%PDF-(\d+\.\d+)", data[:64])
            if ver:
                meta["version"] = ver.group(1).decode("ascii", "ignore")
            for pat, label in _PDF_META_FIELDS:
                m = re.search(rb"/" + pat + rb"\s*\(([^)]*)\)", data[: 1 << 20])
                if m:
                    val = m.group(1).decode("latin-1", "replace").strip()
                    if val:
                        meta[label] = val
            return meta

        if data.startswith(b"PK\x03\x04") and \
                b"[Content_Types].xml" in data[: 1 << 20]:
            import io as _io
            import zipfile as _zip
            meta = {"format": "Office OOXML (docx/xlsx/pptx)"}
            try:
                with _zip.ZipFile(_io.BytesIO(data[: 1 << 20])) as zf:
                    for xml_name in ("docProps/core.xml", "docProps/app.xml"):
                        try:
                            xml = zf.read(xml_name).decode("utf-8", "replace")
                        except KeyError:
                            continue
                        for tag, label in _OOXML_META_FIELDS:
                            m = re.search(
                                r"<%s[^>]*>([^<]*)</%s>" % (re.escape(tag),
                                                            re.escape(tag)),
                                xml)
                            if m and m.group(1).strip():
                                meta[label] = m.group(1).strip()
            except Exception:
                pass
            return meta

        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return extract_ole_meta(data)
    except Exception:
        return {}
    return {}


_OLE_META_ATTRS = [
    ("title", "Title"), ("subject", "Subject"), ("author", "Author"),
    ("keywords", "Keywords"), ("comments", "Comments"),
    ("last_saved_by", "LastSavedBy"),
    ("creating_application", "CreatingApp"),
    ("revision_number", "Revision"),
]


def extract_ole_meta(data: bytes) -> dict:
    """OLE2 (.doc/.xls/.ppt) metadata via olefile. Falls back to format
    detection."""
    import io as _io

    meta = {"format": "OLE2 / MS Office"}
    try:
        import olefile
    except ImportError:
        return meta

    try:
        ole = olefile.OleFileIO(_io.BytesIO(data))
        try:
            si = ole.get_summaryinfo()
        except Exception:
            si = None
        if si is not None:
            for attr, label in _OLE_META_ATTRS:
                try:
                    v = getattr(si, attr)
                except Exception:
                    continue
                if v not in (None, ""):
                    s = str(v).strip()
                    if s:
                        meta[label] = s[:200]
        ole.close()
    except Exception:
        pass
    return meta


def extract_exif(data: bytes) -> dict:
    """Best-effort EXIF extraction via Pillow. Returns {} when unavailable."""
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return {}
    try:
        import io as _io
        img = Image.open(_io.BytesIO(data))
        exif = img.getexif()
        if not exif:
            return {}
        out = {}
        for k, v in exif.items():
            name = ExifTags.TAGS.get(k, str(k))
            if isinstance(v, (int, float, str)):
                out[name] = v
            else:
                out[name] = str(v)
        return out
    except Exception:
        return {}


# --------------------------------------------------------------------------
# Extraction / carving
# --------------------------------------------------------------------------


def carve_embedded(src: Path, outdir: Path) -> list[Path]:
    """Extract embedded payloads found at their offsets. Returns created
    files. Works for copied-concatenated payloads (e.g. file + appended zip).

    This uses a pragmatic strategy: signature at offset -> read to EOF into a
    new file named <name>_<offset>.<ext>.
    """
    created: list[Path] = []
    with src.open("rb") as f:
        data = f.read()
    for idx, name, mime in detect_at_offset(data, sigs=_EMBED_SIGS):
        if idx == 0:
            continue
        ext = _sig_ext(name)
        out = outdir / f"{src.name}_{idx}.{ext}"
        with out.open("wb") as of:
            of.write(data[idx:])
        created.append(out)
    return created


def _sig_ext(name: str) -> str:
    mapping = {
        "PNG": "png", "JPEG": "jpg", "GIF": "gif", "ZIP": "zip",
        "PDF": "pdf", "ELF": "elf", "RAR": "rar", "7-Zip": "7z",
        "gzip": "gz", "bzip2": "bz2", "xz": "xz", "tar": "tar",
        "SQLite": "db", "gif": "gif",
    }
    for k, v in mapping.items():
        if k in name:
            return v
    return "bin"


def collect_files(paths: Iterable[Path], recursive: bool = False) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    out.append(f)
                elif f.is_dir() and recursive:
                    out.extend(collect_files([f], recursive))
        elif p.is_file():
            out.append(p)
    return out