"""Tests for the fscan core."""

import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from fscan.core import (collect_files, detect_at_offset, detect_format,
                        scan_bytes, scan_file)

import fscan.core as core

PNG = b"\x89PNG\r\n\x1a\n" + struct.pack(">II", 13, 0x49484452) + b"payload"


class TestDetection(unittest.TestCase):
    def test_detect_png(self):
        res = detect_format(PNG)
        self.assertTrue(any("PNG" in n for n, _, _ in res))

    def test_detect_jpeg(self):
        self.assertTrue(any("JPEG" in n for n, _, _ in
                            detect_format(b"\xff\xd8\xff\xe0test")))

    def test_detect_elf(self):
        self.assertTrue(any("ELF" in n for n, _, _ in
                            detect_format(b"\x7fELF\x02\x01\x01")))

    def test_detect_pdf(self):
        self.assertTrue(any("PDF" in n for n, _, _ in
                            detect_format(b"%PDF-1.7")))

    def test_detect_zip(self):
        self.assertTrue(any("ZIP" in n for n, _, _ in
                            detect_format(b"PK\x03\x04restofzip")))


class TestMismatch(unittest.TestCase):
    def test_mismatch_detected(self):
        rep = scan_bytes(PNG, "fake.jpg")
        self.assertTrue(rep.mismatch)
        self.assertEqual(rep.extension, ".jpg")

    def test_correct_ext_ok(self):
        rep = scan_bytes(PNG, "real.png")
        self.assertFalse(rep.mismatch)

    def test_unknown_ext_not_flagged(self):
        rep = scan_bytes(PNG, "file.data")
        self.assertFalse(rep.mismatch)


class TestHiddenEmbed(unittest.TestCase):
    def make_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("secret.txt", "S3CR3T_F13")
        return buf.getvalue()

    def test_embedded_zip_found(self):
        data = PNG + self.make_zip()
        rep = scan_bytes(data, "hidden.png")
        self.assertTrue(any("ZIP" in h.name for h in rep.hidden))
        target = [h for h in rep.hidden if "ZIP" in h.name][0]
        self.assertEqual(target.offset, len(PNG))

    def test_no_false_positive_on_clean(self):
        rep = scan_bytes(PNG, "clean.png")
        self.assertEqual(rep.hidden, [])

    def test_dedup_same_offset(self):
        data = b"PK\x03\x04" + b"\x00" * 20
        hits = detect_at_offset(data)
        # only one entry for PK\x03\x04 alias-free
        self.assertEqual(len([h for h in hits if h[0] == 0]), 1)


class TestStrings(unittest.TestCase):
    def test_extract_strings(self):
        rep = scan_bytes(b"hello world\x00\x00FLAG{abc}", "f.bin")
        self.assertTrue(any("FLAG{abc}" in s for s in rep.strings))
        self.assertTrue(any("hello world" in s for s in rep.strings))

    def test_strings_disabled(self):
        rep = scan_bytes(b"zhidden stringz", "f.bin", with_strings=False)
        self.assertEqual(rep.strings, [])


class TestFileScan(unittest.TestCase):
    def test_scan_file_streaming_large(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.bin"
            with p.open("wb") as f:
                f.write(b"Z" * 3_000_000)
                f.write(b"ustar")  # embedded tar marker
            rep = scan_file(p)
            self.assertEqual(rep.size, 3_000_005)
            self.assertTrue(any("tar" in h.name.lower() for h in rep.hidden))

    def test_collect_files_recursive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.txt").write_text("a")
            sub = root / "sub"
            sub.mkdir()
            (sub / "b.txt").write_text("b")
            flat = collect_files([root], recursive=False)
            self.assertEqual(len(flat), 1)
            allf = collect_files([root], recursive=True)
            self.assertEqual(len(allf), 2)


class TestDocumentMetadata(unittest.TestCase):
    def test_pdf_metadata(self):
        data = b"%PDF-1.7\n" + b"/Title (Secret Doc)\n/Author (Alice)\n%%EOF\n"
        rep = scan_bytes(data, "report.pdf")
        self.assertEqual(rep.metadata.get("format"), "PDF")
        self.assertEqual(rep.metadata.get("version"), "1.7")
        self.assertEqual(rep.metadata.get("Title"), "Secret Doc")
        self.assertEqual(rep.metadata.get("Author"), "Alice")

    def test_ooxml_metadata(self):
        buf = io.BytesIO()
        ns = 'xmlns:dc="http://purl.org/dc/elements/1.1/" ' \
             'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr(
                "docProps/core.xml",
                f'<?xml version="1.0"?><cp:coreProperties {ns}><dc:title>'
                f'JOINT REPORT</dc:title><dc:creator>Rizky</dc:creator>'
                f'</cp:coreProperties>',
            )
            zf.writestr("word/document.xml", "<w:document/>")
        rep = scan_bytes(buf.getvalue(), "laporan.docx")
        self.assertIn("Office OOXML", rep.metadata.get("format", ""))
        self.assertEqual(rep.metadata.get("Title"), "JOINT REPORT")
        self.assertEqual(rep.metadata.get("Author"), "Rizky")

    def test_ooxml_metadata_no_docprops(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<w:document/>")
        rep = scan_bytes(buf.getvalue(), "plain.docx")
        self.assertEqual(rep.metadata.get("format"), "Office OOXML (docx/xlsx/pptx)")
        self.assertNotIn("Title", rep.metadata)

    def test_ole2_minimal(self):
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32
        rep = scan_bytes(data, "kuno.doc")
        self.assertEqual(rep.metadata.get("format"), "OLE2 / MS Office")

    def test_ole_metadata_fields(self):
        class FakeSum:
            title = "KLASIFIKASI"
            author = "Paklek"
            subject = ""
            keywords = None
            last_saved_by = "Paklek"

        class FakeOle:
            def __init__(self, buf):
                self.sum = FakeSum()

            def get_summaryinfo(self):
                return self.sum

            def close(self):
                pass

        old = sys.modules.get("olefile")
        sys.modules["olefile"] = type("olefile", (), {"OleFileIO": FakeOle})
        try:
            data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
            rep = scan_bytes(data, "rahasia.doc")
        finally:
            if old is None:
                del sys.modules["olefile"]
            else:
                sys.modules["olefile"] = old

        self.assertEqual(rep.metadata.get("format"), "OLE2 / MS Office")
        self.assertEqual(rep.metadata.get("Title"), "KLASIFIKASI")
        self.assertEqual(rep.metadata.get("Author"), "Paklek")
        self.assertNotIn("Subject", rep.metadata)

    def test_unknown_returns_empty_metadata(self):
        rep = scan_bytes(b"just some plain ascii text", "catatan.txt")
        self.assertEqual(rep.metadata, {})


if __name__ == "__main__":
    unittest.main()