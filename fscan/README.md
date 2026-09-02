# fscan — File Signature & Metadata Scanner

Detects mismatches between a file's extension and its real magic bytes,
extracts metadata, finds files hidden inside other files, and (optionally)
extracts them.

## Installation

```bash
pip install -e .
```

Dependencies: `click`, `rich`, `Pillow` (image EXIF), `olefile` (OLE metadata).
Magic-byte detection does not need `libmagic`/`python-magic` — the signature
database is bundled.

## Usage

```bash
fscan suspicious.jpg
fscan ./forensics_folder --recursive
fscan hidden.png --extract
fscan ./folder --output json
```

Main options:

| Option | Description |
|--------|-------------|
| `PATH` | Single file or folder |
| `--recursive` | Scan folders recursively |
| `--output {table,json}` | Output format (default table) |
| `--extract` | Extract detected hidden files into `./<file>_extracted/` |
| `--strings-min MIN` | Minimum length for embedded strings (default 6) |
| `--no-strings` | Disable string extraction |

Supported magic-byte formats: PNG, JPEG, GIF, BMP, WEBP, PDF, ZIP/OOXML,
RAR, 7z, gzip, bzip2, xz, tar, ELF, PE, Mach-O, RIFF/WAV/AVI, FLAC, MP3, OGG,
MP4, SQLite, Java class, PSD, ICO, TIFF, MIDI, PCAP(NG), OLE/doc.