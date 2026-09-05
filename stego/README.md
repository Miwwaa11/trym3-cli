# stego

Steganography analysis and extraction tool for CTF challenges. Inspects PNG/GIF/JPEG/BMP files for hidden data in extra chunks, extension blocks, and embedded LSB payloads.

## Usage

```bash
stego suspicious.png
stego image.png --lsb
stego image.png --lsb --channel blue
stego image.png --strings
stego image.png --extract-dir ./out
```

Options:

- `--lsb` — attempt LSB hidden text extraction
- `--channel rgb|blue` — colour channel for LSB inspection
- `--strings` — dump printable strings
- `--extract-dir DIR` — where to save extracted payloads
- `--no-extract` — don't auto-extract extra chunks
