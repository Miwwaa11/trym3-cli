# Multi-Cipher Auto-Decoder

A CLI tool that tries many decoding methods at once, chains layered decodes
together, and gives each result a confidence score so the best candidate is
easy to spot.

## Installation

```bash
pip install -e .
```

Dependencies: `click`, `rich` (bundled local dictionary wordlist).

## Usage

```bash
autodecode "SGVsbG8gQ1RGIQ=="
autodecode --only-readable --max-depth 3 "..."
echo "..." | autodecode
```

Main options:

| Option | Description |
|--------|-------------|
| `TEXT` | Ciphertext as a positional argument |
| `--only-readable` | Only show high-confidence results |
| `--max-depth N` | Maximum chaining iterations (default 5) |
| `--min-score F` | Confidence threshold 0.0–1.0 |
| `--no-color` | Disable colored output |

Supported methods: Base64, Base32, Base16/Hex, ROT13, ROT47, Morse Code,
Binary, URL Encoding, HTML entities, and Caesar cipher (all 25 shifts).