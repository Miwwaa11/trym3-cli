# tryme

A small collection of CLI tools I built for solving CTF challenges. Covers crypto, forensics, and binary exploitation.

## Tools

| Tool | Category | What it does |
|------|----------|--------------|
| `autodecode` | Crypto | Tries multiple decodings (base64, rot13, caesar, etc.) and ranks them by confidence |
| `rsatool` | Crypto | Runs common RSA attacks — common factor, Wiener, Fermat, low exponent |
| `fscan` | Forensics | Checks file signatures against extensions, finds hidden data |
| `offsetfind` | Pwn | Finds buffer overflow offsets using cyclic patterns |

## Disclaimer

These tools are made for **legal CTF competitions and educational use only**. Don't use them on systems you don't own or have permission to test. I'm not responsible for any misuse.

## Installation

Requires Python 3.13+.

```bash
git clone <repo-url> && cd cli
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ./autodecode -e ./fscan -e ./rsatool -e ./offsetfind -e .
```

Or if you have `make`:

```bash
make setup
```

After installation, all tools are available as standalone commands. The `tryme` launcher provides an interactive menu:

```bash
tryme
```

## Usage

### Launcher

```bash
tryme
```

Pick a number, enter your text, get results. Type `C` to switch tools, `E` to quit.

### autodecode

```bash
autodecode "SGVsbG8gQ1RGIQ=="
autodecode --only-readable "VGhpcyBpcyBhIHRlc3Q="
echo "..." | autodecode
```

### rsatool

```bash
rsatool --n 12345... --e 3 --c 98765...
rsatool --input keys.json --attack wiener
rsatool --n 0x... --e 0x10001 --c 0x... --hex
```

### fscan

```bash
fscan suspicious.jpg
fscan ./folder --recursive --output json
fscan hidden.png --extract
```

### offsetfind

```bash
offsetfind ./vuln_binary
offsetfind ./vuln_binary --host target.ctf.com --port 1337
offsetfind ./vuln_binary --offset-only
```

Each tool has `--help` for the full option list.

