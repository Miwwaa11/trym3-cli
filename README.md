# tryme

A small collection of CLI tools I built for solving CTF challenges. Covers crypto, forensics, and binary exploitation.

## Tools

| Tool | Category | What it does |
|------|----------|--------------|
| `autodecode` | Crypto | Tries multiple decodings (base64, rot13, caesar, etc.) and ranks them by confidence |
| `rsatool` | Crypto | Runs common RSA attacks — common factor, Wiener, Fermat, low exponent |
| `fscan` | Forensics | Checks file signatures against extensions, finds hidden data |
| `offsetfind` | Pwn | Finds buffer overflow offsets using cyclic patterns |
| `hashcrack` | Crypto | Identifies hash types and cracks them with a wordlist or brute force |
| `stego` | Forensics | Steganography analysis — extra PNG chunks, GIF blocks, LSB extraction |
| `revshell` | Exploit | Generates reverse shell payloads in many languages |
| `netcat-recon` | Recon | TCP port scan with banner grabbing and service detection |
| `binwalk-extract` | Forensics | Carves embedded/concatenated files by magic signature |
| `z3-solver` | Reversing | Helper for solving reversing constraints with Z3 |

## Disclaimer

These tools are made for **legal CTF competitions and educational use only**. Don't use them on systems you don't own or have permission to test. I'm not responsible for any misuse.

## Installation

Requires Python 3.13+.

```bash
git clone <repo-url> && cd cli
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ./autodecode -e ./fscan -e ./rsatool -e ./offsetfind \
    -e ./hashcrack -e ./stego -e ./revshell -e ./netcat-recon \
    -e ./binwalk-extract -e ./z3-solver -e .
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

### hashcrack

```bash
hashcrack 5d41402abc4b2a76b9719d911017c592
hashcrack <hash> -w rockyou.txt
hashcrack <hash> --type SHA-256 --wordlist words.txt
hashcrack --list
```

### stego

```bash
stego image.png
stego image.png --lsb --channel blue
stego image.png --strings --extract-dir ./out
```

### revshell

```bash
revshell --ip 10.0.0.5 --port 4444
revshell -i 10.0.0.5 -p 4444 --lang python
```

### netcat-recon

```bash
netcat-recon 10.0.0.5
netcat-recon host.example.com -p 22,80,443
netcat-recon 10.0.0.5 -p 1-1000 --threads 256
```

### binwalk-extract

```bash
binwalk-extract firmware.bin
binwalk-extract suspicious.bin --extract ./out
```

### z3-solver

```bash
z3-solver --print-vars 20
z3-solver --template
```

> Note: `z3-solver` requires `pip install z3-solver` (or `pip install -e ./z3-solver[solve]`).

Each tool has `--help` for the full option list.

