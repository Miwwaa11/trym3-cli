# hashcrack

Hash identifier and cracker for CTF challenges. Auto-detects common hash types (MD5, SHA-1/256/512, bcrypt, NTLM, etc.) and cracks them with a wordlist or brute force.

## Usage

```bash
hashcrack <hash>
hashcrack <hash> --wordlist rockyou.txt
hashcrack <hash> --type SHA-256 --wordlist words.txt
hashcrack --list
echo <hash> | hashcrack -w words.txt
```

Options:

- `-w, --wordlist FILE` — crack against a wordlist
- `-t, --type TYPE` — force a specific hash type
- `--brute CHARSET LEN` — brute-force (slow)
- `--list` — show known hash types
