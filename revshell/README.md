# revshell

Reverse shell payload generator for CTF exploitation. Produces working one-liners in bash, python, php, ruby, perl, netcat, socat, java, lua, and more. Use only against systems you are authorized to test.

## Usage

```bash
revshell --ip 10.0.0.5 --port 4444
revshell -i 10.0.0.5 -p 4444 --lang python
revshell -i 10.0.0.5 -p 4444 -l php
```

Options:

- `-i, --ip IP` — listener IP (required)
- `-p, --port PORT` — listener port (required)
- `-l, --lang LANG` — filter by language (`all`, `bash`, `python`, `php`, ...)
