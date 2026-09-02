# offsetfind — Buffer Overflow Offset Finder

Generates a cyclic pattern, runs the binary (locally or against a remote
service), captures the crash, and computes the buffer overflow offset
automatically. It also runs `checksec` to review the binary's protections.

## Installation

```bash
pip install -e .
```

Dependencies: `click`, `rich`, `pwntools`.

## Usage

```bash
offsetfind ./vuln_binary
offsetfind ./vuln_binary --host target.ctf.com --port 1337
offsetfind ./vuln_binary --pattern-length 2048
```

Main options:

| Option | Description |
|--------|-------------|
| `BINARY` | Path to the local binary |
| `--host`, `--port` | Remote target service |
| `--pattern-length N` | Cyclic pattern length (default 1024) |
| `--timeout SEC` | Process/connection timeout (default 5) |
| `--no-checksec` | Skip the protection check |
| `--offset-only` | Only print the offset (compact output) |

## Output

For a local binary, the offset can be fully computed from the crash plus the
core dump, including the base address for PIE binaries:

```text
Buffer overflow offset: 40

Fault address : 0x6161616161616166
RIP           : 0x55b4187e61a0
RSP           : 0x7ffed4d43b78

Base address (PIE) : 0x55b4187e5000
```

For a remote target, the offset is still computed from the local binary (if
given); the remote connection is only used to confirm that the payload
crashes the service (the connection drops). Without a local binary,
`offsetfind` can only report the remote status, not the offset value.