# netcat-recon

Simple network reconnaissance tool: TCP connect scan with banner grabbing. Useful for quickly profiling a CTF target.

## Usage

```bash
netcat-recon 10.0.0.5
netcat-recon host.example.com -p 22,80,443
netcat-recon 10.0.0.5 -p 1-1000
netcat-recon 10.0.0.5 --all --threads 256
```

Options:

- `-p, --port SPEC` — comma/range list, e.g. `22,80,1000-2000`
- `--all` — scan ports 1-65535 (slow)
- `--timeout SEC` — per-port timeout
- `--threads N` — concurrent scan threads
