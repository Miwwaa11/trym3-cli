# binwalk-extract

Binary file carving tool — a lightweight binwalk alternative. Scans a blob for known file signatures (images, archives, executables, documents) and extracts embedded/concatenated files.

## Usage

```bash
binwalk-extract firmware.bin
binwalk-extract suspicious.bin --extract ./out
binwalk-extract mystery.png --extract ./carved
```

Options:

- `-e, --extract DIR` — extract carved files into a directory
- `--offset N` — skip initial bytes before scanning
