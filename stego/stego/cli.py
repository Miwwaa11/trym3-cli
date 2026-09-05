"""CLI entry point for stego."""

from __future__ import annotations

import os

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import (detect_format, extract_extra_chunks, hidden_strings,
                   list_extra_chunks, lsb_extract, parse_gif_blocks,
                   png_idat_verify, stringscan)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--extract-dir", "extract_dir", type=click.Path(file_okay=False),
              default="./stego_out", show_default=True,
              help="Directory for extracted payloads.")
@click.option("--lsb", "do_lsb", is_flag=True,
              help="Attempt LSB extraction from the image.")
@click.option("--channel", type=click.Choice(["rgb", "blue"]), default="rgb",
              help="Colour channel to inspect for LSB.")
@click.option("--strings", "do_strings", is_flag=True,
              help="Dump printable strings from the file.")
@click.option("--no-extract", "no_extract", is_flag=True,
              help="Disable automatic extra-chunk extraction.")
@click.option("--no-color", "no_color", is_flag=True,
              help="Disable colors.")
@click.version_option(__version__, prog_name="stego")
def main(path, extract_dir, do_lsb, channel, do_strings, no_extract, no_color):
    """Analyze images for hidden (steganographic) data."""
    console = Console(highlight=False,
                      color_system=("standard" if not no_color else None))

    with open(path, "rb") as f:
        data = f.read()

    fmt = detect_format(data) or "unknown"
    console.print(f"[bold cyan]File:[/bold cyan] {path} "
                  f"({os.path.getsize(path):,} bytes) "
                  f"[green]{fmt}[/green]")

    if fmt == "png":
        _png(console, data, path, extract_dir, not no_extract)
    elif fmt == "gif":
        _gif(console, data)
    elif fmt in ("jpeg", "bmp"):
        console.print("[cyan]Basic format. Use --lsb and --strings.[/cyan]")
    else:
        console.print("[yellow]Unrecognized image format; falling back "
                      "to scans.[/yellow]")

    if do_strings or fmt == "unknown":
        _strings(console, data)

    if do_lsb and fmt in ("png", "jpeg", "bmp"):
        text = lsb_extract(data, channel=channel)
        if text:
            console.print(f"[green][+] LSB hidden text:[/green] {text!r}")
        else:
            console.print("[yellow][-] No readable LSB text found.[/yellow]")

    hidden = hidden_strings(data)
    if hidden:
        console.print("\n[bold magenta]Potential flags/interesting strings:[/bold magenta]")
        for s in hidden[:20]:
            console.print(f"  [magenta]*[/magenta] {s!r}")


def _png(console, data, path, extract_dir, do_extract):
    chunks = list_extra_chunks(data)
    if chunks:
        console.print(f"\n[bold]Non-standard PNG chunks found:[/bold] "
                      f"{len(chunks)}")
        table = Table(title="Extra PNG Chunks")
        table.add_column("Chunk", style="bold cyan")
        table.add_column("Offset")
        table.add_column("Size")
        for c in chunks:
            table.add_row(c.name, str(c.offset), str(c.size))
        console.print(table)

        if do_extract:
            payloads = extract_extra_chunks(data)
            os.makedirs(extract_dir, exist_ok=True)
            for name, payload in payloads.items():
                out = os.path.join(extract_dir, f"{name}.bin")
                with open(out, "wb") as f:
                    f.write(payload)
                console.print(f"[green][+] Extracted[/green] {name} -> {out} "
                              f"({len(payload):,} bytes)")
    else:
        console.print("[yellow]No extra PNG chunks.[/yellow]")

    if not png_idat_verify(data):
        console.print("[red][!] PNG IDAT streams fail to decompress — "
                      "possibly corrupted/obfuscated.[/red]")


def _gif(console, data):
    blocks = parse_gif_blocks(data)
    if blocks:
        console.print(f"\n[bold]GIF application extension blocks:[/bold] "
                      f"{len(blocks)}")
        for i, (offset, size, payload) in enumerate(blocks, 1):
            console.print(f"  [cyan]#{i}[/cyan] offset={offset} size={size} "
                          f"payload={payload!r}")


def _strings(console, data):
    strings = stringscan(data)
    if strings:
        console.print(f"\n[bold]Strings ({len(strings)}):[/bold]")
        for s in strings[:50]:
            console.print(f"  {s!r}")
    else:
        console.print("[yellow]No strings found.[/yellow]")


if __name__ == "__main__":
    main()
