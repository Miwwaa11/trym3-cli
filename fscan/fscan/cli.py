"""CLI entry point for fscan."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import collect_files, scan_file


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", required=True, type=click.Path(path_type=Path))
@click.option("--recursive", is_flag=True,
              help="Scan folders recursively.")
@click.option("--output", "output", type=click.Choice(["table", "json"]),
              default="table", show_default=True, help="Output format.")
@click.option("--extract", "extract", is_flag=True,
              help="Extract detected hidden files.")
@click.option("--strings-min", "strings_min", type=click.IntRange(4, 4096),
              default=6, show_default=True,
              help="Minimum length for embedded strings to extract.")
@click.option("--no-strings", "no_strings", is_flag=True,
              help="Disable string extraction.")
@click.option("--no-color", "no_color", is_flag=True, help="Disable colors.")
@click.version_option(__version__, prog_name="fscan")
def main(path, recursive, output, extract, strings_min, no_strings, no_color):
    """Scan files/folders for magic bytes, metadata, and hidden files."""
    console = Console(highlight=False, color_system=("standard" if not no_color
                                                     else None))

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = collect_files([path], recursive=recursive)
        if not files:
            console.print("[red]Error:[/red] folder contains no "
                          "readable files.")
            raise SystemExit(1)
    else:
        console.print(f"[red]Error:[/red] path not found: {path}")
        raise SystemExit(1)

    reports = []
    with console.status(f"[cyan]Scanning {len(files)} files...[/cyan]",
                        spinner="dots"):
        for f in files:
            rep = scan_file(f, min_string_len=strings_min,
                            with_strings=not no_strings)
            if rep is not None:
                reports.append(rep)

    if extract:
        _do_extract(console, reports, path)

    if output == "json":
        _print_json(console, reports)
    else:
        _print_table(console, reports, extract)


def _do_extract(console, reports, base):
    from .core import carve_embedded
    for rep in reports:
        if not rep.hidden:
            continue
        src = Path(rep.path)
        if not src.is_file():
            continue
        outdir = src.with_name(src.name + "_extracted")
        outdir.mkdir(exist_ok=True)
        try:
            created = carve_embedded(src, outdir)
            if created:
                console.print(f"[green][+] Extracted {src.name}[/green] → "
                              f"{len(created)} files into {outdir}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[red][!] Failed to extract {src.name}: {e}[/red]")


def _print_json(console, reports):
    console.print_json(data=[r.to_dict() for r in reports], indent=2)


def _print_table(console, reports, show_extract_hint):
    table = Table(title=f"fscan report ({len(reports)} files)")
    table.add_column("File", style="bold")
    table.add_column("Size", justify="right")
    table.add_column("Extension", justify="center")
    table.add_column("Magic Detect", style="cyan")
    table.add_column("Status")
    table.add_column("Hidden Files")
    table.add_column("Strings", justify="right")
    table.add_column("EXIF", justify="right")

    for rep in sorted(reports, key=lambda r: r.path):
        status = "[green]OK[/green]"
        if rep.mismatch:
            status = "[red]MISMATCH![/red]"
        elif rep.notes:
            status = "[yellow]-[/yellow]"

        magic = rep.pretty_detected
        hidden = ", ".join(f"{h.name}@{h.offset}" for h in rep.hidden) or "-"
        exif_n = str(len(rep.exif))
        table.add_row(
            rep.path,
            _human_size(rep.size),
            rep.extension or "-",
            magic,
            status,
            hidden,
            str(len(rep.strings)),
            exif_n,
        )

        if rep.mismatch:
            table.add_row("", "", "", "", "", "", "", "", style="dim")
            table.add_row(f"[dim]  ext={rep.extension} suggests "
                          f"{rep.expected}, actual magic: {magic}[/dim]",
                          "", "", "", "", "", "", "", style="dim")

    console.print(table)

    for rep in reports:
        if rep.exif:
            console.print(f"\n[bold cyan]EXIF — {rep.path}[/bold cyan]")
            for k, v in list(rep.exif.items())[:25]:
                console.print(f"  [green]{k}:[/green] {v}")
        if rep.metadata:
            console.print(f"\n[bold cyan]Metadata — {rep.path}[/bold cyan]")
            for k, v in list(rep.metadata.items())[:20]:
                console.print(f"  [green]{k}:[/green] {v}")
        if rep.strings and not show_extract_hint:
            console.print(f"\n[bold cyan]Strings — {rep.path}[/bold cyan] "
                          f"({len(rep.strings)} found)")
            for s in rep.strings[:20]:
                display = s if len(s) <= 120 else s[:120] + "…"
                console.print(f"  [dim]{display}[/dim]")
            if len(rep.strings) > 20:
                console.print(f"  [dim]... and "
                              f"{len(rep.strings) - 20} more "
                              f"(--strings-min to narrow down)[/dim]")


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.0f}TB"


if __name__ == "__main__":
    main()