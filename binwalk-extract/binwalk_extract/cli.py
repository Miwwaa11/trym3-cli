"""CLI entry point for binwalk-extract."""

from __future__ import annotations

import os

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import carve_all, extract_to_dir, find_magic


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--extract", "-e", "extract_dir", type=click.Path(file_okay=False),
              help="Extract carved files into this directory.")
@click.option("--offset", type=click.IntRange(0, 2 ** 40), default=0,
              help="Skip initial bytes before scanning.")
@click.option("--no-color", "no_color", is_flag=True,
              help="Disable colors.")
@click.version_option(__version__, prog_name="binwalk-extract")
def main(path, extract_dir, offset, no_color):
    """Scan a file for embedded/concatenated files and optionally extract them."""
    console = Console(highlight=False,
                      color_system=("standard" if not no_color else None))
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read()

    console.print(f"[bold cyan]Scanning[/bold cyan] [green]{path}[/green] "
                  f"({size:,} bytes)\n")

    results = find_magic(data)
    if not results:
        console.print("[yellow]No known signatures found.[/yellow]")
        return

    table = Table(title="Embedded Files Found")
    table.add_column("Offset", justify="right", style="bold cyan")
    table.add_column("Name", style="green")
    table.add_column("Size", justify="right")
    for c in results:
        table.add_row(f"0x{c.offset:x} ({c.offset})", c.name, str(c.size))
    console.print(table)

    if extract_dir:
        written = extract_to_dir(data, extract_dir)
        console.print(f"\n[green]Extracted {len(written)} file(s) "
                      f"to {extract_dir}:[/green]")
        for w in written:
            console.print(f"  [cyan]*[/cyan] {w}")


if __name__ == "__main__":
    main()
