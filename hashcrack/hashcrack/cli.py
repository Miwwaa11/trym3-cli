"""CLI entry point for hashcrack."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import HASH_PATTERNS, MAILCHIMP_LOOKUP, brute_force, crack_hash, identify_hash


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("hash_str", required=False)
@click.option("--wordlist", "-w", "wordlist_path", type=click.Path(exists=True, dir_okay=False),
              help="Path to wordlist file for cracking.")
@click.option("--type", "-t", "hash_type", type=click.Choice(list(MAILCHIMP_LOOKUP.keys())),
              help="Force specific hash type (default: auto-detect).")
@click.option("--brute", "brute_args", nargs=2, type=(str, int),
              help="Brute-force: --brute <charset> <maxlen>. Slow!")
@click.option("--list", "list_types", is_flag=True, help="List known hash types.")
@click.option("--no-color", "no_color", is_flag=True, help="Disable colors.")
@click.version_option(__version__, prog_name="hashcrack")
def main(hash_str, wordlist_path, hash_type, brute_args, list_types, no_color):
    """Identify and crack hashes. Input via argument or stdin (pipe)."""
    console = Console(highlight=False, color_system=("standard" if not no_color else None))

    if list_types:
        _show_types(console)
        return

    if hash_str is None:
        data = click.get_text_stream("stdin").read()
        if not data:
            console.print("[red]Error:[/red] no input provided. Give a hash "
                          "argument or pipe stdin.", style="bold red")
            raise SystemExit(1)
        hash_str = data.strip()

    _identify(console, hash_str)

    if wordlist_path:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        console.print(f"[cyan]Cracking against {len(words):,} words...[/cyan]")
        result = crack_hash(hash_str, words, hash_type)
        if result:
            console.print(f"[green][+] Found:[/green] {result}")
        else:
            console.print("[yellow][-] No match found in wordlist.[/yellow]")

    if brute_args:
        charset, maxlen = brute_args
        console.print(f"[cyan]Brute-forcing charset={charset!r} up to "
                      f"{maxlen} chars... (may be very slow)[/cyan]")
        result = brute_force(hash_str, charset, maxlen, hash_type)
        if result:
            console.print(f"[green][+] Found:[/green] {result}")
        else:
            console.print("[yellow][-] No match found by brute force.[/yellow]")


def _identify(console, hash_str):
    matches = identify_hash(hash_str)
    if not matches:
        console.print("[yellow]Could not identify hash type.[/yellow]")
        return
    console.print(f"\n[bold cyan]Input hash:[/bold cyan] {hash_str}")
    console.print(f"[bold]Identified:[/bold] {', '.join(m.name for m in matches)}")


def _show_types(console):
    table = Table(title="Known Hash Types")
    table.add_column("Name", style="bold cyan")
    table.add_column("Regex Pattern", overflow="fold")
    table.add_column("Crackable", justify="center")
    for m in HASH_PATTERNS:
        crackable = "yes" if m.name in MAILCHIMP_LOOKUP else "-"
        table.add_row(m.name, m.regex, crackable)
    console.print(table)


if __name__ == "__main__":
    main()
