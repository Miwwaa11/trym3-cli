"""CLI entry point for rsatool."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .core import (RSAParams, int_to_bytes, load_keys_from_json, run_all)


def _parse_int(s: str, is_hex: bool) -> int:
    s = s.strip()
    if is_hex or s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--n", "n", default=None, help="Modulus n (int or hex).")
@click.option("--e", "e", default=None, help="Public exponent e.")
@click.option("--c", "c", default=None, help="Ciphertext c.")
@click.option("--input", "input_file", type=click.Path(exists=True,
                                                       path_type=object),
              help="JSON file containing keys (supports multiple n).")
@click.option("--attack", "attack", default=None, help="Attack name. "
              "Comma-separate to run several. "
              "Choices: common_factor, low_exp, wiener, fermat")
@click.option("--all", "run_all_flag", is_flag=True,
              help="Run every attack even after one succeeds.")
@click.option("--timeout", "timeout", type=click.FloatRange(1, 3600),
              default=60.0, show_default=True, help="Per-attack timeout (s).")
@click.option("--hex", "is_hex", is_flag=True,
              help="Interpret --n/--e/--c values as hex.")
@click.option("--no-color", "no_color", is_flag=True, help="Disable colors.")
@click.version_option(__version__, prog_name="rsatool")
def main(n, e, c, input_file, attack, run_all_flag, timeout, is_hex, no_color):
    """Try common RSA attacks and decrypt the ciphertext on success."""
    console = Console(highlight=False, color_system=("standard" if not no_color
                                                     else None))

    attacks = None
    if attack:
        attacks = [a.strip() for a in attack.split(",") if a.strip()]
        unknown = [a for a in attacks if a not in
                   ("common_factor", "low_exp", "wiener", "fermat")]
        if unknown:
            console.print(f"[red]Error:[/red] unknown attack: "
                          f"{', '.join(unknown)}")
            raise SystemExit(1)

    if input_file is not None:
        try:
            keys = load_keys_from_json(str(input_file))
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Error parsing JSON:[/red] {exc}")
            raise SystemExit(1)
    elif n is not None and e is not None:
        try:
            keys = [RSAParams(
                n=_parse_int(n, is_hex),
                e=_parse_int(e, is_hex),
                c=_parse_int(c, is_hex) if c else 0,
            )]
        except ValueError as exc:
            console.print(f"[red]Error:[/red] invalid value: {exc}")
            raise SystemExit(1)
    else:
        console.print("[red]Error:[/red] provide --n --e [--c] or --input.")
        raise SystemExit(1)

    if not keys:
        console.print("[yellow]No key sets to test.[/yellow]")
        return

    for k in keys:
        if k.n <= 0 or k.e <= 0:
            console.print(f"[red]Error:[/red] {k.label}: n/e must be positive.")
            raise SystemExit(1)

    with console.status("[cyan]Running attacks...[/cyan]", spinner="dots"):
        results = run_all(keys, attacks=attacks,
                          stop_on_success=not run_all_flag,
                          timeout=timeout)

    success = [r for r in results if r.success]
    _print_summary(console, results)
    for r in success:
        _print_success(console, r)
    if not success:
        console.print("\n[yellow][!] No attack succeeded. "
                      "Per spec, skipping manual manipulation.[/yellow]")


def _print_summary(console, results):
    table = Table(title=f"Attack Results ({len(results)} attempts)")
    table.add_column("Attack", style="bold cyan")
    table.add_column("Status")
    table.add_column("Time")
    table.add_column("Details", overflow="fold")

    for r in results:
        if r.success:
            status = "[green]SUCCESS[/green]"
        elif r.timed_out:
            status = "[yellow]TIMEOUT[/yellow]"
        elif r.details.startswith("error"):
            status = "[yellow]ERROR[/yellow]"
        else:
            status = "[dim]failed[/dim]"
        table.add_row(r.attack, status, f"{r.elapsed:.2f}s",
                      r.details[:80])
    console.print(table)


def _print_success(console, res):
    lines = [
        f"[green]Attack:[/green] {res.attack}",
        f"[green]Time:[/green] {res.elapsed:.2f}s",
    ]
    if res.p is not None:
        lines.append(f"[green]p:[/green] {res.p}")
    if res.q is not None:
        lines.append(f"[green]q:[/green] {res.q}")
    if res.d is not None:
        lines.append(f"[green]d:[/green] {res.d}")
    if res.plaintext_int is not None:
        lines.append(f"[green]plaintext (int):[/green] {res.plaintext_int}")
        raw = int_to_bytes(res.plaintext_int)
        lines.append(f"[green]plaintext (hex):[/green] "
                     f"{raw.hex() if raw else '(empty)'}")
        if res.plaintext:
            printable = "".join(ch if 32 <= ord(ch) < 127 else "."
                                for ch in res.plaintext)
            lines.append(f"[bold green]plaintext (ascii):[/bold green] "
                         f"{printable}")
    if res.details:
        lines.append(f"[dim]detail:[/dim] {res.details}")
    console.print(Panel("\n".join(lines), title="[bold green]=== SUCCESS ===",
                        border_style="green"))
    console.print("")


if __name__ == "__main__":
    main()