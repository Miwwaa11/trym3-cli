"""CLI entry point for revshell."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

from . import __version__
from .core import ALL_LANGS, BANNER_NOTE, generate_shell


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--ip", "-i", "ip", required=True,
              help="Listener IP address (LHOST).")
@click.option("--port", "-p", "port", type=click.IntRange(1, 65535),
              required=True, help="Listener port (LPORT).")
@click.option("--lang", "-l", "lang", type=click.Choice(["all"] + ALL_LANGS),
              default="all", show_default=True,
              help="Only show payloads for a specific language.")
@click.option("--no-color", "no_color", is_flag=True,
              help="Disable colors.")
@click.version_option(__version__, prog_name="revshell")
def main(ip, port, lang, no_color):
    """Generate reverse shell payloads in multiple languages."""
    console = Console(highlight=False,
                      color_system=("standard" if not no_color else None))

    shells = generate_shell(ip, port, lang)
    if not shells:
        console.print(f"[red]Error:[/red] unknown language '{lang}'.")
        raise SystemExit(1)

    console.print(f"[bold cyan]{BANNER_NOTE}[/bold cyan]\n")
    console.print(f"[bold]Reverse shells for[/bold] [green]{ip}:{port}[/green] "
                  f"([bold]{len(shells)}[/bold] payloads)\n")

    for i, shell in enumerate(shells, 1):
        console.print(Panel(
            shell.payload.rstrip(),
            title=f"[bold]{i}[/bold] [green]{shell.lang}[/green] — "
                  f"{shell.description}",
            border_style="green",
            expand=False,
        ))
        console.print("")


if __name__ == "__main__":
    main()
