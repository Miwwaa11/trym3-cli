"""CLI for offsetfind - Buffer Overflow Offset Finder."""

from __future__ import annotations

import os

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import core
from .core import OffsetResult

console = Console()

APP_NAME = "offsetfind"


def _checksec_table(result: OffsetResult) -> Table:
    cs = result.checksec
    table = Table(title="Binary Protections (checksec)")
    table.add_column("Property", style="bold")
    table.add_column("Value", justify="center")

    def _bool(v):
        if v is None:
            return "?"
        return "ON" if v else "off"

    arch = str(cs.arch_bits or "?")
    table.add_row("Architecture", f"{arch}-bit")
    table.add_row("NX", _bool(cs.nx))
    table.add_row("PIE", _bool(cs.pie))
    table.add_row("Stack Canary", _bool(cs.canary))
    table.add_row("RELRO", str(cs.relro or "?"))
    table.add_row("ASLR", _bool(cs.aslr))
    table.add_row("Stripped", "yes" if cs.stripped else "no" if cs.stripped is not None else "?")
    return table


def _crash_panel(result: OffsetResult) -> Panel:
    crash = result.crash
    cs = result.checksec
    bits = cs.arch_bits or 64
    lines = []

    if not crash.crashed:
        lines.append("[red]No crash detected.[/red]")
        for note in crash.notes:
            lines.append(f"  - {note}")
        return Panel("\n".join(lines), title="Result")

    if crash.offset is not None:
        lines.append(f"[bold green]Buffer overflow offset: {crash.offset}[/bold green]")
    else:
        lines.append("[yellow]Crash occurred but the fault address is not a "
                     "cyclic pattern.[/yellow]")
        lines.append("  Try: binary with stronger canary/PIE, or increase --pattern-length.")

    lines.append("")
    lines.append(f"Fault address : [cyan]{crash.fault_addr_hex or '?'}[/cyan]")
    lines.append(f"RIP           : {('0x%x' % crash.rip) if crash.rip is not None else '?'}")
    lines.append(f"RSP           : {('0x%x' % crash.rsp) if crash.rsp is not None else '?'}")

    if crash.pie_base is not None:
        lines.append("")
        lines.append(f"Base address (PIE) : [cyan]0x{crash.pie_base:x}[/cyan]")

    if result.remote_reached is not None:
        lines.append("")
        if result.remote_reached:
            lines.append("[green]Remote: service crash confirmed.[/green]")
        else:
            lines.append(f"[yellow]Remote: {result.remote_note or 'no crash'}[/yellow]")

    for note in crash.notes:
        if "remote" in note or note.startswith("failed") or note.startswith("process") or "exit" in note:
            lines.append(f"[dim]- {note}[/dim]")

    return Panel("\n".join(lines), title="Offset Result")


@click.command(name=APP_NAME)
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--host", help="Remote target host.")
@click.option("--port", type=int, help="Remote target port.")
@click.option("--pattern-length", default=1024, show_default=True,
              help="Length of the cyclic pattern.")
@click.option("--timeout", default=5.0, show_default=True, type=float,
              help="Process/connection timeout (seconds).")
@click.option("--no-checksec", is_flag=True, help="Skip the checksec display.")
@click.option("--offset-only", is_flag=True, help="Only print the offset value.")
@click.option("--verbose", is_flag=True, help="Show verbose pwntools logs.")
def main(binary, host, port, pattern_length, timeout, no_checksec, offset_only, verbose):
    """Find a buffer overflow offset via cyclic pattern + core dump.

    BINARY: path to the vulnerable binary.
    """
    if not verbose:
        try:
            from pwn import context
            context.log_level = "error"
        except ImportError:
            pass
    try:
        result = core.find_offset(binary, host=host, port=port,
                                  pattern_length=pattern_length, timeout=timeout)
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Unexpected error:[/red] {exc}")
        raise SystemExit(1)

    if offset_only:
        if result.crash.offset is not None:
            print(result.crash.offset)
        else:
            raise SystemExit(1)
        return

    if host and port:
        console.print(Panel(f"[bold]Target:[/bold] {host}:{port}", title="offsetfind",
                            style="cyan"))
    else:
        console.print(Panel(f"[bold]Binary:[/bold] {os.path.abspath(binary)}",
                            title="offsetfind", style="cyan"))

    if not no_checksec:
        console.print(_checksec_table(result))

    console.print(_crash_panel(result))


if __name__ == "__main__":
    main()