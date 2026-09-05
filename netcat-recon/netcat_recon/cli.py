"""CLI entry point for netcat-recon."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import COMMON_PORTS, scan_ports


def _parse_port_range(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return ports


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("host")
@click.option("--port", "-p", "ports", default=None,
              help="Ports to scan: comma/range list, e.g. '22,80,1000-2000'. "
                   "Default: common ports.")
@click.option("--all", "all_ports", is_flag=True,
              help="Scan all ports 1-65535 (slow).")
@click.option("--timeout", type=click.FloatRange(0.1, 10.0), default=1.0,
              show_default=True, help="Per-port connection timeout (s).")
@click.option("--threads", type=click.IntRange(1, 1024), default=64,
              show_default=True, help="Concurrent scan threads.")
@click.option("--no-color", "no_color", is_flag=True,
              help="Disable colors.")
@click.version_option(__version__, prog_name="netcat-recon")
def main(host, ports, all_ports, timeout, threads, no_color):
    """Quick TCP port scan and banner grab for reconnaissance."""
    console = Console(highlight=False,
                      color_system=("standard" if not no_color else None))

    if all_ports:
        port_list = list(range(1, 65536))
    elif ports:
        port_list = _parse_port_range(ports)
    else:
        port_list = list(COMMON_PORTS)

    console.print(f"[bold cyan]Scanning[/bold cyan] [green]{host}[/green] "
                  f"({len(port_list):,} ports, {threads} threads, "
                  f"{timeout}s timeout)...\n")

    results = scan_ports(host, port_list, timeout=timeout, concurrency=threads)
    open_ports = [r for r in results if r.open]

    if not open_ports:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    table = Table(title=f"Open Ports on {host}")
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("Service", style="green")
    table.add_column("Banner", overflow="fold")
    for r in sorted(open_ports, key=lambda x: x.port):
        banner = r.banner if r.banner else ""
        table.add_row(str(r.port), r.service, banner)
    console.print(table)
    console.print(f"\n[bold]{len(open_ports)}[/bold] open port(s).")


if __name__ == "__main__":
    main()
