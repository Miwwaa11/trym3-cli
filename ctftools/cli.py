"""tryme - CTF tools launcher with interactive menu."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import click
from rich.console import Console

NAME_FILE = "name.txt"
ACCENT = "#A60000"

COMING_SOON = [
    ("steghide", "Steganography extraction tool (Forensics)"),
    ("hashcrack", "Hash identifier & cracker (Crypto)"),
    ("revshell", "Reverse shell generator (Exploit)"),
]

BANNER = rf"""
[{ACCENT}]▄▄▄█████▓ ██▀███ ▓██   ██▓ ███▄ ▄███▓▓█████
[{ACCENT}]▓  ██▒ ▓▒▓██ ▒ ██▒▒██  ██▒▓██▒▀█▀ ██▒▓█   ▀
[{ACCENT}]▒ ▓██░ ▒░▓██ ░▄█ ▒ ▒██ ██░▓██    ▓██░▒███
[{ACCENT}]░ ▓██▓ ░ ▒██▀▀█▄   ░ ▐██▓░▒██    ▒██ ▒▓█  ▄
[{ACCENT}]  ▒██▒ ░ ░██▓ ▒██▒ ░ ██▒▓░▒██▒   ░██▒░▒████▒
[{ACCENT}]  ▒ ░░   ░ ▒▓ ░▒▓░  ██▒▒▒ ░ ▒░   ░  ░░░ ▒░ ░
[{ACCENT}]    ░      ░▒ ░ ▒░▓██ ░▒░ ░  ░      ░ ░ ░  ░
[{ACCENT}]  ░        ░░   ░ ▒ ▒ ░░  ░      ░      ░
[{ACCENT}]            ░     ░ ░            ░      ░  ░
[{ACCENT}]                  ░ ░
"""


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_names() -> list[str]:
    candidates = [
        os.path.join(_repo_root(), NAME_FILE),
        os.path.join(os.getcwd(), NAME_FILE),
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                names = [line.strip() for line in f if line.strip()]
            if names:
                return names
    return []


def _resolve_tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for base in (sys.prefix, sys.base_prefix):
        candidate = os.path.join(base, "bin", name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _run_menu() -> None:
    names = _load_names()
    if not names:
        raise click.ClickException(
            f"No tool list found. Fill in {NAME_FILE} (one tool name per line)."
        )

    all_names = names + [c[0] for c in COMING_SOON]

    while True:
        console = Console()
        console.print(BANNER)
        click.echo("Select a tool:\n")
        for i, name in enumerate(names, 1):
            click.echo(f"  {i}. {name}")
        for i, (name, _) in enumerate(COMING_SOON, len(names) + 1):
            click.echo(f"  {i}. {name}  [Coming soon]")
        click.echo("  0. Exit\n")

        try:
            raw = input(f"Choice [0-{len(all_names)}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("")
            return

        if raw in ("", "0"):
            return
        if not raw.isdigit():
            click.echo("Invalid number.\n")
            continue

        idx = int(raw)
        if not 1 <= idx <= len(all_names):
            click.echo("Invalid number.\n")
            continue

        name = all_names[idx - 1]

        if any(c[0] == name for c in COMING_SOON):
            desc = next(d for n, d in COMING_SOON if n == name)
            click.echo(f"\n  {name} - {desc}")
            click.echo("  Coming soon!\n")
            continue

        exe = _resolve_tool(name)
        if not exe:
            click.echo(f"Error: '{name}' is not installed.\n")
            continue

        try:
            text = input("Enter text: ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("")
            continue
        if not text:
            click.echo("No input.\n")
            continue

        while True:
            click.echo("")
            subprocess.run([exe, text])
            click.echo("\n[C] Close  [E] Exit")
            try:
                choice = input("Choice: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                click.echo("")
                return
            if choice == "c":
                break
            if choice == "e":
                return
            try:
                text = input("Enter text: ").strip()
            except (EOFError, KeyboardInterrupt):
                click.echo("")
                return
            if not text:
                click.echo("No input.\n")
                continue


@click.group(invoke_without_command=True, no_args_is_help=False)
@click.version_option(version="1.0.0", prog_name="tryme")
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        _run_menu()


def main():
    cli()


if __name__ == "__main__":
    main()
