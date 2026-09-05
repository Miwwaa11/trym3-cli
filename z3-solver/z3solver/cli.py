"""CLI entry point for z3-solver."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

from . import __version__
from .core import require_z3


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--print-vars", "n_vars", type=click.IntRange(0, 256), default=0,
              show_default=True,
              help="Print Python code to declare & constrain a flag of N vars, "
                   "then exit.")
@click.option("--template", "use_template", is_flag=True,
              help="Print a full runnable Z3 flag-solving template to stdout.")
@click.option("--no-color", "no_color", is_flag=True,
              help="Disable colors.")
@click.version_option(__version__, prog_name="z3-solver")
def main(n_vars, use_template, no_color):
    """Helper for solving CTF reversing constraints with Z3."""
    console = Console(highlight=False,
                      color_system=("standard" if not no_color else None))

    if use_template:
        console.print(_TEMPLATE, markup=False)
        return

    if n_vars:
        _print_vars(console, n_vars)
        return

    z3 = _load(console)
    console.print(Panel(
        "z3-solver: interactive constraint helper.\n"
        "No direct REPL is exposed; write a script using the printed template.\n\n"
        "  • Passive import check passed.\n"
        "  • Use --template to get a runnable skeleton.\n"
        "  • Use --print-vars N to scaffold flag variables.",
        title="[green]z3-solver ready[/green]",
        border_style="green",
    ))


def _load(console):
    try:
        return require_z3()
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)


def _print_vars(console, n):
    console.print("# Declare symbolic flag bytes:")
    console.print(
        f"flag = [BitVec('flag[i]', 8) for i in range({n})]",
        markup=False,
    )
    console.print("for f in flag:\n    s.add(And(f >= 32, f <= 126))",
                  markup=False)


_TEMPLATE = r"""
# Z3 flag-solving template for reversing challenges.
from z3 import *

n = 0          # <-- number of unknown characters
flag = [BitVec(f'flag[{i}]', 8) for i in range(n)]
s = Solver()

# ASCII printable range (typical CTF flag)
for f in flag:
    s.add(And(f >= 32, f <= 126))

# =========================================================================
# Add your constraints here. Common patterns:
#
#   1. Direct equality:        s.add(flag[0] == ord('c'))
#   2. XOR with constant:      s.add(flag[i] ^ 0x5a == target[i])
#   3. Add with carry:         s.add(flag[i] + flag[i+1] == target[i])
#   4. Multiplication:         s.add(flag[0] * flag[1] == 0x1f2)
#   5. Compare string:         s.add(flag[0:6] == b'flag{')
#   6. Loop-sum check:         s.add(Sum(flag) == 0x1234)
# =========================================================================

if s.check() == sat:
    m = s.model()
    result = bytes([m[f].as_long() for f in flag])
    print(result.decode('ascii', errors='replace'))
else:
    print('UNSAT')
"""


if __name__ == "__main__":
    main()
