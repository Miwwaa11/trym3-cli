"""CLI entry point for autodecode."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .core import (best_candidate, confidence, decode_all, is_meaningful,
                   single_step)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("text", required=False)
@click.option("--text", "text_opt", help="Input ciphertext (alternative when "
              "the text starts with a dash).")
@click.option("--only-readable", "only_readable", is_flag=True,
              help="Only show results with high confidence (>=0.6).")
@click.option("--all", "show_all", is_flag=True,
              help="Exhaustive mode: show every decode candidate (BFS).")
@click.option("--max-depth", "max_depth", type=click.IntRange(1, 20), default=5,
              show_default=True, help="Maximum decode-chaining iterations.")
@click.option("--min-score", "min_score", type=click.FloatRange(0.0, 1.0),
              default=None, help="Minimum confidence to display (0.0-1.0).")
@click.option("--max-results", "max_results", type=click.IntRange(1, 500),
              default=50, show_default=True, help="Limit number of results (--all mode).")
@click.option("--no-color", "no_color", is_flag=True, help="Disable colors.")
@click.version_option(__version__, prog_name="autodecode")
def main(text, text_opt, only_readable, show_all, max_depth, min_score,
         max_results, no_color):
    """Multi-cipher auto-decoder. Input via argument, --text, or stdin (pipe)."""
    console = Console(highlight=False, color_system=("standard" if not no_color
                                                     else None))

    if text_opt is not None:
        text = text_opt
    elif text is None:
        data = click.get_text_stream("stdin").read()
        if not data:
            console.print("[red]Error:[/red] no input provided. Give an "
                          "argument or pipe stdin.", style="bold red")
            raise SystemExit(1)
        text = data
    text = text.strip()

    console.print(f"[bold cyan]Input:[/bold cyan] {text!r}\n")

    if show_all:
        _show_all(console, text, max_depth, min_score, max_results)
        return

    _show_default(console, text, max_depth, only_readable, min_score)


def _show_default(console, text, max_depth, only_readable, min_score):
    try:
        chain = best_candidate(text, max_depth=max_depth)
    except RecursionError:
        chain = None

    if chain is not None and chain.chain:
        steps = " → ".join(chain.chain)
        console.print(Panel(
            f"[bold]{chain.text}[/bold]",
            title=f"[green]Best Candidate[/green] "
                  f"({chain.score * 100:.1f}%)",
            subtitle=f"Steps: {steps}",
            border_style="green",
        ))
        console.print("")

    steps = single_step(text)
    steps = [s for s in steps if is_meaningful(s.text)]
    threshold = 0.6 if only_readable else None
    if threshold is not None:
        steps = [s for s in steps if s.score >= threshold]
    if min_score is not None:
        steps = [s for s in steps if s.score >= min_score]

    if not steps:
        console.print("[yellow]No readable single-step results. "
                      "Try --all.[/yellow]")
        return

    table = Table(title="Single-Step Results (ordered by confidence)")
    table.add_column("#", justify="right")
    table.add_column("Method", style="bold cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Result", overflow="fold")

    for i, s in enumerate(steps, 1):
        color = "green" if s.score >= 0.6 else ("yellow" if s.score >= 0.3
                                                else "red")
        table.add_row(str(i), s.method, f"[{color}]{s.score * 100:.1f}%[/{color}]",
                      s.text)
    console.print(table)


def _show_all(console, text, max_depth, min_score, max_results):
    results = decode_all(text, max_depth=max_depth)
    if min_score is not None:
        results = [r for r in results if r.score >= min_score]
    if not results:
        console.print("[yellow]No readable decode results found. Try "
                      "lowering --min-score.[/yellow]")
        return

    results = results[:max_results]
    table = Table(title="All Decode Results (ordered by confidence)")
    table.add_column("#", justify="right")
    table.add_column("Method", style="bold cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Result", overflow="fold")

    for i, r in enumerate(results, 1):
        chain_txt = " → ".join(r.chain)
        color = "green" if r.score >= 0.6 else ("yellow" if r.score >= 0.3
                                                else "red")
        table.add_row(str(i), chain_txt,
                      f"[{color}]{r.score * 100:.1f}%[/{color}]", r.text)
    console.print(table)


if __name__ == "__main__":
    main()