# z3-solver

Constraint solver helper for CTF reversing challenges. Scaffolds symbolic flag variables and standard Z3 patterns so you can focus on adding the actual constraints.

Requires `z3-solver`:

```bash
pip install z3-solver
```

Or install with solve extras: `pip install -e ./z3-solver[solve]`.

## Usage

```bash
z3-solver --print-vars 20
z3-solver --template
```

The `--template` option prints a runnable skeleton with common constraint patterns preloaded.
