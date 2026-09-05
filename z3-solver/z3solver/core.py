"""Core logic for z3-solver: helpers for common Z3 constraint patterns."""

from __future__ import annotations


def require_z3():
    """Lazily import z3, with a friendly error if missing."""
    try:
        import z3  # noqa: F401
        return z3
    except ImportError as e:
        raise RuntimeError(
            "z3-solver is not installed. Install it with:\n"
            "    pip install z3-solver"
        ) from e


def flag_words(flag: str, n: int, z3) -> list:
    """Create n 8-bit symbolic BitVec variables named after the flag."""
    return [z3.BitVec(f"{flag}[{i}]", 8) for i in range(n)]


def add_flag_range(constraints: list, vars_: list, z3) -> None:
    """Constrain ASCII-printable characters (32-126), common for CTF flags."""
    for v in vars_:
        constraints.append(z3.And(v >= 32, v <= 126))


def solve(constraints: list, z3, timeout_ms: int = 10_000) -> dict | None:
    """Solve constraints (a z3.Solver object must be passed or built)."""
    s = z3.Solver()
    s.set(timeout=timeout_ms)
    for c in constraints:
        s.add(c)
    if s.check() == z3.sat:
        return s.model()
    return None


def extract_bytes(model, vars_: list) -> bytes:
    """Convert a sat model's vars to a bytes string."""
    out = bytearray()
    for v in vars_:
        val = model[v]
        b = int(val.as_long()) & 0xFF if hasattr(val, "as_long") else int(val)
        out.append(b)
    return bytes(out)
