"""Core RSA attacks: common factor, low exponent, wiener, fermat."""

from __future__ import annotations

import itertools
import json
import math
import signal
import time
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Callable, Optional

from sympy import gcd


class AttackTimeout(Exception):
    pass


class _Timeout:
    """SIGALRM-based soft timeouts for CPU-bound attack functions."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._used = False

    def __enter__(self):
        self._used = True
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, self._handler)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)

    def __exit__(self, exc_type, exc, tb):
        if hasattr(signal, "SIGALRM"):
            signal.setitimer(signal.ITIMER_REAL, 0)
        return False

    def _handler(self, signum, frame):  # pragma: no cover - signal path
        raise AttackTimeout(f"attack timed out after {self.seconds:.0f}s")


@dataclass
class RSAParams:
    n: int
    e: int
    c: int
    label: str = ""

    def __post_init__(self):
        if not self.label:
            self.label = f"n={self.n}"


@dataclass
class AttackResult:
    attack: str
    success: bool = False
    p: Optional[int] = None
    q: Optional[int] = None
    d: Optional[int] = None
    plaintext_int: Optional[int] = None
    plaintext: Optional[str] = None
    details: str = ""
    timed_out: bool = False
    elapsed: float = 0.0


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b""
    hexed = hex(value)[2:]
    if len(hexed) % 2:
        hexed = "0" + hexed
    return bytes.fromhex(hexed)


def bytes_to_text(b: bytes) -> str:
    for enc in ("utf-8", "latin-1", "ascii"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return hex(int.from_bytes(b, "big"))


def compute_private(params: RSAParams, p: int, q: int) -> int:
    """Compute d = e^-1 mod lcm(p-1, q-1). Handles p == q (n = p^2)."""
    if p == q:
        phi = p * (p - 1)
    else:
        from sympy import ilcm
        phi = ilcm(p - 1, q - 1)
    return pow(params.e, -1, phi)


def decrypt(params: RSAParams, p: int, q: int) -> tuple[int, str] | None:
    """Compute d, decrypt c. Returns None if e is not invertible mod phi."""
    try:
        d = compute_private(params, p, q)
    except ValueError:
        return None
    m = pow(params.c, d, params.n)
    text = bytes_to_text(int_to_bytes(m))
    return m, text


# --------------------------------------------------------------------------
# Attacks
# --------------------------------------------------------------------------


def attack_common_factor(keys: list[RSAParams]) -> AttackResult:
    """GCD over all pairs of moduli. Works when two keys share a prime."""
    res = AttackResult(attack="common_factor")
    if len(keys) < 2:
        return res
    for i, j in itertools.combinations(range(len(keys)), 2):
        ki, kj = keys[i], keys[j]
        if ki.n == kj.n:
            continue
        g = int(gcd(ki.n, kj.n))
        if g > 1 and g < ki.n:
            p = g
            q = ki.n // p
            if p * q != ki.n:
                continue
            res.success = True
            res.p, res.q = p, q
            res.details = f"gcd(n[{i}], n[{j}]) = {p}"
            if ki.c:
                dec = decrypt(ki, p, q)
                if dec:
                    res.plaintext_int, res.plaintext = dec
            return res
    return res


def _integer_nth_root(n: int, k: int) -> Optional[int]:
    """Exact integer k-th root via Newton iterations."""
    if n < 0 or k <= 0:
        return None
    if n == 0:
        return 0
    if k == 1:
        return n
    # initial guess via bit length
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            break
        x = y
    return x if x ** k == n else None


def attack_low_exp(params: RSAParams) -> AttackResult:
    """Small 'e' without padding: plaintext^e == c (exact root, no mod)."""
    res = AttackResult(attack="low_exponent")
    try:
        root = _integer_nth_root(params.c, params.e)
    except (OverflowError, ZeroDivisionError):
        return res
    if root is not None and root ** params.e == params.c:
        res.success = True
        res.plaintext_int = root
        res.plaintext = bytes_to_text(int_to_bytes(root))
        res.details = (f"c^(1/{params.e}) exact ({len(bin(root))} bits), "
                       "m^e < n (no padding)")
    return res


def _cf_expansion(fr: Fraction) -> list[int]:
    out = []
    while fr != 0 and len(out) < 10000:
        a = fr.numerator // fr.denominator
        out.append(a)
        rem = fr - a
        if rem == 0:
            break
        fr = 1 / rem
    return out


def _convergents(cf: list[int]):
    # returns (h_i, k_i) pairs
    h_prev2, k_prev2 = 0, 1
    h_prev1, k_prev1 = 1, 0
    for a in cf:
        h = a * h_prev1 + h_prev2
        k = a * k_prev1 + k_prev2
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k
        yield h, k


def attack_wiener(params: RSAParams) -> AttackResult:
    """Wiener: private exponent d is small (< n^0.25 / 3)."""
    res = AttackResult(attack="wiener")
    e, n = params.e, params.n
    if e >= n:
        return res
    cf = _cf_expansion(Fraction(e, n))
    for h, k in _convergents(cf):
        if k == 0 or h == 0:
            continue
        phi = (e * k - 1) // h
        if (e * k - 1) % h != 0:
            continue
        # phi = (p-1)(q-1) => p+q = n - phi + 1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        disc_root = math.isqrt(disc)
        if disc_root * disc_root != disc:
            continue
        p = (s + disc_root) // 2
        q = (s - disc_root) // 2
        if p * q == n and 1 < p < n:
            res.success = True
            res.p, res.q = p, q
            res.d = k  # candidate private exponent (convergent denominator)
            res.details = f"d ≈ {k} via continued fraction"
            if params.c:
                m = pow(params.c, k, n)
                res.plaintext_int = m
                res.plaintext = bytes_to_text(int_to_bytes(m))
            return res
    return res


def attack_fermat(params: RSAParams, max_iter: int = 2_000_000) -> AttackResult:
    """Fermat factorization when p and q are close."""
    res = AttackResult(attack="fermat")
    n = params.n
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    for i in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p > 1 and q > 1 and p * q == n:
                res.success = True
                res.p, res.q = p, q
                res.details = f"{i} iterations (|p-q|={q - p})"
                if params.c:
                    dec = decrypt(params, p, q)
                    if dec:
                        res.plaintext_int, res.plaintext = dec
                return res
        b2 += (a << 1) + 1
        a += 1
    return res


ATTACKS: list[tuple[str, str, Callable]] = [
    ("common_factor", "Common Factor (GCD across n)", attack_common_factor),
    ("low_exp", "Low Public Exponent (m^e = c)", attack_low_exp),
    ("wiener", "Wiener's Attack (small d)", attack_wiener),
    ("fermat", "Fermat Factorization (p,q close)", attack_fermat),
]


def run_attack(applied: str, fn: Callable, args, timeout: float) -> AttackResult:
    """Run an attack function with a per-attack timeout."""
    start = time.monotonic()
    try:
        with _Timeout(timeout):
            res = fn(*args)
    except AttackTimeout as exc:
        res = AttackResult(attack=applied, timed_out=True,
                           details=str(exc))
    except Exception as exc:  # noqa: BLE001
        res = AttackResult(attack=applied, timed_out=False,
                           details=f"error: {exc}")
    res.elapsed = time.monotonic() - start
    return res


def run_all(keys: list[RSAParams], attacks: Optional[list[str]] = None,
            stop_on_success: bool = True,
            timeout: float = 60.0) -> list[AttackResult]:
    """Run attacks sequentially over all keys."""
    selected = []
    for name, desc, fn in ATTACKS:
        if attacks is None or name in attacks:
            selected.append((name, desc, fn))

    results: list[AttackResult] = []

    for name, desc, fn in selected:
        if name == "common_factor":
            res = run_attack(name, fn, (keys,), timeout)
            results.append(res)
            if res.success and stop_on_success:
                return results
            continue
        for params in keys:
            res = run_attack(name, fn, (params,), timeout)
            results.append(res)
            if res.success and stop_on_success:
                return results

    return results


def load_keys_from_json(path: str) -> list[RSAParams]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    raw_keys = data.get("keys") if isinstance(data, dict) else data
    if isinstance(raw_keys, dict):
        raw_keys = [raw_keys]
    keys = []
    for i, rk in enumerate(raw_keys):
        n = _to_int(rk.get("n"))
        e = _to_int(rk.get("e"))
        c = _to_int(rk.get("c", 0))
        keys.append(RSAParams(n=n, e=e, c=c, label=rk.get("label", f"key[{i}]")))
    return keys


def _to_int(value) -> int:
    if value is None:
        raise ValueError("missing value in the keys file")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)