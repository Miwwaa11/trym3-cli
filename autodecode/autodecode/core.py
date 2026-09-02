"""Core decoding logic: coders, chaining, and confidence scoring."""

from __future__ import annotations

import base64
import html
import math
import re
import string
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from queue import deque
from typing import Callable, Optional

WORDLIST_PATH = Path(__file__).parent / "data" / "words.txt"

_PRINTABLE = set(string.printable)

_COMMON_WORDS = None


def _load_wordlist() -> set[str]:
    """Load bundled english wordlist once, lazily."""
    global _COMMON_WORDS
    if _COMMON_WORDS is None:
        words = set()
        p = WORDLIST_PATH
        if p.exists():
            with p.open(encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip().lower()
                    if w:
                        words.add(w)
        _COMMON_WORDS = words
    return _COMMON_WORDS


# --------------------------------------------------------------------------
# Low-level codecs. Each returns the decoded str or None if invalid.
# --------------------------------------------------------------------------


def _b64(data: str) -> Optional[str]:
    try:
        raw = base64.b64decode(data, validate=True)
    except Exception:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _b32(data: str) -> Optional[str]:
    try:
        raw = base64.b32decode(data.upper())
    except Exception:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _hex(data: str) -> Optional[str]:
    s = data.strip()
    if len(s) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _rot13(data: str) -> str:
    return data.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
        + string.ascii_uppercase[13:] + string.ascii_uppercase[:13],
    ))


def _rot47(data: str) -> str:
    out = []
    for ch in data:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o + 14) % 94)))
        else:
            out.append(ch)
    return "".join(out)


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'",
    "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-",
    "..--.-": "_", ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}
_MORSE_REV = {v: k for k, v in _MORSE.items()}


def _morse(data: str) -> Optional[str]:
    """Decode morse like '- .... . / --.- ..- .. -.-. -.-'.

    '/' or multi-space separates words; single space separates characters.
    """
    s = data.strip()
    if not s or not set(s) <= set("-.,/|_ "):
        return None

    # choose character separator: '|' or '_' are explicit; else single space
    char_sep = "|" if "|" in s else ("_" if "_" in s else " ")
    word_sep = "/" if "/" in s else ("  " if "  " in s else None)

    words_text = s.split("/") if word_sep else [s]
    out_words = []
    for word_text in words_text:
        chars = [t for t in word_text.split(char_sep) if t.strip()]
        decoded = [_MORSE.get(t.strip()) for t in chars]
        if any(d is None for d in decoded):
            return None
        out_words.append("".join(decoded))
    return " ".join(out_words)


def _binary(data: str) -> Optional[str]:
    s = re.sub(r"\s+", "", data)
    if not s or len(s) % 8 != 0 or not set(s) <= set("01"):
        return None
    try:
        raw = bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))
    except ValueError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _url(data: str) -> Optional[str]:
    try:
        return urllib.parse.unquote(data)
    except Exception:
        return None


def _html_unescape(data: str) -> Optional[str]:
    u = html.unescape(data)
    return u if u != data else None


def _caesar(data: str, shift: int) -> str:
    out = []
    for ch in data:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# Confidence scoring
# --------------------------------------------------------------------------


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    allowed = set("\t\n\r")
    ok = sum(1 for ch in text if ch in _PRINTABLE or ch in allowed)
    return ok / len(text)


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def dictionary_score(text: str) -> float:
    """Character coverage of alphabetic runs that are real dictionary words."""
    words = _load_wordlist()
    if not words:
        return 0.0
    runs = [r for r in re.findall(r"[A-Za-z]+", text) if len(r) >= 3]
    if not runs:
        return 0.0
    covered = sum(len(r) for r in runs if r.lower() in words)
    total = sum(len(r) for r in runs)
    return covered / total


_FLAG_RE = re.compile(r"(?:flag|ctf)\s*\{[^}]{2,}\}", re.IGNORECASE)


def confidence(text: str) -> float:
    """0..1 heuristic: how likely is `text` to be real CTF plaintext.

    Signals: printability, word-character coverage, entropy, symbol/digit
    density (encoded artifacts), base64 markers, and flag patterns.
    """
    if not text:
        return 0.0

    pr = printable_ratio(text)
    length_factor = min(1.0, len(text) / 12.0)

    # word coverage across eligible alphabetic runs
    runs = [r for r in re.findall(r"[A-Za-z]+", text) if len(r) >= 3]
    if runs:
        _words = _load_wordlist()
        covered = sum(len(r) for r in runs if r.lower() in _words)
        ds = covered / sum(len(r) for r in runs)
    else:
        ds = 0.0

    alpha_chars = sum(len(r) for r in re.findall(r"[A-Za-z]+", text))
    symbol_density = 1.0 - (alpha_chars / len(text)) if text else 1.0

    # digits within or around words suggest encoded/coded artifact
    digit_ratio = sum(1 for ch in text if ch.isdigit()) / len(text)

    # base64/url-ish markers
    marker_penalty = 0.0
    for ch in "+=/%":
        if ch in text.strip():
            marker_penalty = max(marker_penalty, 0.10)
    marker_penalty = min(marker_penalty, 0.30)

    en = entropy(text)
    ent_quality = 1.0 if en <= 4.9 else max(0.0, 1.0 - (en - 4.9) * 0.25)

    flag_bonus = 0.15 if _FLAG_RE.search(text) else 0.0

    score = (0.32 * pr
             + 0.38 * ds * length_factor * (0.5 + 0.5 * length_factor)
             + 0.12 * ent_quality
             + 0.18 * (1.0 - symbol_density)
             - 0.30 * digit_ratio
             - marker_penalty
             + flag_bonus)
    return max(0.0, min(1.0, score))


def is_meaningful(text: str) -> bool:
    """True if a decode result is worth keeping (mostly printable)."""
    if not text:
        return False
    return printable_ratio(text) >= 0.5


def is_terminal(text: str) -> bool:
    """True if the text already looks like final readable plaintext.

    Terminal nodes are NOT expanded further, preventing runaway chaining
    into garbage. A result is terminal when it is printable and dominated
    by alphabetic content that forms real words.
    """
    if not text or len(text) < 2:
        return True
    words = _load_wordlist()
    tokens = [t for t in re.findall(r"[A-Za-z]+", text) if len(t) >= 3]
    if not tokens:
        return False
    hits = sum(1 for t in tokens if t.lower() in words)
    ds = hits / len(tokens)
    alpha_chars = sum(len(t) for t in re.findall(r"[A-Za-z]+", text))
    symbol_density = 1.0 - (alpha_chars / len(text))
    pr = printable_ratio(text)
    return pr >= 0.95 and ds >= 0.5 and symbol_density <= 0.35


@dataclass
class DecodeResult:
    method: str
    text: str
    score: float
    depth: int = 0
    chain: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Chained decoding
# --------------------------------------------------------------------------

CODERS: list[tuple[str, Callable[[str], Optional[str]]]] = [
    ("base64", _b64),
    ("base32", _b32),
    ("hex", _hex),
    ("url", _url),
    ("html_unescape", _html_unescape),
    ("morse", _morse),
    ("binary", _binary),
    ("rot13", _rot13),
    ("rot47", _rot47),
]

SINGLE_SHOT = {name for name, _ in CODERS}

_ALPHA64 = frozenset(string.ascii_letters + string.digits + "+/=")
_HEXCHARS = frozenset("0123456789abcdefABCDEF")
_BINCHARS = frozenset("01")


def codec_likelihood(text: str) -> list[tuple[str, float]]:
    """Heuristic score (0..1) of how likely `text` is each encoding form."""
    if not text:
        return []
    s = text.strip()
    scores: list[tuple[str, float]] = []

    is_binary = set(s) <= _BINCHARS and len(s) >= 8
    is_hex = set(s) <= _HEXCHARS and len(s) >= 2

    # binary: only {0,1}. A ['{a,1,14}')base64.text can rarely be pure 01.
    if is_binary and len(s) % 8 == 0:
        scores.append(("binary", 1.0))
        return scores

    # hex: only hexchars and even length -- strongly suggests hex encoding
    if is_hex and len(s) % 2 == 0 and not is_binary:
        scores.append(("hex", 0.95))

    # base32
    if (len(s) >= 8 and len(s) % 8 == 0
            and set(s) <= frozenset(string.ascii_uppercase + string.digits + "=")):
        scores.append(("base32", 0.75))

    # base64 -- only if not already classified as hex/binary, or has '=' pad
    if len(s) >= 4 and len(s) % 4 == 0:
        weird = sum(1 for ch in s if ch not in _ALPHA64)
        eq = s.count("=")
        ok_pad = eq == 0 or (eq in (1, 2) and s.endswith("=" * eq))
        pure_hex = set(s) <= _HEXCHARS
        if weird == 0 and ok_pad and not (pure_hex and len(s) % 2 == 0):
            scores.append(("base64", 0.85))

    # morse
    if s and set(s) <= set("-., /|_…") and any(ch in s for ch in ".-"):
        toks = [t for t in re.split(r"[ /|_…]+", s) if t]
        if toks and all(tok in _MORSE or tok == "-.-.--" for tok in toks):
            scores.append(("morse", 0.8))

    # url encoding
    if "%" in s:
        scores.append(("url", 0.8 if re.search(r"%[0-9a-fA-F]{2}", s) else 0.4))

    # html entities
    if re.search(r"&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);", s, re.I):
        scores.append(("html_unescape", 0.7))

    # rot13 / rot47 / caesar only apply to letter-like text; low confidence
    if any(ch.isalpha() for ch in s):
        scores.append(("rot13", 0.35))
        scores.append(("rot47", 0.25))

    return sorted(scores, key=lambda x: x[1], reverse=True)


def chain_detect(text: str, max_depth: int = 5) -> Optional[DecodeResult]:
    """Greedily decode based on best matching charset.

    Mirrors human triage: 'this looks like base64' -> decode, repeat.
    Returns the terminal result after chaining, or None if no encoding was
    detected.
    """
    cur = text
    chain: list[str] = []
    visited = {text}

    for depth in range(1, max_depth + 1):
        candidates = codec_likelihood(cur)
        best_name, best_score = candidates[0] if candidates else (None, 0.0)
        if best_name is None or best_score < 0.5:
            break
        if best_name in ("rot13", "rot47"):
            break  # avoid wrong chains on plain text
        out = _apply(best_name, cur)
        if out is None or out == cur or out in visited:
            break
        chain.append(best_name)
        cur = out
        visited.add(cur)

    if not chain:
        return None

    return DecodeResult(method=chain[-1], text=cur,
                        score=confidence(cur), depth=len(chain), chain=chain)


def chain_readable(text: str, max_depth: int = 5) -> Optional[DecodeResult]:
    """Fallback greedy: follow the most readable single decode repeatedly.

    Useful for letter-only ciphers (caesar/rot) where charset detection
    cannot apply. Requires a readability improvement at each step.
    """
    cur = text
    chain: list[str] = []
    base_score = confidence(cur)

    for depth in range(max_depth):
        if is_terminal(cur):
            break
        steps = single_step(cur)
        steps = [s for s in steps if s.score > base_score + 0.05 and
                 s.score >= 0.5]
        if not steps:
            break
        best = steps[0]
        chain.append(best.method)
        cur = best.text
        base_score = best.score

    if not chain:
        return None
    return DecodeResult(method=chain[-1], text=cur, score=confidence(cur),
                        depth=len(chain), chain=chain)


def single_step(text: str, min_score: float = 0.0) -> list[DecodeResult]:
    """Compute all depth-1 decode results for a text, sorted by confidence."""
    results = {}
    for name in SINGLE_SHOT:
        out = _apply(name, text)
        if out is None or out == text:
            continue
        results.setdefault(name, DecodeResult(method=name, text=out,
                                              score=confidence(out), chain=[name]))
    for shift in range(1, 26):
        out = _caesar(text, shift)
        if out in (None, text):
            continue
        key = f"caesar({shift})"
        results.setdefault(key, DecodeResult(method=key, text=out,
                                             score=confidence(out),
                                             chain=[key]))
    return sorted(results.values(), key=lambda r: r.score, reverse=True)


def _apply(name: str, text: str) -> Optional[str]:
    for n, fn in CODERS:
        if n == name:
            return fn(text)
    raise KeyError(name)


def best_candidate(text: str, max_depth: int = 5) -> Optional[DecodeResult]:
    """Find the most likely final plaintext.

    Combines charset-driven chaining (base64->hex->...) with a readability
    finishing pass for letter-only ciphers (caesar/rot). Returns None if no
    decode can be found.
    """
    result = chain_detect(text, max_depth=max_depth)
    if result is not None:
        finish = chain_readable(result.text,
                                max_depth=max_depth - result.depth)
        if finish is not None:
            result = DecodeResult(
                method=finish.chain[-1],
                text=finish.text,
                score=finish.score,
                depth=result.depth + finish.depth,
                chain=result.chain + finish.chain,
            )
        return result
    return chain_readable(text, max_depth=max_depth)


def decode_all(text: str, max_depth: int = 5, budget: int = 20000
               ) -> list[DecodeResult]:
    """Expand decode results via BFS chaining with pruning.

    Only results that remain mostly printable are expanded further, which
    keeps the search tractable while still finding chained encodings. A
    global expansion budget prevents runaway on very large inputs.
    """
    results: dict[tuple[int, str], DecodeResult] = {}
    visited: set[str] = {text}
    queue = deque()
    expansions = 0

    def add(parent, method, new_text):
        if new_text is None or new_text == parent.text:
            return
        chain = parent.chain + [method]
        key = (parent.depth + 1, new_text)
        existing = results.get(key)
        if existing is not None and existing.depth <= parent.depth + 1:
            return
        r = DecodeResult(method=chain[-1], text=new_text,
                         score=confidence(new_text),
                         depth=parent.depth + 1, chain=chain)
        results[key] = r
        queue.append(r)

    initial = DecodeResult(method="input", text=text,
                           score=confidence(text), depth=0, chain=[])
    queue.append(initial)

    while queue:
        cur = queue.popleft()
        if not is_meaningful(cur.text) or is_terminal(cur.text):
            continue
        if cur.depth >= max_depth:
            continue
        if cur.text in visited and cur.depth > 0:
            continue  # already expanded this exact text at an earlier depth
        visited.add(cur.text)

        expansions += 1
        if expansions > budget:
            break

        for name in SINGLE_SHOT:
            add(cur, name, _apply(name, cur.text))

        for shift in range(1, 26):
            add(cur, f"caesar({shift})", _caesar(cur.text, shift))

    meaningful = [r for r in results.values() if is_meaningful(r.text)]
    return sorted(meaningful, key=lambda r: (r.score, -r.depth),
                  reverse=True)
