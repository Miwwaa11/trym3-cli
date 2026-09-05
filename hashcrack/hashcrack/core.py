"""Core logic for hashcrack: hash identification and cracking."""

from __future__ import annotations

import hashlib
import itertools
import re
from dataclasses import dataclass


@dataclass
class HashMatch:
    name: str
    regex: str
    example: str


HASH_PATTERNS: list[HashMatch] = [
    HashMatch("MD5", r"^[a-fA-F0-9]{32}$", "5d41402abc4b2a76b9719d911017c592"),
    HashMatch("SHA-1", r"^[a-fA-F0-9]{40}$", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
    HashMatch("SHA-224", r"^[a-fA-F0-9]{56}$", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
    HashMatch("SHA-256", r"^[a-fA-F0-9]{64}$", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
    HashMatch("SHA-384", r"^[a-fA-F0-9]{96}$", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
    HashMatch("SHA-512", r"^[a-fA-F0-9]{128}$",
              "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    HashMatch("MD4", r"^[a-fA-F0-9]{32}$", "aaf4c61ddcc5e8a2dabede0f3b482cd9"),
    HashMatch("NTLM", r"^[a-fA-F0-9]{32}$", "32ed87bdb5fdc5e9cba88547376818d4"),
    HashMatch("MySQL323", r"^[a-fA-F0-9]{16}$", "8f982be407dbea0f"),
    HashMatch("MySQL5", r"^\*[a-fA-F0-9]{40}$", "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"),
    HashMatch("SHA-1 base64 (ldap)", r"^\{SHA\}[A-Za-z0-9+/=]+$", "{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="),
    HashMatch("SHA-256 base64 (ldap)", r"^\{SSHA256\}[A-Za-z0-9+/=]+$", "{SSHA256}abc"),
    HashMatch("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
              "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"),
    HashMatch("PHPass (WordPress)", r"^\$[HP]\$[./0-9A-Za-z]{31}$",
              "$P$BXYLZ2lO7DqLqTzSZV2N2Y2Y1uQ0p1H"),
    HashMatch("Django (PBKDF2)", r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$",
              "pbkdf2_sha256$216000$salt$hash"),
    HashMatch("APR1 (Apache)", r"^\$apr1\$[^$]+\$[./A-Za-z0-9]{22}$",
              "$apr1$7vz9u9q4$NvZ2nQjJdG6F8WpOh.Hzu/"),
    HashMatch("SHA-1 (Crypt)", r"^\$[156]\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]+$",
              "$6$salt$hash"),
    HashMatch("Unix DES (crypt)", r"^[./A-Za-z0-9]{13}$", "abcXYZ123abc"),
    HashMatch("Base64 (guessed)", r"^[A-Za-z0-9+/]{16,}={0,2}$", "SGVsbG8gd29ybGQ="),
    HashMatch("UUID MD5", r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-3[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$",
              "550e8400-e29b-41d4-a716-446655440000"),
    HashMatch("CRC32", r"^[a-fA-F0-9]{8}$", "d41d8cd9"),
]


MAILCHIMP_LOOKUP = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}


def identify_hash(hash_str: str) -> list[HashMatch]:
    """Return possible hash type matches for the given hash string."""
    s = hash_str.strip()
    matches: list[HashMatch] = []
    for pattern in HASH_PATTERNS:
        if re.match(pattern.regex, s):
            matches.append(pattern)
    return matches


def crack_hash(hash_str: str, wordlist: list[str],
               hash_type: str | None = None) -> str | None:
    """Try to crack a hash against a wordlist. Returns matching plaintext."""
    s = hash_str.strip()

    candidates: list[HashMatch] = []
    if hash_type:
        for m in HASH_PATTERNS:
            if m.name.lower() == hash_type.lower():
                candidates.append(m)
                break
    else:
        candidates = identify_hash(s)
        candidates = [m for m in candidates if m.name in MAILCHIMP_LOOKUP]

    if not candidates:
        return None

    for word in wordlist:
        w = word.strip()
        if not w:
            continue
        for match in candidates:
            algo = MAILCHIMP_LOOKUP.get(match.name)
            if algo is None:
                continue
            if algo(w.encode()).hexdigest().lower() == s.lower():
                return w
        if s.lower() in (
            hashlib.md5(w.encode()).hexdigest().lower(),
            hashlib.sha1(w.encode()).hexdigest().lower(),
        ):
            return w
    return None


def brute_force(hash_str: str, charset: str, max_len: int,
                hash_type: str | None = None) -> str | None:
    """Brute-force a hash within a given charset length. Slow, use sparingly."""
    s = hash_str.strip().lower()

    algos = [hashlib.md5, hashlib.sha1, hashlib.sha256]
    if hash_type:
        for name, fn in MAILCHIMP_LOOKUP.items():
            if name.lower() == hash_type.lower():
                algos = [fn]
                break

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            word = "".join(combo)
            for fn in algos:
                if fn(word.encode()).hexdigest() == s:
                    return word
    return None
