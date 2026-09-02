"""Tests for the rsatool core."""

import json
import os
import tempfile
import unittest
from sympy import mod_inverse, nextprime

from rsatool.core import (RSAParams, attack_common_factor, attack_fermat,
                          attack_low_exp, attack_wiener, bytes_to_text,
                          compute_private, int_to_bytes, load_keys_from_json,
                          run_all)


def _b32i(s: str) -> int:
    return int.from_bytes(s.encode(), "big")


class TestLowExponent(unittest.TestCase):
    def test_cube_root(self):
        p = nextprime(2**40 + 1)
        q = nextprime(2**40 + 2_000_000)
        n = p * q
        m = _b32i("low_exp_ok")
        c = m**3
        params = RSAParams(n=n, e=3, c=c)
        res = attack_low_exp(params)
        self.assertTrue(res.success)
        self.assertEqual(res.plaintext, "low_exp_ok")

    def test_high_e_no_attack(self):
        res = attack_low_exp(RSAParams(n=1009, e=65537, c=12345))
        self.assertFalse(res.success)


class TestWiener(unittest.TestCase):
    def test_small_d(self):
        p = nextprime(2**40 + 1)
        q = nextprime(2**40 + 2_000_000)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 99991
        e = mod_inverse(d, phi)
        m = _b32i("wiener_ok")
        c = pow(m, e, n)
        res = attack_wiener(RSAParams(n=n, e=e, c=c))
        self.assertTrue(res.success)
        self.assertEqual(res.d, d)
        self.assertEqual(res.p * res.q, n)
        self.assertEqual(res.plaintext, "wiener_ok")


class TestFermat(unittest.TestCase):
    def test_close_primes(self):
        p = nextprime(2**40 + 1)
        q = nextprime(p + 2)
        n = p * q
        e = 65537
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)
        m = _b32i("fermat_ok")
        c = pow(m, e, n)
        res = attack_fermat(RSAParams(n=n, e=e, c=c))
        self.assertTrue(res.success)
        self.assertEqual(res.p, p)
        self.assertEqual(res.q, q)
        self.assertEqual(res.plaintext, "fermat_ok")

    def test_wide_primes_times_out(self):
        res = attack_fermat(RSAParams(n=nextprime(2**40 + 1) *
                                      nextprime(2**42 + 1), e=3, c=1),
                            max_iter=1000)
        self.assertFalse(res.success)


class TestCommonFactor(unittest.TestCase):
    def test_shared_prime(self):
        p = nextprime(2**40 + 1000)
        q1 = nextprime(2**40 + 2_000_000)
        q2 = nextprime(2**40 + 4_000_000)
        e = 65537
        m = _b32i("common_ok")
        k1 = RSAParams(n=p * q1, e=e, c=pow(m, e, p * q1))
        k2 = RSAParams(n=p * q2, e=e, c=pow(m, e, p * q2))
        res = attack_common_factor([k1, k2])
        self.assertTrue(res.success)
        self.assertEqual(res.p, p)
        self.assertEqual(res.plaintext, "common_ok")

    def test_needs_two_keys(self):
        res = attack_common_factor([RSAParams(n=123, e=5, c=0)])
        self.assertFalse(res.success)


class TestPrivateAndText(unittest.TestCase):
    def test_compute_private(self):
        p, q = 61, 53
        n = p * q
        e = 17
        params = RSAParams(n=n, e=e, c=0)
        d = compute_private(params, p, q)
        self.assertEqual(pow(5, e * d, n), 5 % n)

    def test_n_is_square(self):
        p = 99991
        n = p * p
        e = 65537
        params = RSAParams(n=n, e=e, c=0)
        d = compute_private(params, p, p)
        self.assertEqual(pow(7, e * d, n), 7 % n)

    def test_bytes_text_roundtrip(self):
        b = b"hello rsa"
        self.assertEqual(bytes_to_text(b), b.decode())
        self.assertEqual(int_to_bytes(int.from_bytes(b, "big")), b)


class TestRunAll(unittest.TestCase):
    def test_stops_on_success(self):
        p = nextprime(2**40 + 1)
        q = nextprime(2**40 + 2_000_000)
        n = p * q
        m = _b32i("low_exp_ok")
        params = RSAParams(n=n, e=3, c=m**3)
        results = run_all([params], timeout=5)
        self.assertTrue(any(r.success for r in results))
        self.assertLessEqual(len(results), 2)  # stops right after success

    def test_all_option_runs_all(self):
        p = nextprime(2**40 + 1)
        q = nextprime(2**40 + 2_000_000)
        n = p * q
        m = _b32i("xf")
        params = RSAParams(n=n, e=3, c=m**3)
        results = run_all([params], stop_on_success=False, timeout=5)
        self.assertEqual(len(results), 4)


class TestLoadKeys(unittest.TestCase):
    def test_load_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump({"keys": [{"n": "16", "e": "3", "c": "0x5"},
                                {"n": 0x1A, "e": 1, "c": "9"}]}, fh)
            fh.flush()
            keys = load_keys_from_json(fh.name)
        os.unlink(fh.name)
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0].n, 16)
        self.assertEqual(keys[0].c, 5)
        self.assertEqual(keys[1].n, 26)


if __name__ == "__main__":
    unittest.main()