"""Tests for the offsetfind core (run with a Python 3.13 venv)."""

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

from offsetfind import core

GCC = shutil.which("gcc")

VULN_C = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){
    char buf[32];
    printf("prompt> ");
    fflush(stdout);
    read(0, buf, 256);
    return 0;
}
"""

SAFE_C = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){
    char buf[8];
    read(0, buf, 8);
    return 0;
}
"""


def _compile(src, extra=()):
    d = tempfile.mkdtemp(prefix="offsetfind_test_")
    src_path = os.path.join(d, "t.c")
    with open(src_path, "w") as fh:
        fh.write(src)
    out = os.path.join(d, "tbin")
    cmd = ["gcc", "-O0", "-fno-stack-protector", src_path, "-o", out, *extra]
    subprocess.run(cmd, check=True, capture_output=True)
    return out


@unittest.skipUnless(GCC, "gcc not available")
class TestPattern(unittest.TestCase):
    def test_make_pattern_64_bits(self):
        pattern = core.make_pattern(200, bits=64)
        self.assertEqual(len(pattern), 200)
        word = pattern[40:48]  # 8-byte word at offset 40
        value = int.from_bytes(word, "little")
        self.assertEqual(core.find_offset_in_pattern(value, 64), 40)

    def test_make_pattern_32_bits(self):
        pattern = core.make_pattern(128, bits=32)
        word = pattern[16:20]
        value = int.from_bytes(word, "little")
        self.assertEqual(core.find_offset_in_pattern(value, 32), 16)

    def test_unmatched_value_returns_none(self):
        self.assertIsNone(core.find_offset_in_pattern(0xDEADBEEF, 64))


@unittest.skipUnless(GCC, "gcc not available")
class TestLocalCrash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_cwd = os.getcwd()
        cls._workdir = tempfile.mkdtemp(prefix="offsetfind_crash_")
        os.chdir(cls._workdir)
        cls.vuln_pie = _compile(VULN_C)
        cls.vuln_nopie = _compile(VULN_C, ["-no-pie"])
        cls.safe = _compile(SAFE_C)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls._old_cwd)

    def test_crash_offset_40(self):
        result = core.find_offset(self.vuln_pie)
        self.assertTrue(result.crash.crashed)
        self.assertEqual(result.crash.offset, 40)

    def test_crash_offset_nopie(self):
        result = core.find_offset(self.vuln_nopie)
        self.assertTrue(result.crash.crashed)
        self.assertEqual(result.crash.offset, 40)

    def test_no_crash_small_input(self):
        proc = core.run_local_crash(self.vuln_pie, b"A" * 20)
        self.assertFalse(proc.crashed)

    def test_safe_binary_does_not_crash(self):
        result = core.find_offset(self.safe)
        self.assertFalse(result.crash.crashed)


@unittest.skipUnless(GCC, "gcc not available")
class TestChecksec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln_pie = _compile(VULN_C)
        cls.vuln_nopie = _compile(VULN_C, ["-no-pie"])

    def test_pie_detected(self):
        cs = core.get_checksec(self.vuln_pie)
        self.assertEqual(cs.arch_bits, 64)
        self.assertTrue(cs.pie)
        self.assertFalse(cs.canary)

    def test_nopie_detected(self):
        cs = core.get_checksec(self.vuln_nopie)
        self.assertFalse(cs.pie)


class TestRemoteProbe(unittest.TestCase):
    def _serve(self, behavior):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _run():
            conn, _ = srv.accept()
            conn.settimeout(2)
            try:
                if behavior == "respond":
                    conn.recv(1024)
                    conn.sendall(b"echo: got it\n")
                    conn.close()
                else:  # close right away -> looks like a crash
                    conn.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
            srv.close()

        th = threading.Thread(target=_run, daemon=True)
        th.start()
        return port

    def test_remote_responds_no_crash(self):
        port = self._serve("respond")
        hit, _ = core.probe_remote("127.0.0.1", port, b"AAAA", timeout=2)
        self.assertIs(hit, False)

    def test_remote_closes_crash_like(self):
        port = self._serve("crash")
        hit, _ = core.probe_remote("127.0.0.1", port, b"AAAA", timeout=2)
        self.assertIs(hit, True)

    def test_remote_unreachable(self):
        hit, note = core.probe_remote("127.0.0.1", 1, b"AAAA", timeout=1)
        self.assertIsNone(hit)
        self.assertIn("failed", note)


if __name__ == "__main__":
    unittest.main()