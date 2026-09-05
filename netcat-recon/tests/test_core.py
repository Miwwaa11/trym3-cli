"""Tests for netcat-recon core logic."""

import socket
import threading
import unittest

from netcat_recon.core import (BANNER_PORTS, SERVICE_GUESS, scan_port,
                               scan_ports)


class _TestServer(threading.Thread):
    def __init__(self, port, banner=b"SSH-2.0-OpenSSH test\r\n"):
        super().__init__(daemon=True)
        self.port = port
        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            conn.sendall(self.banner)
            conn.close()

    def stop(self):
        self.sock.close()


class TestScanPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _TestServer(0)
        cls.server.start()
        cls.port = cls.server.sock.getsockname()[1]
        cls.empty = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.empty.bind(("127.0.0.1", 0))
        cls.empty_port = cls.empty.getsockname()[1]
        cls.empty.listen(1)
        cls.empty_server = threading.Thread(
            target=cls._empty_serve, args=(cls.empty,), daemon=True)
        cls.empty_server.start()

    @staticmethod
    def _empty_serve(sock):
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                break
            conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.empty.close()

    def test_open_with_banner(self):
        r = scan_port("127.0.0.1", self.port, timeout=0.5)
        self.assertTrue(r.open)
        if self.port in BANNER_PORTS:
            self.assertIsNotNone(r.banner)

    def test_closed_port(self):
        # pick a definitely-closed port
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        r = scan_port("127.0.0.1", closed_port, timeout=0.1)
        self.assertFalse(r.open)

    def test_service_guess(self):
        self.assertEqual(SERVICE_GUESS.get(22), "SSH")
        self.assertEqual(SERVICE_GUESS.get(443), "HTTPS")


class TestScanPorts(unittest.TestCase):
    def test_scan_list(self):
        results = scan_ports("127.0.0.1", [22, 443], timeout=0.2,
                             concurrency=2)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.open is False for r in results))


if __name__ == "__main__":
    unittest.main()
