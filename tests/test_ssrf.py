import os
import unittest
from unittest import mock

from checker.ssrf import UnsafeURL, validate_url


def fake_dns(ip):
    return lambda host, port, proto=0: [(2, 1, 6, "", (ip, port))]


class SSRFGuard(unittest.TestCase):
    def setUp(self):
        os.environ.pop("ALLOW_PRIVATE", None)

    def test_rejects_non_http_scheme(self):
        for url in ("file:///etc/passwd", "ftp://example.com", "gopher://x"):
            with self.assertRaises(UnsafeURL):
                validate_url(url)

    def test_rejects_credentials(self):
        with self.assertRaises(UnsafeURL):
            validate_url("http://user:pw@example.com")

    def test_rejects_private_addresses(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9",
                   "169.254.169.254", "0.0.0.0", "::1"):
            with mock.patch("socket.getaddrinfo", fake_dns(ip)):
                with self.assertRaises(UnsafeURL, msg=ip):
                    validate_url("http://evil.example.com")

    def test_allows_public_address(self):
        with mock.patch("socket.getaddrinfo", fake_dns("93.184.216.34")):
            self.assertEqual(validate_url("https://example.com"), "https://example.com")

    def test_allow_private_override(self):
        os.environ["ALLOW_PRIVATE"] = "1"
        try:
            self.assertEqual(validate_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")
        finally:
            os.environ.pop("ALLOW_PRIVATE", None)


if __name__ == "__main__":
    unittest.main()
