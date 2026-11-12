import unittest

from checker import headers as h
from checker.analyzer import grade_for, run_checks, summarize
from checker.cookies import check_cookies


class HeaderChecks(unittest.TestCase):
    def test_hsts_missing(self):
        self.assertEqual(h.check_hsts({}, True)["status"], "fail")

    def test_hsts_on_http_fails(self):
        self.assertEqual(h.check_hsts({"strict-transport-security": "max-age=99999999"}, False)["status"], "fail")

    def test_hsts_short_max_age_warns(self):
        r = h.check_hsts({"strict-transport-security": "max-age=300"}, True)
        self.assertEqual(r["status"], "warn")

    def test_hsts_good(self):
        r = h.check_hsts({"strict-transport-security": "max-age=31536000; includeSubDomains"}, True)
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["points"], r["max"])

    def test_csp_missing(self):
        self.assertEqual(h.check_csp({})["status"], "fail")

    def test_csp_unsafe_inline_warns(self):
        r = h.check_csp({"content-security-policy": "script-src 'self' 'unsafe-inline'"})
        self.assertEqual(r["status"], "warn")

    def test_csp_good(self):
        self.assertEqual(h.check_csp({"content-security-policy": "default-src 'self'"})["status"], "pass")

    def test_frame_protection_via_xfo(self):
        self.assertEqual(h.check_frame_protection({"x-frame-options": "DENY"})["status"], "pass")

    def test_frame_protection_via_csp(self):
        self.assertEqual(h.check_frame_protection({"content-security-policy": "frame-ancestors 'none'"})["status"], "pass")

    def test_nosniff(self):
        self.assertEqual(h.check_nosniff({"x-content-type-options": "nosniff"})["status"], "pass")
        self.assertEqual(h.check_nosniff({})["status"], "fail")

    def test_info_leak(self):
        self.assertEqual(h.check_info_leak({"server": "nginx/1.18.0"})["status"], "warn")
        self.assertEqual(h.check_info_leak({"server": "cloudflare"})["status"], "pass")


class CookieChecks(unittest.TestCase):
    def test_no_cookies_skipped(self):
        self.assertIsNone(check_cookies([], True))

    def test_insecure_cookie(self):
        r = check_cookies(["sid=abc; Path=/"], True)
        self.assertIn("Secure 없음", r["message"])
        self.assertIn("HttpOnly 없음", r["message"])
        self.assertNotEqual(r["status"], "pass")

    def test_secure_cookie(self):
        r = check_cookies(["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"], True)
        self.assertEqual(r["status"], "pass")

    def test_samesite_none_requires_secure(self):
        r = check_cookies(["a=b; HttpOnly; SameSite=None"], False)
        self.assertIn("SameSite=None", r["message"])


class Scoring(unittest.TestCase):
    def test_grades(self):
        self.assertEqual(grade_for(95), "A")
        self.assertEqual(grade_for(82), "B")
        self.assertEqual(grade_for(70), "C")
        self.assertEqual(grade_for(55), "D")
        self.assertEqual(grade_for(10), "F")

    def test_perfect_site_gets_A(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }
        s = summarize(run_checks(headers, [], True))
        self.assertEqual(s["grade"], "A")
        self.assertEqual(s["percent"], 100)

    def test_empty_site_gets_F(self):
        s = summarize(run_checks({}, [], True))
        self.assertEqual(s["grade"], "F")


if __name__ == "__main__":
    unittest.main()
