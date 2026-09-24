from email.message import Message
from http.client import BadStatusLine
from io import BytesIO
import json
import ssl
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPHandler, build_opener
from urllib.response import addinfourl

from tobacco.http_checks import _NoRedirect, probe


class HttpCheckTests(unittest.TestCase):
    def response(self, headers=(), status=200):
        response = MagicMock()
        response.status = status
        response.headers = Message()
        for name, value in headers:
            response.headers[name] = value
        response.__enter__.return_value = response
        return response

    def run_probe(self, headers=(), url="https://example.test/", status=200):
        response = self.response(headers, status)
        with patch("tobacco.http_checks.build_opener") as build:
            build.return_value.open.return_value = response
            report = probe(url)
        self.assertEqual(build.return_value.open.call_count, 1)
        response.read.assert_not_called()
        response.__exit__.assert_called_once()
        return report

    def rules(self, report):
        return {finding.rule_id for finding in report.findings}

    def test_html_response_headers_and_cookie_flags(self):
        report = self.run_probe([
            ("Content-Type", "text/html; charset=utf-8"),
            ("Set-Cookie", "session=secret-cookie-value; Path=/"),
        ])
        self.assertEqual(self.rules(report), {"HTTP002", "HTTP003", "HTTP004",
                                             "HTTP005", "HTTP006", "HTTP007"})
        self.assertEqual(report.http_requests, 1)
        self.assertEqual(report.mode, "http")
        self.assertFalse(report.errors)
        self.assertNotIn("secret-cookie-value", json.dumps(report.to_dict()))
        self.assertTrue(all(finding.path == "https://example.test/" for finding in report.findings))

    def test_protected_response(self):
        report = self.run_probe([
            ("Content-Type", "text/html"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax"),
        ])
        self.assertEqual(report.findings, [])
        self.assertEqual(report.coverage, [])

    def test_plain_http_is_flagged_without_https_only_checks(self):
        report = self.run_probe([("Content-Type", "text/html")], "http://localhost:8000/")
        self.assertEqual(self.rules(report), {"HTTP001", "HTTP003", "HTTP004"})

    def test_non_html_does_not_run_html_checks(self):
        report = self.run_probe([("Content-Type", "application/json")])
        self.assertEqual(self.rules(report), {"HTTP002"})
        self.assertEqual(len(report.coverage), 1)
        self.assertIn("not HTML", report.coverage[0].reason)

    def test_invalid_or_disabled_hsts_is_flagged(self):
        for value in ("", "max-age=0", "max-age=000", "max-age=invalid", "includeSubDomains",
                      'max-age="3600', 'max-age=3600"'):
            with self.subTest(value=value):
                self.assertIn("HTTP002", self.rules(self.run_probe([("Strict-Transport-Security", value)])))

    def test_positive_hsts_and_case_insensitive_headers(self):
        report = self.run_probe([
            ("strict-transport-security", 'MAX-AGE="3600"; includeSubDomains'),
            ("content-type", "TEXT/HTML; charset=utf-8"),
            ("x-content-type-options", "NoSniff"),
            ("content-security-policy", "default-src 'none'"),
        ])
        self.assertEqual(report.findings, [])

    def test_duplicate_and_malformed_hsts_directives_are_rejected(self):
        for value in (
            "max-age=3600; max-age=0", "max-age=0; max-age=3600",
            "max-age=3600; MAX-AGE=3600", "max-age=3600; max-age",
            "max-age=3600; includeSubDomains; includesubdomains",
            "max-age=3600; includeSubDomains=no", "max-age=3600; broken value",
            "max-age=3600; preload; preload", 'max-age=3600; unknown="unfinished',
            "max-age=3600; max-age=no", "max-age=3600, max-age=0",
        ):
            with self.subTest(value=value):
                report = self.run_probe([("Strict-Transport-Security", value)])
                self.assertIn("HTTP002", self.rules(report))

    def test_hsts_quoted_extensions_do_not_hide_or_invent_directives(self):
        for value in (
            'max-age=3600; extension="max-age=0; data"',
            'extension="escaped\\\"; max-age=0"; max-age=3600',
            '; max-age="\\3600"; includeSubDomains; preload;',
        ):
            with self.subTest(value=value):
                report = self.run_probe([("Strict-Transport-Security", value)])
                self.assertNotIn("HTTP002", self.rules(report))

    def test_report_only_csp_is_not_enforcing(self):
        report = self.run_probe([
            ("Content-Type", "text/html"),
            ("Content-Security-Policy-Report-Only", "default-src 'self'"),
        ])
        self.assertIn("HTTP004", self.rules(report))

    def test_multiple_csp_headers_consider_all_enforced_policies(self):
        report = self.run_probe([
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", ""),
            ("Content-Security-Policy", "default-src 'none'"),
        ])
        self.assertNotIn("HTTP004", self.rules(report))

    def test_multiple_cookies_are_counted_without_exposing_names_or_values(self):
        report = self.run_probe([
            ("Set-Cookie", "first_sensitive_name=first-sensitive-value; Path=/"),
            ("Set-Cookie", "second_sensitive_name=second-sensitive-value; SameSite=None; Secure"),
        ])
        findings = {finding.rule_id: finding for finding in report.findings}
        self.assertEqual(findings["HTTP005"].details["cookie_count"], 1)
        self.assertEqual(findings["HTTP006"].details["cookie_count"], 2)
        self.assertEqual(findings["HTTP007"].details["cookie_count"], 2)
        serialized = json.dumps(report.to_dict())
        for secret in ("first_sensitive_name", "second_sensitive_name", "first-sensitive-value", "second-sensitive-value"):
            self.assertNotIn(secret, serialized)

    def test_malformed_cookie_marks_incomplete_coverage(self):
        report = self.run_probe([("Set-Cookie", "not a valid cookie")])
        self.assertEqual(len(report.errors), 1)
        self.assertIn("could not be parsed", report.errors[0].reason)

    def test_cookie_extensions_are_attributes_not_additional_cookies(self):
        for suffix in ("Priority=High", "Partitioned", "Priority=High; Partitioned",
                       'NewExtension=secret-extension; BareExtension; Other="quoted-extension"'):
            with self.subTest(suffix=suffix):
                report = self.run_probe([
                    ("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax; " + suffix),
                ])
                self.assertFalse(self.rules(report) & {"HTTP005", "HTTP006", "HTTP007"})
                self.assertFalse(report.errors)
                self.assertNotIn("secret-extension", json.dumps(report.to_dict()))

    def test_cookie_extensions_cannot_supply_missing_protections(self):
        report = self.run_probe([
            ("Set-Cookie", "session=secret; Priority=High; Partitioned; Extension=Secure; Other=HttpOnly"),
        ])
        findings = {finding.rule_id: finding for finding in report.findings}
        for rule in ("HTTP005", "HTTP006", "HTTP007"):
            self.assertEqual(findings[rule].details["cookie_count"], 1)
        self.assertFalse(report.errors)

    def test_quoted_cookie_value_and_flag_presence(self):
        for value in ('session="secret=encoded"', 'session=""', 'session='):
            with self.subTest(value=value):
                report = self.run_probe([
                    ("Set-Cookie", value + "; Secure=no; HttpOnly=false; SameSite=Strict; Partitioned"),
                ])
                self.assertFalse(self.rules(report) & {"HTTP005", "HTTP006", "HTTP007"})
                self.assertFalse(report.errors)
                self.assertNotIn("secret=encoded", json.dumps(report.to_dict()))

    def test_malformed_cookie_pairs_do_not_hide_incomplete_checks(self):
        for value in ('session="unterminated', 'session="x; Secure; HttpOnly; SameSite=Lax"',
                      'session=x"', "=value; Secure", "bad name=value; Secure", "session=x\x00",
                      "session=" + "x" * 65536):
            with self.subTest(value=value[:50]):
                report = self.run_probe([("Set-Cookie", value)])
                self.assertEqual(len(report.errors), 1)
                self.assertFalse(self.rules(report) & {"HTTP005", "HTTP006", "HTTP007"})

    def test_repeated_samesite_uses_last_attribute(self):
        for attributes, expected in (("SameSite=Lax; SameSite=None", True),
                                     ("SameSite=None; SameSite=Lax", False)):
            with self.subTest(attributes=attributes):
                report = self.run_probe([("Set-Cookie", "session=x; " + attributes)])
                self.assertEqual("HTTP007" in self.rules(report), expected)

    def test_credentials_queries_fragments_and_invalid_urls_never_make_requests(self):
        invalid = [
            "https://user:password@example.test/", "https://example.test/?token=secret",
            "https://example.test/#secret", "https://example.test/?", "https://example.test/#",
            "file:///etc/passwd", "ftp://example.test/file", "javascript:alert(1)",
            "https:///missing", "https://example.test:0/", "https://example.test:70000/",
            "https://example.test:/", "https://exam ple.test/", "https://example.test/\n",
            " https://example.test/", "https://example.test\\@other.test/",
            "https://[::1", "https://[fe80::1%25eth0]/", "https://-invalid.test/",
            "https://[::1]garbage/", "https://[v1.future]/", "https://example.test../",
            "https://example.test/%zz", "", None,
        ]
        with patch("tobacco.http_checks.build_opener") as build:
            for url in invalid:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    probe(url)
            build.assert_not_called()

    def test_url_normalization_and_single_request_settings(self):
        response = self.response()
        with patch("tobacco.http_checks.build_opener") as build:
            build.return_value.open.return_value = response
            report = probe("HTTPS://EXAMPLE.TEST/café", timeout=4)
        self.assertEqual(report.root, "https://example.test/caf%C3%A9")
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, report.root)
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertIsNone(request.get_header("Cookie"))
        self.assertEqual(build.return_value.open.call_args.kwargs, {"timeout": 4})
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], _NoRedirect)

    def test_ipv6_url_is_supported(self):
        report = self.run_probe(url="http://[0:0:0:0:0:0:0:1]:8080")
        self.assertEqual(report.root, "http://[::1]:8080/")

    def test_timeout_must_be_positive_finite_and_bounded(self):
        with patch("tobacco.http_checks.build_opener") as build:
            for timeout in (0, -1, 120, float("nan"), float("inf"), "5", True):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    probe("https://example.test/", timeout=timeout)
            build.assert_not_called()

    def test_redirects_return_original_response_without_following_or_leaking_location(self):
        response = self.response([("Location", "https://other.test/?secret=redirect-token")], 302)
        handler = _NoRedirect()
        for code in (301, 302, 303, 307, 308):
            method = getattr(handler, f"http_error_{code}")
            self.assertIs(method(None, response, code, "Redirect", response.headers), response)
        report = self.run_probe([
            ("Content-Type", "text/html"),
            ("Location", "https://other.test/?secret=redirect-token"),
        ], status=302)
        self.assertEqual(report.options["response_status"], 302)
        self.assertIn("not followed", report.coverage[0].reason)
        self.assertNotIn("redirect-token", json.dumps(report.to_dict()))

    def test_real_opener_does_not_follow_redirects(self):
        class SimulatedTransport(HTTPHandler):
            def __init__(self):
                super().__init__()
                self.urls = []

            def http_open(self, request):
                self.urls.append(request.full_url)
                headers = Message()
                headers["Location"] = "http://other.test/?token=private"
                headers["Content-Type"] = "text/html"
                response = addinfourl(BytesIO(b"unread body"), headers, request.full_url, 302)
                response.msg = "Found"
                return response

        transport = SimulatedTransport()

        def opener_with_simulated_transport(*handlers):
            return build_opener(*handlers, transport)

        with patch("tobacco.http_checks.build_opener", side_effect=opener_with_simulated_transport):
            report = probe("http://selected.test/")
        self.assertEqual(transport.urls, ["http://selected.test/"])
        self.assertEqual(report.options["response_status"], 302)
        self.assertIn("HTTP004", self.rules(report))
        self.assertFalse(report.errors)

    def test_http_errors_preserve_headers_and_mark_incomplete_coverage(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        body = BytesIO(b"secret response body")
        error = HTTPError("https://example.test/", 403, "secret status reason", headers, body)
        with patch("tobacco.http_checks.build_opener") as build:
            build.return_value.open.side_effect = error
            report = probe("https://example.test/")
        self.assertIn("HTTP004", self.rules(report))
        self.assertEqual(len(report.errors), 1)
        self.assertIn("403", report.errors[0].reason)
        self.assertTrue(body.closed)
        self.assertNotIn("secret", json.dumps(report.to_dict()))

    def test_certificate_failure_is_reported_without_retry(self):
        for error in (ssl.SSLCertVerificationError(1, "secret certificate details"),
                      URLError(ssl.SSLCertVerificationError(1, "secret certificate details"))):
            with self.subTest(error=type(error).__name__), patch("tobacco.http_checks.build_opener") as build:
                build.return_value.open.side_effect = error
                report = probe("https://example.test/")
            self.assertEqual(self.rules(report), {"HTTP008"})
            self.assertEqual(len(report.errors), 1)
            self.assertEqual(build.return_value.open.call_count, 1)
            self.assertNotIn("secret certificate details", json.dumps(report.to_dict()))

    def test_network_timeout_and_protocol_errors_have_no_sensitive_exception_text(self):
        for error in (URLError("secret network diagnostic"), TimeoutError("secret timeout"),
                      BadStatusLine("secret malformed status")):
            with self.subTest(error=type(error).__name__), patch("tobacco.http_checks.build_opener") as build:
                build.return_value.open.side_effect = error
                report = probe("https://example.test/")
            self.assertEqual(report.findings, [])
            self.assertEqual(len(report.errors), 1)
            self.assertNotIn("secret", json.dumps(report.to_dict()))


if __name__ == "__main__":
    unittest.main()
