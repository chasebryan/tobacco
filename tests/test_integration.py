"""CLI/report integration, with network services replaced by deterministic responses."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

from tobacco.cli import main, render_sarif, render_text
from tobacco.models import CoverageNote, Finding, ScanReport
from tobacco.scanner import ScanOptions, scan


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")

    def call_cli(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(map(str, args)))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_normal_scan_does_not_query_or_collect_dependencies(self):
        with patch("tobacco.scanner.audit_dependencies") as audit, \
                patch("tobacco.scanner.collect_dependencies") as collect:
            report = scan(self.root)
        audit.assert_not_called()
        collect.assert_not_called()
        self.assertEqual(report.dependencies_queried, 0)
        self.assertEqual(report.to_dict()["capabilities"]["dependencies"], "Not requested")

    def test_multiple_advisories_at_same_location_survive_deduplication(self):
        advisories = [{"id": identifier, "database_specific": {"severity": "HIGH"}}
                      for identifier in ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff")]
        with patch("tobacco.dependencies._request", return_value={"vulns": advisories}) as request:
            report = scan(self.root, ScanOptions(dependencies=True))
        self.assertEqual(request.call_count, 1)
        self.assertEqual(report.dependencies_found, 1)
        self.assertEqual(report.dependencies_queried, 1)
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(len({finding.fingerprint for finding in report.findings}), 2)
        sarif = render_sarif(report)
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["details"]["package"], "flask")

    def test_dependency_findings_use_common_cli_filters_and_exit_codes(self):
        response = {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "database_specific": {"severity": "HIGH"}}]}
        with patch("tobacco.dependencies._request", return_value=response):
            code, output, errors = self.call_cli("scan", self.root, "--dependencies", "--format", "json")
            self.assertEqual(code, 1)
            self.assertEqual(errors, "")
            self.assertEqual(json.loads(output)["summary"]["dependencies_queried"], 1)
            code, output, _ = self.call_cli("scan", self.root, "--dependencies", "--ignore-rule", "DEP001", "--format", "json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["summary"]["filtered_findings"], 1)

    def test_dependency_failure_keeps_source_findings_and_exit_two(self):
        (self.root / "app.py").write_text("eval(input())\n", encoding="utf-8")
        with patch("tobacco.dependencies._request", side_effect=URLError("private-network-detail")):
            code, output, errors = self.call_cli("scan", self.root, "--dependencies", "--format", "json", "--fail-on", "none")
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(errors, "")
        self.assertIn("PY001", {finding["rule_id"] for finding in report["findings"]})
        self.assertEqual(report["summary"]["dependencies_queried"], 0)
        self.assertGreater(report["summary"]["analysis_errors"], 0)
        self.assertNotIn("private-network-detail", output)

    def test_excluded_lockfile_never_reaches_network(self):
        with patch("tobacco.dependencies._request") as request:
            report = scan(self.root, ScanOptions(dependencies=True, excludes=["requirements.txt"]))
        request.assert_not_called()
        self.assertEqual(report.dependencies_found, 0)
        self.assertTrue(any("coverage is empty" in note.reason for note in report.coverage))

    def test_http_report_formats_and_filters(self):
        url = "https://localhost/"
        finding = Finding("HTTP002", "Missing HSTS", "medium", "high", url, 1, 1,
                          "Missing HSTS.", "Enable HSTS.", "CWE-319")
        for format_name in ("text", "json", "sarif"):
            report = ScanReport(root=url, mode="http", http_requests=1, findings=[finding])
            with patch("tobacco.cli.probe", return_value=report):
                code, output, errors = self.call_cli("probe", url, "--format", format_name, "--fail-on", "medium")
            self.assertEqual(code, 1)
            self.assertEqual(errors, "")
            if format_name == "json":
                self.assertEqual(json.loads(output)["mode"], "http")
            elif format_name == "sarif":
                run = json.loads(output)["runs"][0]
                self.assertNotIn("originalUriBaseIds", run)
                self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"],
                                 {"artifactLocation": {"uri": url}})
            else:
                self.assertIn("HTTP security check", output)
        report = ScanReport(root=url, mode="http", findings=[finding])
        with patch("tobacco.cli.probe", return_value=report):
            code, output, _ = self.call_cli("probe", url, "--min-severity", "high", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["summary"]["filtered_findings"], 1)

    def test_http_error_is_reported_even_when_findings_disabled(self):
        report = ScanReport(root="https://localhost/", mode="http", http_requests=1,
                            coverage=[CoverageNote("https://localhost/", "Request failed", "error")])
        with patch("tobacco.cli.probe", return_value=report):
            code, output, _ = self.call_cli("probe", report.root, "--fail-on", "none", "--format", "json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["summary"]["analysis_errors"], 1)

    def test_probe_rejects_sensitive_or_invalid_urls_before_network(self):
        for url in ("https://user:password@example.test/", "https://example.test/?token=value", "file:///tmp/file"):
            with self.subTest(url=url), patch("tobacco.http_checks.build_opener") as opener:
                code, output, errors = self.call_cli("probe", url)
                opener.assert_not_called()
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertNotIn("password", errors)
                self.assertNotIn("token=value", errors)

    def test_text_renderer_neutralizes_advisory_control_characters(self):
        finding = Finding("DEP001", "title\x1b", "high", "high", "requirements.txt", 1, 1,
                          "message\x1b", "fix\x1b", "CWE-1395")
        output = render_text(ScanReport(root=str(self.root), findings=[finding]))
        self.assertNotIn("\x1b", output)


if __name__ == "__main__":
    unittest.main()
