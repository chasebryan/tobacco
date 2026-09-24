import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tobacco.cli import render_sarif, render_text
from tobacco.scanner import ScanOptions, scan


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, source):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_never_executes_target(self):
        marker = self.root / "should-not-exist"
        self.write("app.py", f"from pathlib import Path\nPath({str(marker)!r}).touch()\neval(input())\n")
        report = scan(self.root)
        self.assertFalse(marker.exists())
        self.assertIn("PY001", {f.rule_id for f in report.findings})
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.python_files_analyzed, 1)

    def test_symlinks_binary_large_files_and_dependencies_have_coverage_notes(self):
        self.write("app.py", "eval(input())\n")
        self.write("node_modules/dependency.js", "eval(userInput);\n")
        self.write("large.txt", "x" * 101)
        (self.root / "blob.bin").write_bytes(b"\x00\xff\x80")
        (self.root / "link.py").symlink_to(self.root / "app.py")
        (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        report = scan(self.root, ScanOptions(max_file_bytes=100))
        self.assertEqual(report.files_scanned, 1)
        self.assertEqual({n.path for n in report.coverage},
                         {"node_modules", "large.txt", "blob.bin", "link.py", "loop"})
        self.assertFalse(report.errors)

    def test_non_utf8_is_reported(self):
        (self.root / "latin.py").write_bytes(b"# caf\xe9\n")
        report = scan(self.root)
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(report.coverage[0].reason, "Not UTF-8 text")

    def test_can_include_dependencies(self):
        self.write("vendor/tool.py", "eval(input())\n")
        self.assertEqual(scan(self.root).files_scanned, 0)
        self.assertEqual(scan(self.root, ScanOptions(use_default_excludes=False)).files_scanned, 1)

    def test_globs_and_rule_filters(self):
        self.write("test_app.py", "eval(input())\n")
        self.write("src/app.py", "eval(input())\n")
        self.write("generated/app.py", "eval(input())\n")
        report = scan(self.root, ScanOptions(excludes=["test_*", "generated/"]))
        self.assertEqual({f.path for f in report.findings}, {"src/app.py"})
        ignored = scan(self.root, ScanOptions(ignore_rules=["PY001"]))
        self.assertEqual(ignored.findings, [])
        self.assertEqual(ignored.filtered_findings, 3)

    def test_parse_errors_do_not_hide_text_findings_or_other_files(self):
        self.write("broken.py", "password = 'mX4uZ7Qp6Lt9Wv2n'\nif :\n")
        self.write("good.py", "eval(input())\n")
        report = scan(self.root)
        self.assertEqual(report.files_scanned, 2)
        self.assertEqual(report.python_files_analyzed, 1)
        self.assertEqual(len(report.errors), 1)
        self.assertIn("PY001", {f.rule_id for f in report.findings})
        self.assertIn("SEC003", {f.rule_id for f in report.findings})
        self.assertNotIn("mX4uZ7Qp6Lt9Wv2n", json.dumps(report.to_dict()))

    def test_read_failure_preserves_partial_report(self):
        self.write("app.py", "eval(input())\n")
        original_open = os.open

        def deny_file(path, flags, **kwargs):
            if str(path) == "app.py":
                raise PermissionError(13, "Permission denied")
            return original_open(path, flags, **kwargs)

        with patch("tobacco.scanner.os.open", side_effect=deny_file) as patched_open, \
                patch("tobacco.scanner.os.supports_dir_fd", os.supports_dir_fd | {patched_open}):
            report = scan(self.root)
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(len(report.errors), 1)

    def test_single_file_uses_relative_filename(self):
        path = self.write("app.py", "eval(input())\n")
        self.assertEqual(scan(path).findings[0].path, "app.py")

    def test_reports_are_deterministic_and_do_not_include_secret_values(self):
        secret = "qD7sR4bN2yK8vW6t"
        self.write("a.py", "eval(input())\n")
        self.write("z.env", f"DB_PASSWORD={secret}\n")
        first = scan(self.root)
        second = scan(self.root)
        self.assertEqual(first.to_dict(), second.to_dict())
        for output in (render_text(first), json.dumps(first.to_dict()), json.dumps(render_sarif(first))):
            self.assertNotIn(secret, output)

    def test_target_symlink_and_special_files_rejected(self):
        path = self.write("app.py", "pass\n")
        link = self.root / "link.py"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            scan(link)
        if hasattr(os, "mkfifo"):
            fifo = self.root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                scan(fifo)

    def test_text_report_escapes_terminal_control_characters(self):
        self.write("bad\x1b[31m.py", "eval(input())\n")
        output = render_text(scan(self.root))
        self.assertNotIn("\x1b", output)
        self.assertIn("\\u001b", output)

    def test_sarif_encodes_paths_and_records_incomplete_analysis(self):
        self.write("nested/file #1.py", "eval(input())\n")
        self.write("bad.py", "if :\n")
        run = render_sarif(scan(self.root))["runs"][0]
        result = run["results"][0]
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "nested/file%20%231.py")
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(result["properties"]["status"], "needs_review")

    @unittest.skipUnless(os.name == "posix", "POSIX filename bytes")
    def test_sarif_handles_non_utf8_filename_bytes(self):
        path = os.fsencode(self.root) + b"/invalid-\xff.py"
        try:
            stream = open(path, "wb")
        except OSError as error:
            if error.errno == errno.EILSEQ:
                self.skipTest("This filesystem requires valid UTF-8 filenames")
            raise
        with stream:
            stream.write(b"eval(input())\n")
        report = scan(self.root)
        run = render_sarif(report)["runs"][0]
        location = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "invalid-%FF.py")
        self.assertIn("\\udcff", render_text(report))
        json.dumps(report.to_dict())

    def test_directory_replaced_with_symlink_cannot_escape_target(self):
        selected = self.root / "selected"
        selected.mkdir()
        queued = selected / "queued"
        queued.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "private.py").write_text("eval(input())\n")
        original_open = os.open

        def replace_directory(path, flags, **kwargs):
            if str(path) == "queued":
                queued.rmdir()
                queued.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, **kwargs)

        with patch("tobacco.scanner.os.open", side_effect=replace_directory) as patched_open, \
                patch("tobacco.scanner.os.supports_dir_fd", os.supports_dir_fd | {patched_open}):
            report = scan(selected)
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(report.findings, [])
        self.assertEqual(len(report.errors), 1)

    def test_max_size_read_limit_applies_if_file_grows_after_stat(self):
        path = self.write("app.py", "x" * 100)
        with patch("tobacco.scanner.os.fstat") as metadata:
            metadata.return_value.st_size = 1
            metadata.return_value.st_mode = path.stat().st_mode
            report = scan(path, ScanOptions(max_file_bytes=50))
        self.assertEqual(report.files_scanned, 0)
        self.assertEqual(report.coverage[0].reason, "Exceeds maximum file size")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = Path(__file__).resolve().parents[1]

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "tobacco", *map(str, args)],
                              cwd=self.repo, text=True, capture_output=True, timeout=20)

    def test_help_version_and_rule_catalog(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        self.assertIn("Tobacco 0.1.0", self.run_cli("--version").stdout)
        rules = self.run_cli("rules")
        self.assertEqual(rules.returncode, 0)
        self.assertIn("PY001", rules.stdout)
        self.assertIn("SEC001", rules.stdout)

    def test_exit_codes_and_json_stdout(self):
        path = self.root / "app.py"
        path.write_text("eval(input())\n")
        result = self.run_cli("scan", path, "--format", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["summary"]["findings"], 1)
        self.assertEqual(self.run_cli("scan", path, "--fail-on", "none").returncode, 0)
        self.assertEqual(self.run_cli("scan", path, "--min-severity", "critical").returncode, 0)
        path.write_text("print('ok')\n")
        self.assertEqual(self.run_cli("scan", path).returncode, 0)

    def test_parse_error_exit_two_even_with_fail_on_none(self):
        path = self.root / "app.py"
        path.write_text("if :\n")
        result = self.run_cli("scan", path, "--fail-on", "none", "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["summary"]["analysis_errors"], 1)

    def test_invalid_inputs_exit_two(self):
        for args in [
            ("scan", self.root / "missing"),
            ("scan", self.root, "--max-file-bytes", "0"),
            ("scan", self.root, "--ignore-rule", "MISSING"),
        ]:
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args).returncode, 2)


if __name__ == "__main__":
    unittest.main()
