"""Dependency metadata and OSV behavior; all HTTP is mocked."""

import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from tobacco.dependencies import (
    Dependency, OSV_QUERY_URL, _NoRedirect, _request,
    audit_dependencies, collect_dependencies,
)


class DependencyParsingTests(unittest.TestCase):
    def test_requirements_exact_pins_extras_hashes_and_continuations(self):
        source = "# packages\nRequests[security]==2.31.0\nDjango == 4.2.1 \\\n    --hash=sha256:abcdef # generated hash\n"
        dependencies, notes = collect_dependencies("dev/requirements-dev.txt", source)
        self.assertEqual([(d.name, d.version, d.line) for d in dependencies],
                         [("requests", "2.31.0", 2), ("django", "4.2.1", 3)])
        self.assertEqual(notes, [])

    def test_requirements_markers_query_all_pinned_variants(self):
        source = "flask==2.0.0; python_version < '3.10'\nflask==3.0.0; python_version >= '3.10'\n"
        dependencies, notes = collect_dependencies("requirements.txt", source)
        self.assertEqual(len(dependencies), 2)
        self.assertEqual(len(notes), 1)
        self.assertIn("markers", notes[0].reason)

    def test_unresolved_requirements_not_uploaded_or_followed(self):
        source = "requests>=2.0\n-r secrets.txt\n--index-url https://secret:token@internal/\npackage @ https://internal/pkg.whl\npackage==1.*\npackage==https://internal/token\n"
        dependencies, notes = collect_dependencies("requirements.txt", source)
        self.assertEqual(dependencies, [])
        self.assertTrue(notes)
        self.assertNotIn("token", repr(notes))

    def test_incomplete_continuation_is_an_error(self):
        dependencies, notes = collect_dependencies("requirements.txt", "flask==2.0.0 \\")
        self.assertEqual(dependencies, [])
        self.assertEqual(notes[0].category, "error")

    def test_source_overrides_skip_every_pin_regardless_of_position(self):
        directives = ("--index-url https://user:secret@internal/simple", "--index-url=https://internal/simple",
                      "--extra-index-url https://internal/simple", "--no-index", "--find-links /private/wheels",
                      "-i https://internal/simple", "-ihttps://internal/simple", "-f /private/wheels",
                      "-f/private/wheels", "--index-url https://pypi.org/simple")
        for directive in directives:
            for source in (directive + "\nprivate-package==1.0\n", "private-package==1.0\n" + directive):
                with self.subTest(directive=directive):
                    dependencies, notes = collect_dependencies("requirements.txt", source)
                    self.assertEqual(dependencies, [])
                    self.assertIn("source overrides", notes[0].reason)
                    self.assertNotIn("secret", repr(notes))
                    self.assertNotIn("internal", repr(notes))
                    with patch("tobacco.dependencies._request") as request:
                        self.assertEqual(audit_dependencies(dependencies), ([], [], 0))
                    request.assert_not_called()

    def test_source_override_continuations_cannot_hide_private_index(self):
        for directive in ("--index-url \\\nhttps://internal/simple", "--index-\\\nurl=https://internal/simple",
                          "--extra-index-url \\\nhttps://internal/simple", "-\\\nihttps://internal/simple",
                          "--find-\\\nlinks=/private/wheels", "--no-\\\nindex", "--index-url \\"):
            with self.subTest(directive=directive):
                dependencies, notes = collect_dependencies("requirements.txt", "private-package==1.0\n" + directive)
                self.assertEqual(dependencies, [])
                self.assertTrue(any("source overrides" in note.reason for note in notes))

    def test_source_options_in_comments_do_not_hide_public_packages(self):
        source = "# --index-url https://internal/simple\nflask==2.0.0 # --find-links /private/wheels\n"
        dependencies, notes = collect_dependencies("requirements.txt", source)
        self.assertEqual([dependency.name for dependency in dependencies], ["flask"])
        self.assertEqual(notes, [])

    def test_npm_v1_includes_nested_packages(self):
        source = json.dumps({"lockfileVersion": 1, "name": "own-project", "version": "0.1.0", "dependencies": {
            "first": {"version": "1.0.0", "dependencies": {"nested": {"version": "2.0.0"}}},
            "@scope/pkg": {"version": "3.0.0"},
        }}, indent=2)
        dependencies, notes = collect_dependencies("package-lock.json", source)
        self.assertEqual([(d.name, d.version) for d in dependencies],
                         [("first", "1.0.0"), ("nested", "2.0.0"), ("@scope/pkg", "3.0.0")])
        self.assertTrue(all(d.line > 1 for d in dependencies))
        self.assertEqual(notes, [])

    def test_npm_v2_v3_ignore_project_root_and_legacy_duplicate_section(self):
        for version in (2, 3):
            source = json.dumps({"lockfileVersion": version, "packages": {
                "": {"name": "own-project", "version": "1.0.0"},
                "node_modules/one": {"version": "2.0.0"},
                "node_modules/one/node_modules/@scope/two": {"version": "3.0.0"},
            }, "dependencies": {"one": {"version": "2.0.0"}}}, indent=2)
            dependencies, notes = collect_dependencies("package-lock.json", source)
            self.assertEqual([d.name for d in dependencies], ["one", "@scope/two"])
            self.assertEqual(notes, [])

    def test_npm_links_workspaces_and_non_registry_sources_have_notes(self):
        source = json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/link": {"link": True, "resolved": "../local"},
            "packages/local": {"name": "local", "version": "1.0.0"},
            "node_modules/git": {"version": "1.0.0", "resolved": "git+https://example.com/a"},
            "node_modules/tar": {"version": "https://user:token@internal/pkg.tgz"},
        }})
        dependencies, notes = collect_dependencies("package-lock.json", source)
        self.assertEqual(dependencies, [])
        self.assertEqual(len(notes), 4)
        self.assertNotIn("token", repr(notes))

    def test_npm_shrinkwrap_uses_same_parser(self):
        dependencies, notes = collect_dependencies("npm-shrinkwrap.json", '{"lockfileVersion": 1, "dependencies": {"safe": {"version": "1.0.0"}}}')
        self.assertEqual(dependencies[0].name, "safe")
        self.assertEqual(notes, [])

    def test_pipfile_both_sections_and_private_sources(self):
        source = json.dumps({"default": {"Django": {"version": "==4.2.0"}, "private": {"version": "==1.0", "index": "internal"}},
                             "develop": {"pytest": {"version": "==7.0.0", "markers": "python_version >= '3.8'"}}}, indent=2)
        dependencies, notes = collect_dependencies("Pipfile.lock", source)
        self.assertEqual([d.name for d in dependencies], ["django", "pytest"])
        self.assertEqual(len(notes), 2)

    def test_pipfile_repeated_packages_locate_each_section(self):
        source = json.dumps({"default": {"same": {"version": "==1.0"}}, "develop": {"same": {"version": "==1.0"}}}, indent=2)
        dependencies, _ = collect_dependencies("Pipfile.lock", source)
        self.assertLess(dependencies[0].line, dependencies[1].line)

    def test_private_index_cannot_masquerade_as_public_by_name(self):
        source = json.dumps({"_meta": {"sources": [{"name": "pypi", "url": "https://internal/simple"}]},
                             "default": {"internal-one": {"version": "==1.0", "index": "pypi"},
                                         "internal-two": {"version": "==1.0"}}})
        dependencies, notes = collect_dependencies("Pipfile.lock", source)
        self.assertEqual(dependencies, [])
        self.assertTrue(notes)

    def test_poetry_transitive_versions_and_nondefault_sources(self):
        source = '[[package]]\nname = "one"\nversion = "1.0.0"\npython-versions = ">=3.8"\n\n[[package]]\nname = "two"\nversion = "2.0.0"\n[package.source]\ntype = "git"\nurl = "https://internal/token"\n'
        dependencies, notes = collect_dependencies("poetry.lock", source)
        self.assertEqual(dependencies, [Dependency("one", "1.0.0", "PyPI", "poetry.lock", 1)])
        self.assertEqual(len(notes), 2)
        self.assertNotIn("token", repr(notes))

    def test_recognized_unsupported_manifests_report_skips(self):
        for path in ("Cargo.lock", "yarn.lock", "package.json", "pyproject.toml", "go.mod", "requirements.in", "app.csproj"):
            with self.subTest(path=path):
                dependencies, notes = collect_dependencies(path, "sensitive source")
                self.assertEqual(dependencies, [])
                self.assertEqual(len(notes), 1)
                self.assertEqual(notes[0].category, "skipped")
                self.assertNotIn("sensitive", notes[0].reason)
        self.assertEqual(collect_dependencies("app.py", "print('hello')"), ([], []))

    def test_malformed_lockfiles_report_errors_without_contents(self):
        for path, source in (("package-lock.json", '{"secret"'), ("Pipfile.lock", "[]"),
                             ("poetry.lock", "[broken"), ("package-lock.json", '{"lockfileVersion": true}'),
                             ("package-lock.json", '{"lockfileVersion": 3, "packages": []}')):
            with self.subTest(path=path, source=source):
                dependencies, notes = collect_dependencies(path, source)
                self.assertEqual(dependencies, [])
                self.assertEqual(notes[0].category, "error")
                self.assertNotIn("secret", notes[0].reason)

    def test_invalid_metadata_shapes_do_not_crash(self):
        sources = [
            ("Pipfile.lock", {"_meta": {"sources": [{"url": {}, "name": []}]}, "default": {"one": {"index": [], "version": "==1.0"}}}),
            ("package-lock.json", {"lockfileVersion": 1, "dependencies": {"one": {"version": {}, "dependencies": []}}}),
            ("package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/a": None}}),
        ]
        for path, data in sources:
            with self.subTest(path=path):
                dependencies, notes = collect_dependencies(path, json.dumps(data))
                self.assertEqual(dependencies, [])
                self.assertTrue(notes)


class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        self.dependency = Dependency("flask", "2.0.0", "PyPI", "requirements.txt", 2)
        self.advisory = {"id": "GHSA-abcd-1234-efgh", "aliases": ["CVE-2025-1234"],
                         "database_specific": {"severity": "HIGH"}, "affected": [{
                             "package": {"name": "flask", "ecosystem": "PyPI"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]}

    def audit(self, responses, dependencies=None, **kwargs):
        with patch("tobacco.dependencies._request", side_effect=responses) as request:
            result = audit_dependencies(dependencies if dependencies is not None else [self.dependency], **kwargs)
        return result, request

    def test_advisory_finding_contains_fixed_version_and_sanitized_metadata(self):
        self.advisory["summary"] = "\x1b[31m remote content"
        self.advisory["aliases"].append("bad\nidentifier")
        (findings, notes, count), request = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(count, 1)
        self.assertEqual(notes, [])
        finding = findings[0]
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.details["fixed_versions"], ["2.2.5"])
        self.assertEqual(finding.details["aliases"], ["CVE-2025-1234"])
        self.assertEqual(finding.path, "requirements.txt")
        self.assertEqual(finding.line, 2)
        self.assertNotIn("remote content", repr(finding))
        self.assertIn("unconfirmed", finding.message)
        self.assertEqual(request.call_args.args[0], {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "2.0.0"})

    def test_dedupes_queries_but_preserves_package_occurrences(self):
        other = Dependency("flask", "2.0.0", "PyPI", "nested/requirements.txt", 5)
        (findings, _, count), request = self.audit([{"vulns": [self.advisory, self.advisory]}], [self.dependency, other])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(count, 1)
        self.assertEqual([f.path for f in findings], ["requirements.txt", "nested/requirements.txt"])

    def test_clean_result_counts_as_a_success(self):
        (findings, notes, count), _ = self.audit([{}])
        self.assertEqual((findings, notes, count), ([], [], 1))

    def test_empty_dependencies_do_not_access_network(self):
        result, request = self.audit([], [])
        self.assertEqual(result, ([], [], 0))
        request.assert_not_called()

    def test_withdrawn_advisory_is_ignored(self):
        self.advisory["withdrawn"] = "2026-01-01T00:00:00Z"
        result, _ = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(result, ([], [], 1))

    def test_missing_or_unsupported_severity_has_explicit_high_priority(self):
        del self.advisory["database_specific"]
        for entries in ([], [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
                        [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}], None):
            self.advisory["severity"] = entries
            (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
            self.assertEqual(findings[0].severity, "high")
            self.assertIn("severity unavailable or unsupported; high review priority", findings[0].message)
            self.assertNotIn("cvss_base_score", findings[0].details)

    def test_explicit_numeric_severity(self):
        for value, expected in ((9.8, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"), (True, "high"), (float("nan"), "high"), (10**400, "high")):
            self.advisory["database_specific"]["severity"] = value
            (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
            self.assertEqual(findings[0].severity, expected)

    def test_cvss_v30_and_v31_base_scores_and_severities(self):
        # FIRST v3.1 examples: Cisco IOS CVE-2012-0384 (7.2), MySQL
        # CVE-2013-0375 (6.4), POODLE CVE-2014-3566 (3.1).
        # https://www.first.org/cvss/v3.1/examples
        del self.advisory["database_specific"]
        examples = (
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
            ("AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "high"),
            ("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "medium"),
            ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "low"),
            ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
            ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "low"),
        )
        for version in ("3.0", "3.1"):
            for metrics, score, severity in examples:
                vector = f"CVSS:{version}/{metrics}"
                with self.subTest(vector=vector):
                    self.advisory["severity"] = [{"type": "CVSS_V3", "score": vector}]
                    (findings, notes, _), _ = self.audit([{"vulns": [self.advisory]}])
                    self.assertEqual(notes, [])
                    self.assertEqual(findings[0].severity, severity)
                    self.assertEqual(findings[0].details["cvss_base_score"], score)
                    self.assertEqual(findings[0].details["cvss_vector"], vector)
                    self.assertIn(vector, findings[0].message)

    def test_cvss_accepts_metric_reordering_and_scores_only_base_metrics(self):
        del self.advisory["database_specific"]
        vector = "CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H/E:U/RL:O/RC:U/CR:L/IR:X/AR:M/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:N/MA:X"
        self.advisory["severity"] = [{"type": "CVSS_V3", "score": vector}]
        (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(findings[0].details["cvss_base_score"], 9.8)
        self.assertEqual(findings[0].details["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_cvss_rejects_duplicate_missing_invalid_and_untrusted_metrics(self):
        del self.advisory["database_specific"]
        valid = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        invalid = (valid + "/AV:N", valid.replace("/PR:N", ""), valid.replace("AV:N", "AV:X"),
                   valid + "/E:Z", valid + "/E:XX", valid + "/secret:token", valid + "/", valid + "\n",
                   valid.lower(), valid.replace("CVSS:3.1", "CVSS:3.2"), {}, None)
        for vector in invalid:
            with self.subTest(vector=vector):
                self.advisory["severity"] = [{"type": "CVSS_V3", "score": vector}]
                (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
                self.assertEqual(findings[0].severity, "high")
                self.assertNotIn("cvss_base_score", findings[0].details)
                self.assertNotIn("token", repr(findings))

    def test_multiple_valid_cvss_vectors_use_highest_base_score(self):
        del self.advisory["database_specific"]
        self.advisory["severity"] = [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ]
        (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].details["cvss_base_score"], 9.8)

    def test_explicit_database_severity_precedes_cvss(self):
        self.advisory["database_specific"]["severity"] = "LOW"
        self.advisory["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].details["severity_source"], "database_specific.severity")

    def test_fixed_versions_only_for_matching_package_and_version_ranges(self):
        self.advisory["affected"].extend([
            {"package": {"name": "other", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9"}]}]},
            {"package": {"name": "flask", "ecosystem": "PyPI"}, "ranges": [{"type": "GIT", "events": [{"fixed": "1abcdef"}]}, {"type": [], "events": []}]},
        ])
        (findings, _, _), _ = self.audit([{"vulns": [self.advisory]}])
        self.assertEqual(findings[0].details["fixed_versions"], ["2.2.5"])

    def test_pagination_queries_remaining_results(self):
        (findings, notes, count), request = self.audit([
            {"vulns": [self.advisory], "next_page_token": "cGFnZTI="},
            {"vulns": [self.advisory]},
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(notes, [])
        self.assertEqual(count, 1)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.args[0]["page_token"], "cGFnZTI=")

    def test_pagination_failure_keeps_partial_findings_with_error(self):
        (findings, notes, count), _ = self.audit([
            {"vulns": [self.advisory], "next_page_token": "page2"}, URLError("private raw response"),
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(count, 0)
        self.assertEqual(notes[0].category, "error")
        self.assertNotIn("private raw", notes[0].reason)

    def test_repeated_or_invalid_page_tokens_report_incomplete(self):
        for token in ("https://internal/token", ["invalid"], "again"):
            with self.subTest(token=token):
                (findings, notes, count), _ = self.audit([{"next_page_token": token}, {"next_page_token": token}])
                self.assertEqual(count, 0)
                self.assertTrue(notes)
                self.assertEqual(findings, [])

    def test_page_limit_is_not_reported_as_clean(self):
        with patch("tobacco.dependencies.MAX_PAGES", 1):
            (findings, notes, count), _ = self.audit([{"next_page_token": "next"}])
        self.assertEqual(count, 0)
        self.assertIn("pagination limit", notes[0].reason)

    def test_malformed_advisory_is_coverage_error(self):
        for advisory in (None, {"id": "\x1b[31mbad"}, {"id": "https://internal"}, {}):
            (findings, notes, count), _ = self.audit([{"vulns": [advisory]}])
            self.assertEqual((findings, count), ([], 0))
            self.assertEqual(notes[0].category, "error")

    def test_rejects_unsafe_metadata_before_network(self):
        dependencies = [Dependency("https://internal/token", "1.0.0", "PyPI", "requirements.txt", 1),
                        Dependency("safe", "secret value", "npm", "package-lock.json", 1),
                        Dependency("safe", "1.0.0", "GIT", "package-lock.json", 1)]
        (findings, notes, count), request = self.audit([], dependencies)
        request.assert_not_called()
        self.assertEqual(count, 0)
        self.assertTrue(notes)
        self.assertNotIn("token", repr(notes))

    def test_package_limit_notes_every_skipped_manifest(self):
        with patch("tobacco.dependencies.MAX_PACKAGES", 1):
            other = Dependency("second", "1.0", "npm", "package-lock.json", 1)
            (_, notes, count), request = self.audit([{}], [self.dependency, other])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(count, 1)
        self.assertEqual(notes[0].path, "package-lock.json")

    def test_repeated_failures_stop_requests_and_leave_notes(self):
        dependencies = [Dependency(f"package{i}", "1.0", "npm", f"app{i}/package-lock.json", 1) for i in range(4)]
        (_, notes, count), request = self.audit([URLError("secret")] * 3, dependencies)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(count, 0)
        self.assertEqual(len(notes), 4)

    def test_exhausted_budget_does_not_make_requests(self):
        with patch("tobacco.dependencies.MAX_AUDIT_SECONDS", 0):
            (_, notes, count), request = self.audit([])
        request.assert_not_called()
        self.assertEqual(count, 0)
        self.assertIn("budget", notes[0].reason)

    def test_invalid_timeout_is_rejected(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                audit_dependencies([], timeout)


class OSVTransportTests(unittest.TestCase):
    def response(self, content, status=200):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = status
        response.read.return_value = content
        return response

    def test_fixed_post_endpoint_and_metadata_only_payload(self):
        payload = {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "2.0.0"}
        with patch("tobacco.dependencies.build_opener") as factory:
            factory.return_value.open.return_value = self.response(b"{}")
            self.assertEqual(_request(payload, 3.0), {})
        request = factory.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, OSV_QUERY_URL)
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.data), payload)
        self.assertEqual(factory.return_value.open.call_args.kwargs["timeout"], 3.0)
        self.assertIsInstance(factory.call_args.args[0], _NoRedirect)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 307, "redirect", {}, "https://internal"))

    def test_malformed_responses_are_rejected(self):
        for content in (b"[]", b'{"error":"private error"}', b'{"vulns":null}', b"not json"):
            with patch("tobacco.dependencies.build_opener") as factory:
                factory.return_value.open.return_value = self.response(content)
                with self.assertRaises(ValueError):
                    _request({}, 1)

    def test_response_size_is_bounded(self):
        with patch("tobacco.dependencies.MAX_RESPONSE_BYTES", 10), patch("tobacco.dependencies.build_opener") as factory:
            response = self.response(b"x" * 11)
            factory.return_value.open.return_value = response
            with self.assertRaises(ValueError):
                _request({}, 1)
            response.read.assert_called_once_with(11)

    def test_non_success_status_is_not_clean(self):
        with patch("tobacco.dependencies.build_opener") as factory:
            factory.return_value.open.return_value = self.response(b"{}", status=500)
            with self.assertRaises(ValueError):
                _request({}, 1)


if __name__ == "__main__":
    unittest.main()
