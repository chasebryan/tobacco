"""Command-line entry point and report formats."""

import argparse
import json
import math
import os
from pathlib import Path
import sys
from urllib.parse import quote_from_bytes

from . import __version__
from .models import RULES, SEVERITIES, ScanReport
from .scanner import ScanOptions, scan
from .http_checks import probe


def terminal_text(value: str) -> str:
    """Prevent filenames and other target-controlled text from escaping the terminal."""
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in value)


def render_text(report: ScanReport) -> str:
    label = "HTTP security check" if report.mode == "http" else "source security audit"
    lines = [f"TOBACCO {__version__} | {label}", f"Target: {terminal_text(report.root)}", "",
             "Potential vulnerabilities require review; exploitability is not confirmed.", ""]
    for finding in report.findings:
        lines.extend([
            f"[{finding.severity.upper()}] {finding.rule_id} {terminal_text(finding.title)}",
            f"  {terminal_text(finding.path)}:{finding.line}:{finding.column}"
            f" | confidence: {finding.confidence} | {finding.cwe}",
            f"  {terminal_text(finding.message)}",
            f"  Fix: {terminal_text(finding.recommendation)}",
        ])
        if finding.details.get("advisory_id"):
            lines.append(f"  Advisory: {terminal_text(finding.details['url'])}")
            fixes = finding.details.get("fixed_versions", [])
            if fixes:
                lines.append(f"  Fixed versions listed by advisory: {terminal_text(', '.join(fixes))}")
        lines.append("")
    if not report.findings:
        lines.extend(["No findings from the enabled checks. This is not a security clearance.", ""])
    counts = ", ".join(f"{count} {severity}" for severity, count in report.counts.items())
    if report.mode == "source":
        lines.append(f"Scanned {report.files_scanned} text files ({report.python_files_analyzed} with Python syntax analysis).")
        lines.append("Coverage: Python syntax; JS/TS/PHP patterns; selected credentials/configuration checks.")
        if report.options.get("dependencies"):
            lines.append(f"Dependencies: {report.dependencies_found} locked entries; {report.dependencies_queried} unique versions checked against OSV.")
        else:
            lines.append("Dependency advisories: not requested (use --dependencies for OSV lookups).")
    else:
        lines.append(f"HTTP requests: {report.http_requests}. Redirects were not followed; response bodies were not read.")
    lines.extend([
        f"Found {len(report.findings)} review candidates: {counts}.",
        f"Filtered findings: {report.filtered_findings}. Analysis errors: {len(report.errors)}.",
        "Exploitability, authentication logic, and whole-program dataflow are not assessed.",
    ])
    if report.coverage:
        lines.append("Coverage notes (excluded directories represent entire subtrees):")
        for note in report.coverage:
            lines.append(f"  {note.category.upper()} {terminal_text(note.path)}: {terminal_text(note.reason)}")
    return "\n".join(lines) + "\n"


def render_sarif(report: ScanReport) -> dict:
    rule_ids = sorted({finding.rule_id for finding in report.findings})
    root = Path(report.root)
    base = root if root.is_dir() else root.parent

    def location(finding):
        if report.mode == "http":
            return {"artifactLocation": {"uri": finding.path}}
        return {
            "artifactLocation": {"uri": quote_from_bytes(os.fsencode(finding.path), safe="/"), "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": finding.line, "startColumn": finding.column},
        }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "columnKind": "unicodeCodePoints",
            "tool": {"driver": {
                "name": "Tobacco", "version": __version__,
                "informationUri": "https://github.com/chasebryan/tobacco",
                "rules": [{"id": rule_id, "shortDescription": {"text": RULES[rule_id]}}
                          for rule_id in rule_ids],
            }},
            **({"originalUriBaseIds": {"%SRCROOT%": {"uri": base.as_uri().rstrip("/") + "/"}}} if report.mode == "source" else {}),
            "results": [{
                "ruleId": finding.rule_id,
                "ruleIndex": rule_ids.index(finding.rule_id),
                "level": "error" if finding.severity in {"critical", "high"} else "warning"
                    if finding.severity == "medium" else "note",
                "message": {"text": f"{finding.message} Fix: {finding.recommendation}"},
                "locations": [{"physicalLocation": location(finding)}],
                "partialFingerprints": {"tobaccoLocation/v1": finding.fingerprint},
                "properties": {"severity": finding.severity, "confidence": finding.confidence,
                               "cwe": finding.cwe, "status": "needs_review", "details": finding.details},
            } for finding in report.findings],
            "invocations": [{
                "executionSuccessful": not report.errors,
                "toolExecutionNotifications": [{
                    "level": "error" if note.category == "error" else "note",
                    "message": {"text": f"{terminal_text(note.path)}: {note.reason}"},
                } for note in report.coverage],
            }],
            "properties": {"coverage": report.to_dict()["summary"], "options": report.options},
        }],
    }


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Must be a positive integer.") from error
    if number < 1:
        raise argparse.ArgumentTypeError("Must be a positive integer.")
    return number


def network_timeout(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Timeout must be a number between 0 and 120 seconds (exclusive).") from error
    if not math.isfinite(number) or not 0 < number < 120:
        raise argparse.ArgumentTypeError("Timeout must be a number between 0 and 120 seconds (exclusive).")
    return number


def report_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    command.add_argument("--ignore-rule", action="append", default=[], choices=sorted(RULES), metavar="RULE_ID")
    command.add_argument("--min-severity", choices=SEVERITIES, default="low", help="Lowest severity to report (default: low)")
    command.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="high",
                         help="Exit 1 for reported findings at this severity or above (default: high)")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="tobacco", description="Find potential security weaknesses in local source code.")
    result.add_argument("--version", action="version", version=f"Tobacco {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("rules", help="List built-in checks")
    scan_parser = commands.add_parser("scan", help="Read and audit a local directory or source file")
    scan_parser.add_argument("target", type=Path, help="Local application directory or file")
    report_options(scan_parser)
    scan_parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                             help="Exclude a relative path or basename glob; repeatable")
    scan_parser.add_argument("--max-file-bytes", type=positive_int, default=1024 * 1024,
                             help="Maximum bytes read per file (default: 1048576)")
    scan_parser.add_argument("--no-default-excludes", action="store_true",
                             help="Also inspect dependency, build, and version-control directories")
    scan_parser.add_argument("--dependencies", action="store_true",
                             help="Query OSV online; sends pinned package names, versions, and ecosystems, never source code")
    scan_parser.add_argument("--dependency-timeout", type=network_timeout, default=10.0,
                             help="OSV socket timeout in seconds (default: 10)")
    probe_parser = commands.add_parser("probe", help="Check HTTP response headers and TLS for a running app using one GET")
    probe_parser.add_argument("url", help="HTTP(S) URL without credentials, query, or fragment")
    probe_parser.add_argument("--timeout", type=network_timeout, default=10.0, help="Socket timeout in seconds (default: 10)")
    report_options(probe_parser)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "rules":
        for rule_id, title in RULES.items():
            print(f"{rule_id:8} {title}")
        return 0
    try:
        if args.command == "probe":
            report = probe(args.url, args.timeout)
            findings = report.findings
            report.findings = [finding for finding in findings if finding.rule_id not in args.ignore_rule
                               and SEVERITIES[finding.severity] >= SEVERITIES[args.min_severity]]
            report.filtered_findings = len(findings) - len(report.findings)
            report.options.update({"min_severity": args.min_severity, "ignored_rules": args.ignore_rule})
        else:
            report = scan(args.target, ScanOptions(
                excludes=args.exclude, ignore_rules=args.ignore_rule, min_severity=args.min_severity,
                max_file_bytes=args.max_file_bytes, use_default_excludes=not args.no_default_excludes,
                dependencies=args.dependencies, dependency_timeout=args.dependency_timeout,
            ))
    except (OSError, ValueError) as error:
        print(f"tobacco: {terminal_text(str(error))}", file=sys.stderr)
        return 2
    if args.format == "text":
        output = render_text(report)
    else:
        output = json.dumps(report.to_dict() if args.format == "json" else render_sarif(report), indent=2) + "\n"
    try:
        sys.stdout.write(output)
    except BrokenPipeError:
        # Avoid a second flush error when a consumer (such as head) closes early.
        sys.stdout = open(os.devnull, "w")
        return 0
    if report.errors:
        return 2
    if args.fail_on != "none" and any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] for f in report.findings):
        return 1
    return 0
