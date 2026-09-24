"""Bounded, read-only traversal of an explicitly selected local target."""

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
import os
from pathlib import Path
import stat

from .models import CoverageNote, Finding, ScanReport, SEVERITIES
from .python_checks import analyze_python
from .text_checks import analyze_text
from .dependencies import Dependency, audit_dependencies, collect_dependencies

DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".nuxt", "coverage", ".idea",
})


@dataclass
class ScanOptions:
    excludes: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    min_severity: str = "low"
    max_file_bytes: int = 1024 * 1024
    use_default_excludes: bool = True
    dependencies: bool = False
    dependency_timeout: float = 10.0


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanReport:
    options = options or ScanOptions()
    if options.max_file_bytes < 1:
        raise ValueError("Maximum file size must be positive.")
    if options.min_severity not in SEVERITIES:
        raise ValueError("Unknown minimum severity.")
    root = Path(os.path.abspath(target))
    if root.is_symlink():
        raise ValueError("The target is a symbolic link. Select its actual directory or file.")
    mode = root.stat().st_mode
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise ValueError("The target must be a regular file or directory.")
    report = ScanReport(root=str(root), options={
        "excludes": options.excludes,
        "ignored_rules": options.ignore_rules,
        "min_severity": options.min_severity,
        "max_file_bytes": options.max_file_bytes,
        "dependencies": options.dependencies,
        "dependency_timeout": options.dependency_timeout,
        "default_excluded_directories": sorted(DEFAULT_EXCLUDED_DIRS)
            if options.use_default_excludes else [],
    })
    dependencies: list[Dependency] = []

    def note(path: str, reason: str, category: str = "skipped") -> None:
        report.coverage.append(CoverageNote(path, reason, category))

    def excluded(relative: str, name: str, directory: bool) -> bool:
        if (directory and options.use_default_excludes
                and name in DEFAULT_EXCLUDED_DIRS):
            note(relative, "Default excluded directory (entire subtree)")
            return True
        for pattern in options.excludes:
            # A trailing slash is accepted for directory names.
            pattern = pattern.rstrip("/")
            if fnmatchcase(relative, pattern) or fnmatchcase(name, pattern):
                note(relative, "User exclusion" + (" (entire subtree)" if directory else ""))
                return True
        return False

    def accept_findings(findings: list[Finding]) -> None:
        for finding in findings:
            if (finding.rule_id in options.ignore_rules
                    or SEVERITIES[finding.severity] < SEVERITIES[options.min_severity]):
                report.filtered_findings += 1
            else:
                report.findings.append(finding)

    def inspect_file(path: Path, relative: str, directory_fd: int | None = None) -> None:
        try:
            # Do not follow final-component symlinks, or block if a file turns
            # into a FIFO between traversal and open.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(path, flags, dir_fd=directory_fd)
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    note(relative, "Not a regular file")
                    return
                if metadata.st_size > options.max_file_bytes:
                    note(relative, "Exceeds maximum file size")
                    return
                data = stream.read(options.max_file_bytes + 1)
        except OSError as error:
            note(relative, f"Cannot read file: {error.strerror or 'I/O failure'}", "error")
            return
        if len(data) > options.max_file_bytes:
            note(relative, "Exceeds maximum file size")
            return
        if b"\x00" in data:
            note(relative, "Binary or NUL-containing file")
            return
        try:
            source = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            note(relative, "Not UTF-8 text")
            return
        report.files_scanned += 1
        report.bytes_scanned += len(data)
        if options.dependencies:
            packages, notes = collect_dependencies(relative, source)
            dependencies.extend(packages)
            report.coverage.extend(notes)
        findings = analyze_text(relative, source)
        if path.suffix.lower() in {".py", ".pyw"}:
            try:
                findings.extend(analyze_python(relative, source))
                report.python_files_analyzed += 1
            except (SyntaxError, RecursionError) as error:
                # SyntaxError text may contain credentials; record the location only.
                line = getattr(error, "lineno", None)
                location = f" at line {line}" if line else ""
                note(relative, f"Python syntax analysis failed{location}; text checks still ran", "error")
        accept_findings(findings)

    if stat.S_ISREG(mode):
        if not excluded(root.name, root.name, False):
            inspect_file(root, root.name)
    else:
        if os.open not in os.supports_dir_fd or os.scandir not in os.supports_fd:
            raise ValueError("Directory scanning requires descriptor-relative file access (Linux/macOS).")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

        def names(directory_fd: int):
            with os.scandir(directory_fd) as listing:
                return iter(sorted(entry.name for entry in listing))

        # Keep directory handles open during descent. Every child is opened
        # relative to its parent's handle, never through a mutable ancestor path.
        # Iteration avoids Python recursion limits on deeply nested projects.
        pending = []
        root_fd = os.open(root, directory_flags)
        try:
            pending.append((root_fd, "", names(root_fd)))
        except BaseException:
            os.close(root_fd)
            raise
        try:
            while pending:
                directory_fd, prefix, entries = pending[-1]
                try:
                    name = next(entries)
                except StopIteration:
                    os.close(directory_fd)
                    pending.pop()
                    continue
                relative = f"{prefix}/{name}" if prefix else name
                try:
                    entry_mode = os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
                    if stat.S_ISLNK(entry_mode):
                        note(relative, "Symbolic link")
                    elif stat.S_ISDIR(entry_mode):
                        if not excluded(relative, name, True):
                            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                            try:
                                child_names = names(child_fd)
                            except BaseException:
                                os.close(child_fd)
                                raise
                            pending.append((child_fd, relative, child_names))
                    elif stat.S_ISREG(entry_mode):
                        if not excluded(relative, name, False):
                            inspect_file(Path(name), relative, directory_fd)
                    else:
                        note(relative, "Not a regular file")
                except OSError as error:
                    note(relative, f"Cannot inspect entry: {error.strerror or 'I/O failure'}", "error")
        finally:
            for directory_fd, _prefix, _entries in pending:
                os.close(directory_fd)

    if options.dependencies:
        report.dependencies_found = len(dependencies)
        findings, notes, queried = audit_dependencies(dependencies, options.dependency_timeout)
        report.dependencies_queried = queried
        report.coverage.extend(notes)
        accept_findings(findings)
        if not dependencies:
            note(".", "No supported pinned dependency versions were found; dependency coverage is empty")

    unique: dict[str, Finding] = {}
    for finding in report.findings:
        unique[finding.fingerprint] = finding
    report.findings = sorted(unique.values(), key=lambda f: (
        -SEVERITIES[f.severity], f.path, f.line, f.column, f.rule_id, f.fingerprint))
    report.coverage.sort(key=lambda note: (note.path, note.category, note.reason))
    return report
