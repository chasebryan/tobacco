"""Serializable results. Findings deliberately contain no source excerpts."""

from dataclasses import asdict, dataclass, field
import hashlib

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}

RULES = {
    "SEC001": "Private-key material",
    "SEC002": "Recognizable service credential",
    "SEC003": "Embedded secret assignment",
    "PY001": "Dynamic Python code execution",
    "PY002": "Dynamic shell command",
    "PY003": "Constructed SQL query",
    "PY004": "Pickle deserialization",
    "PY005": "Unsafe YAML loading",
    "PY006": "Disabled TLS certificate verification",
    "PY007": "Application debug mode",
    "PY008": "Insecure temporary filename",
    "JS001": "Dynamic JavaScript code execution",
    "JS002": "Dynamic JavaScript shell command",
    "JS003": "Interpolated SQL query",
    "PHP001": "Request input passed to a dangerous PHP function",
    "CFG001": "Disabled TLS verification in configuration",
    "CFG002": "Privileged container",
    "CFG003": "Untrusted checkout in a privileged Actions event",
    "DEP001": "Dependency version matches a published advisory",
    "HTTP001": "HTTP transport is not encrypted",
    "HTTP002": "Missing or disabled HTTP Strict Transport Security",
    "HTTP003": "Missing MIME sniffing protection",
    "HTTP004": "Missing Content Security Policy",
    "HTTP005": "Cookie lacks Secure",
    "HTTP006": "Cookie lacks HttpOnly",
    "HTTP007": "Cookie SameSite configuration needs review",
    "HTTP008": "TLS certificate verification failed",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    path: str
    line: int
    column: int
    message: str
    recommendation: str
    cwe: str
    details: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Location identity, without hashing or retaining secret material."""
        location = f"{self.rule_id}\0{self.path}\0{self.line}\0{self.column}"
        if self.details.get("advisory_id"):
            location += f"\0{self.details.get('ecosystem')}\0{self.details.get('package')}\0{self.details.get('version')}\0{self.details['advisory_id']}"
        return hashlib.sha256(location.encode("utf-8", errors="surrogatepass")).hexdigest()[:24]

    def to_dict(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint, "status": "needs_review"}


@dataclass(frozen=True)
class CoverageNote:
    path: str
    reason: str
    category: str  # skipped or error


@dataclass
class ScanReport:
    root: str
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CoverageNote] = field(default_factory=list)
    files_scanned: int = 0
    python_files_analyzed: int = 0
    bytes_scanned: int = 0
    filtered_findings: int = 0
    options: dict = field(default_factory=dict)
    mode: str = "source"
    dependencies_found: int = 0
    dependencies_queried: int = 0
    http_requests: int = 0

    @property
    def errors(self) -> list[CoverageNote]:
        return [note for note in self.coverage if note.category == "error"]

    @property
    def counts(self) -> dict[str, int]:
        return {severity: sum(f.severity == severity for f in self.findings)
                for severity in reversed(SEVERITIES)}

    def to_dict(self) -> dict:
        from . import __version__
        return {
            "schema_version": "1.1",
            "tool": {"name": "tobacco", "version": __version__},
            "root": self.root,
            "mode": self.mode,
            "assessment": "Security review candidates; exploitability is not confirmed.",
            "capabilities": {
                "python": "Syntax analysis with limited local assignment tracking",
                "javascript_typescript_php": "Selected text patterns, without full language parsing",
                "other_files": "Selected credential and configuration patterns only",
                "dependencies": "OSV lookups for supported pinned versions" if self.options.get("dependencies") else "Not requested",
            } if self.mode == "source" else {
                "http": "One GET request; response header, cookie, and TLS review",
                "redirects": "Not followed",
                "response_body": "Not read",
            },
            "limitations": [
                "No whole-program or cross-file dataflow analysis",
                "No exploit execution, authentication testing, or application crawling",
                "A clean report does not establish that the application is secure",
            ],
            "summary": {
                "files_scanned": self.files_scanned,
                "python_files_analyzed": self.python_files_analyzed,
                "bytes_scanned": self.bytes_scanned,
                "findings": len(self.findings),
                "by_severity": self.counts,
                "filtered_findings": self.filtered_findings,
                "skipped_entries": sum(n.category == "skipped" for n in self.coverage),
                "analysis_errors": len(self.errors),
                "dependencies_found": self.dependencies_found,
                "dependencies_queried": self.dependencies_queried,
                "http_requests": self.http_requests,
            },
            "options": self.options,
            "findings": [finding.to_dict() for finding in self.findings],
            "coverage": [asdict(note) for note in self.coverage],
        }
