"""Read resolved dependency metadata and optionally query the public OSV API.

No target code, package manager, registry URL, or manifest include is executed.
Only validated package names, versions, and ecosystems leave the machine.
"""

from dataclasses import dataclass
import http.client
import json
import math
from pathlib import PurePath
import re
import time
import tomllib
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import CoverageNote, Finding


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PACKAGES = 500
MAX_PAGES = 5
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_AUDIT_SECONDS = 60.0
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?\Z")
_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
_VERSION = re.compile(r"[vV]?[0-9][0-9A-Za-z.!+_-]{0,79}\Z")
_ADVISORY_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_UNSUPPORTED = {
    "package.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "uv.lock", "pdm.lock",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "gradle.lockfile", "packages.lock.json", "packages.config",
}


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    path: str
    line: int


def _valid_package(name: object, version: object, ecosystem: str) -> bool:
    pattern = _PYPI_NAME if ecosystem == "PyPI" else _NPM_NAME
    return (ecosystem in {"PyPI", "npm"} and isinstance(name, str)
            and len(name) <= 214 and pattern.fullmatch(name) is not None
            and isinstance(version, str) and _VERSION.fullmatch(version) is not None)


def _normalize_name(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _note(notes: list[CoverageNote], path: str, reason: str, category="skipped") -> None:
    note = CoverageNote(path, reason, category)
    if note not in notes:
        notes.append(note)


def _add(result, notes, name, version, ecosystem, path, line):
    if _valid_package(name, version, ecosystem):
        result.append(Dependency(_normalize_name(name, ecosystem), version, ecosystem, path, line))
    else:
        _note(notes, path, "Some dependency entries lack a supported, safe exact name and version")


class _KeyLines:
    """Locate JSON object keys without retaining source in audit results."""

    def __init__(self, source):
        self.lines = {}
        for number, line in enumerate(source.splitlines(), 1):
            for match in re.finditer(r'"((?:[^"\\]|\\.)*)"\s*:', line):
                try:
                    key = json.loads('"' + match[1] + '"')
                except ValueError:
                    continue
                self.lines.setdefault(key, []).append(number)
        self.positions = {}

    def get(self, key):
        candidates = self.lines.get(key, [1])
        position = self.positions.get(key, 0)
        self.positions[key] = position + 1
        return candidates[min(position, len(candidates) - 1)]


def _requirements(path, source, result, notes):
    pending = ""
    start = 1
    logical_lines = []
    for number, raw in enumerate(source.splitlines(), 1):
        if not pending:
            start = number
        text = raw.strip()
        if text.endswith("\\"):
            pending += text[:-1]
            continue
        text = pending + text
        pending = ""
        if not text or text.startswith("#"):
            continue
        text = re.split(r"\s+#", text, maxsplit=1)[0].strip()
        logical_lines.append((start, text))
    if pending:
        _note(notes, path, "Incomplete requirements continuation was not resolved", "error")
        logical_lines.append((start, pending))
    # Source options apply to the whole file, even if declared after a package.
    # Conservatively skip even an explicit public index: do not infer registry
    # identity from options, interpolate environment variables, or expose URLs.
    source_override = re.compile(r"(?:^|\s)(?:--(?:index-url|extra-index-url|no-index|find-links)(?==|\s|$)|-[if])")
    if any(source_override.search(text) for _, text in logical_lines):
        _note(notes, path, "Requirements source overrides are not resolved; no packages from this file were queried")
        return
    for start, text in logical_lines:
        if pending and start == logical_lines[-1][0]:
            continue
        if ";" in text:
            text = text.split(";", 1)[0].strip()
            _note(notes, path, "Environment markers were not evaluated; all exactly pinned variants were checked")
        text = re.sub(r"\s+--hash[= ]sha(?:256|384|512):[0-9a-fA-F]+", "", text).strip()
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9._,-]+\])?\s*==\s*([^\s=]+)", text)
        if match:
            _add(result, notes, match[1], match[2], "PyPI", path, start)
        else:
            _note(notes, path, "Some requirements are not supported exact pins; ranges, includes, URLs and options are not resolved")


def _npm_lock(path, data, lines, result, notes):
    lock_version = data.get("lockfileVersion")
    if type(lock_version) is not int or lock_version not in {1, 2, 3}:
        _note(notes, path, "Unsupported npm lockfile version", "error")
        return

    def add_package(name, entry, line):
        if not isinstance(entry, dict):
            _note(notes, path, "Malformed npm dependency entry", "error")
            return
        if entry.get("link"):
            _note(notes, path, "Linked npm packages are not queried")
            return
        resolved = entry.get("resolved")
        if resolved is not None and (not isinstance(resolved, str)
                                     or not resolved.startswith("https://registry.npmjs.org/")):
            _note(notes, path, "Non-public-registry npm dependency sources are not queried")
            return
        _add(result, notes, entry.get("name", name), entry.get("version"), "npm", path, line)

    if lock_version in {2, 3}:
        packages = data.get("packages")
        if not isinstance(packages, dict):
            _note(notes, path, "npm lockfile has no usable packages table", "error")
            return
        for location, entry in packages.items():
            if not location:  # This is the project itself, not an installed dependency.
                continue
            if "node_modules/" not in location:
                _note(notes, path, "Workspace npm packages are not queried")
                continue
            name = location.rsplit("node_modules/", 1)[1]
            add_package(name, entry, lines.get(location))
        return
    dependencies = data.get("dependencies", {})
    if not isinstance(dependencies, dict):
        _note(notes, path, "Malformed npm dependencies table", "error")
        return
    # An explicit stack avoids recursion on deeply nested v1 dependency trees.
    pending = list(reversed(list(dependencies.items())))
    while pending:
        name, entry = pending.pop()
        add_package(name, entry, lines.get(name))
        if isinstance(entry, dict) and "dependencies" in entry:
            children = entry["dependencies"]
            if isinstance(children, dict):
                pending.extend(reversed(list(children.items())))
            else:
                _note(notes, path, "Malformed npm dependencies table", "error")


def _pipfile_lock(path, data, lines, result, notes):
    if not any(section in data for section in ("default", "develop")):
        _note(notes, path, "Pipfile lock has no dependency sections", "error")
        return
    sources = data.get("_meta", {}).get("sources", []) if isinstance(data.get("_meta", {}), dict) else []
    public_indexes = {"pypi"}
    if isinstance(sources, list) and sources:
        public_indexes = {item.get("name") for item in sources if isinstance(item, dict)
                          and isinstance(item.get("url"), str)
                          and item.get("url") in {"https://pypi.org/simple", "https://pypi.org/simple/",
                                                   "https://pypi.python.org/simple", "https://pypi.python.org/simple/"}
                          and isinstance(item.get("name"), str)}
    has_private_source = isinstance(sources, list) and len(public_indexes) < len(sources)
    for section in ("default", "develop"):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            _note(notes, path, "Malformed Pipfile dependency section", "error")
            continue
        for name, entry in entries.items():
            line = lines.get(name)
            if not isinstance(entry, dict):
                _note(notes, path, "Malformed Pipfile dependency entry", "error")
                continue
            if (any(key in entry for key in ("git", "path", "file", "ref"))
                    or ("index" in entry and (not isinstance(entry["index"], str) or entry["index"] not in public_indexes))
                    or ("index" not in entry and has_private_source)):
                _note(notes, path, "Non-public-registry Python dependency sources are not queried")
                continue
            if "markers" in entry:
                _note(notes, path, "Environment markers were not evaluated; all exactly pinned variants were checked")
            version = entry.get("version")
            _add(result, notes, name, version[2:] if isinstance(version, str) and version.startswith("==") else None,
                 "PyPI", path, line)


def _poetry_lock(path, data, source, result, notes):
    if not any(section in data for section in ("package", "metadata")):
        _note(notes, path, "Poetry lock has no package or metadata sections", "error")
        return
    packages = data.get("package", [])
    if not isinstance(packages, list):
        _note(notes, path, "Malformed Poetry packages table", "error")
        return
    locations = [i for i, line in enumerate(source.splitlines(), 1) if re.fullmatch(r"\s*\[\[package\]\]\s*(?:#.*)?", line)]
    for position, entry in enumerate(packages):
        if not isinstance(entry, dict):
            _note(notes, path, "Malformed Poetry dependency entry", "error")
            continue
        if "source" in entry:
            _note(notes, path, "Non-default-source Poetry dependencies are not queried")
            continue
        if "markers" in entry or "marker" in entry or entry.get("python-versions", "*") != "*":
            _note(notes, path, "Environment markers were not evaluated; all exactly pinned variants were checked")
        _add(result, notes, entry.get("name"), entry.get("version"), "PyPI", path,
             locations[position] if position < len(locations) else 1)


def collect_dependencies(path: str, source: str) -> tuple[list[Dependency], list[CoverageNote]]:
    """Parse supported manifest text, noting unsupported and incomplete coverage."""
    name = PurePath(path).name
    result: list[Dependency] = []
    notes: list[CoverageNote] = []
    if re.fullmatch(r"requirements[^/]*\.txt", name, re.IGNORECASE):
        _requirements(path, source, result, notes)
    elif name in {"package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock", "poetry.lock"}:
        try:
            data = tomllib.loads(source) if name == "poetry.lock" else json.loads(source)
            if not isinstance(data, dict):
                raise ValueError
            if name == "poetry.lock":
                _poetry_lock(path, data, source, result, notes)
            elif name == "Pipfile.lock":
                _pipfile_lock(path, data, _KeyLines(source), result, notes)
            else:
                _npm_lock(path, data, _KeyLines(source), result, notes)
        except (ValueError, RecursionError):
            _note(notes, path, "Dependency lockfile could not be parsed", "error")
    elif name in _UNSUPPORTED or name.endswith((".csproj", ".fsproj", ".vbproj", ".gemspec")) or re.fullmatch(r"requirements.*\.in", name, re.IGNORECASE):
        _note(notes, path, "Dependency manifest format is not queried directly; use a supported resolved lockfile")
    return result, notes


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(payload: dict, timeout: float) -> dict:
    request = Request(OSV_QUERY_URL, data=json.dumps(payload).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/json", "Accept": "application/json",
                               "User-Agent": "tobacco-audit"})
    # Never follow a redirect to a different service (including one supplied by a target).
    with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("Unexpected OSV response status")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeds size limit")
    data = json.loads(raw)
    if not isinstance(data, dict) or ("vulns" in data and not isinstance(data["vulns"], list)):
        raise ValueError("Malformed OSV response")
    # An empty object is the documented clean response. Other envelopes must not
    # accidentally turn an API error into a successful clean lookup.
    if data and not any(key in data for key in ("vulns", "next_page_token")):
        raise ValueError("Unexpected OSV response envelope")
    return data


def _cvss_v3_base(vector):
    """Calculate FIRST CVSS v3.0/v3.1 Base Score, or reject an invalid vector.

    CVSS is owned by FIRST and used by permission. Equations and rounding:
    https://www.first.org/cvss/v3.1/specification-document#7-1-Base-Metrics-Equations
    https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
    The v3.0 Base equations are identical; environmental metrics are not scored.
    """
    if not isinstance(vector, str) or len(vector) > 256:
        return None
    pieces = vector.split("/")
    if pieces[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        return None
    allowed = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
               "C": "HLN", "I": "HLN", "A": "HLN", "E": "XHFPU", "RL": "XUWTO",
               "RC": "XCRU", "CR": "XHML", "IR": "XHML", "AR": "XHML",
               "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR",
               "MS": "XUC", "MC": "XNLH", "MI": "XNLH", "MA": "XNLH"}
    metrics = {}
    for piece in pieces[1:]:
        key, separator, value = piece.partition(":")
        if (not separator or key not in allowed or len(value) != 1
                or value not in allowed[key] or key in metrics):
            return None
        metrics[key] = value
    base_keys = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in metrics for key in base_keys):
        return None
    vector = pieces[0] + "/" + "/".join(f"{key}:{metrics[key]}" for key in base_keys)
    impacts = {"H": 0.56, "L": 0.22, "N": 0.0}
    impact_subscore = 1 - math.prod(1 - impacts[metrics[key]] for key in ("C", "I", "A"))
    changed = metrics["S"] == "C"
    impact = (7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
              if changed else 6.42 * impact_subscore)
    if impact <= 0:
        return 0.0, vector
    attack = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    privileges = {"N": 0.85, "L": 0.68 if changed else 0.62,
                  "H": 0.5 if changed else 0.27}[metrics["PR"]]
    interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    exploitability = 8.22 * attack * complexity * privileges * interaction
    raw_score = min((1.08 if changed else 1.0) * (impact + exploitability), 10.0)
    # Appendix A: round to five decimal places, then round upward to one.
    integer_score = round(raw_score * 100000)
    score = (integer_score + 9999) // 10000 / 10.0
    return score, vector


def _score_severity(score):
    # Tobacco has no "none" finding level; a zero-score advisory remains low.
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _severity(advisory):
    database = advisory.get("database_specific")
    value = database.get("severity") if isinstance(database, dict) else None
    labels = {"low": "low", "moderate": "medium", "medium": "medium", "high": "high", "critical": "critical"}
    if isinstance(value, str) and value.lower() in labels:
        return labels[value.lower()], "database_specific.severity", {}
    if type(value) in {int, float} and 0 <= value <= 10 and math.isfinite(value):
        return _score_severity(value), "database_specific.severity", {}
    scores = []
    reported = advisory.get("severity", [])
    if isinstance(reported, list):
        for entry in reported:
            if isinstance(entry, dict) and entry.get("type") == "CVSS_V3":
                calculated = _cvss_v3_base(entry.get("score"))
                if calculated is not None:
                    scores.append(calculated)
    if scores:
        score, vector = max(scores)
        return _score_severity(score), "CVSS_V3 base score", {"cvss_base_score": score, "cvss_vector": vector}
    return "high", "severity unavailable or unsupported; high review priority", {}


def _advisory_finding(dependency, advisory):
    if not isinstance(advisory, dict):
        raise ValueError("Malformed OSV advisory")
    if advisory.get("withdrawn"):
        return None
    advisory_id = advisory.get("id")
    if not isinstance(advisory_id, str) or not _ADVISORY_ID.fullmatch(advisory_id):
        raise ValueError("Malformed OSV advisory identifier")
    aliases = advisory.get("aliases", [])
    aliases = sorted({alias for alias in aliases if isinstance(alias, str) and _ADVISORY_ID.fullmatch(alias)}) if isinstance(aliases, list) else []
    fixed = set()
    affected = advisory.get("affected", [])
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
                continue
            package = entry["package"]
            name = package.get("name")
            if (not isinstance(name, str) or package.get("ecosystem") != dependency.ecosystem
                    or _normalize_name(name, dependency.ecosystem) != dependency.name):
                continue
            ranges = entry.get("ranges", [])
            if not isinstance(ranges, list):
                continue
            for affected_range in ranges:
                if not isinstance(affected_range, dict) or affected_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                events = affected_range.get("events", [])
                if not isinstance(events, list):
                    continue
                for event in events:
                    version = event.get("fixed") if isinstance(event, dict) else None
                    if isinstance(version, str) and _VERSION.fullmatch(version):
                        fixed.add(version)
    severity, severity_source, severity_details = _severity(advisory)
    message = f"OSV reports {advisory_id} for {dependency.name} {dependency.version}. Application exploitability is unconfirmed."
    if severity_source.startswith("severity unavailable"):
        message += " Advisory severity unavailable or unsupported; high review priority is used."
    if severity_details:
        message += f" CVSS base score: {severity_details['cvss_base_score']:.1f} ({severity_details['cvss_vector']})."
    return Finding(
        rule_id="DEP001", title="Dependency with a published vulnerability", severity=severity,
        confidence="high", path=dependency.path, line=dependency.line, column=1, message=message,
        recommendation="Review the advisory and affected code paths; upgrade to a compatible unaffected release. Reported fixed versions may cover different release branches.",
        cwe="CWE-1395", details={"advisory_id": advisory_id, "aliases": aliases,
                               "package": dependency.name, "version": dependency.version,
                               "ecosystem": dependency.ecosystem,
                               "url": f"https://osv.dev/vulnerability/{advisory_id}",
                               "fixed_versions": sorted(fixed), "severity_source": severity_source,
                               **severity_details},
    )


def audit_dependencies(dependencies: list[Dependency], timeout: float = 10.0) -> tuple[list[Finding], list[CoverageNote], int]:
    """Query OSV with bounded resources; count only fully successful unique queries."""
    if not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Dependency timeout must be a positive finite number")
    findings: list[Finding] = []
    notes: list[CoverageNote] = []
    packages = {}
    for dependency in dependencies:
        if not _valid_package(dependency.name, dependency.version, dependency.ecosystem):
            _note(notes, dependency.path, "Dependency metadata was rejected before network access", "error")
            continue
        key = (_normalize_name(dependency.name, dependency.ecosystem), dependency.version, dependency.ecosystem)
        packages.setdefault(key, []).append(dependency)
    deadline = time.monotonic() + MAX_AUDIT_SECONDS
    completed = 0
    failed_requests = 0
    for index, ((name, version, ecosystem), occurrences) in enumerate(packages.items()):
        reason = None
        if index >= MAX_PACKAGES:
            reason = "OSV lookup limit reached; some dependencies were not checked"
        elif time.monotonic() >= deadline:
            reason = "OSV audit time budget exhausted; some dependencies were not checked"
        elif failed_requests >= 3:
            reason = "OSV lookups stopped after repeated failures; some dependencies were not checked"
        if reason:
            for dependency in occurrences:
                _note(notes, dependency.path, reason, "error")
            continue
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        seen_tokens = set()
        seen_advisories = set()
        complete = False
        try:
            for page in range(MAX_PAGES):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                response = _request(payload, min(float(timeout), remaining))
                for advisory in response.get("vulns", []):
                    # Validate even duplicate entries, but emit each advisory only once.
                    candidates = [_advisory_finding(dependency, advisory) for dependency in occurrences]
                    if candidates and candidates[0] is not None:
                        advisory_id = candidates[0].details["advisory_id"]
                        if advisory_id not in seen_advisories:
                            findings.extend(candidate for candidate in candidates if candidate is not None)
                            seen_advisories.add(advisory_id)
                token = response.get("next_page_token")
                if token is None or token == "":
                    complete = True
                    break
                if not isinstance(token, str) or len(token) > 2048 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", token) or token in seen_tokens:
                    raise ValueError("Malformed OSV pagination")
                seen_tokens.add(token)
                payload["page_token"] = token
            if not complete:
                reason = "OSV pagination limit reached; dependency lookup is incomplete"
            else:
                completed += 1
                failed_requests = 0
        except (OSError, URLError, http.client.HTTPException, ValueError, RecursionError):
            failed_requests += 1
            reason = "OSV lookup failed or returned an invalid response; dependency lookup is incomplete"
        if reason:
            for dependency in occurrences:
                _note(notes, dependency.path, reason, "error")
    return findings, notes, completed
