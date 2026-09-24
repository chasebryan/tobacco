"""Small, explainable text checks for languages without a built-in parser.

These checks report review candidates, not demonstrated exploitability. They do
not execute source code, resolve dependencies, or include source text in reports.
"""

from __future__ import annotations

from bisect import bisect_right
import re
from pathlib import PurePath

from .models import Finding


_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
_SECRET_EXTENSIONS = _JS_EXTENSIONS | {
    ".py", ".pyw", ".pyi", ".php", ".rb", ".go", ".rs", ".java", ".kt", ".kts",
    ".cs", ".c", ".h", ".cc", ".cpp", ".sh", ".bash", ".zsh", ".fish",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".tf", ".tfvars", ".xml", ".pem", ".key",
}
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_SERVICE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"gh[pousr]_[A-Za-z0-9]{36}"
    r"|github_pat_[A-Za-z0-9_]{50,255}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,200}"
    r"|sk_live_[A-Za-z0-9]{20,200}"
    r")(?![A-Za-z0-9_])"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?<![\w])[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_-]{0,127})"
    r"[\"']?[ \t]*[:=][ \t]*(?P<quote>[\"'])(?P<value>[^\r\n]*?)(?P=quote)"
)
_ENV_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^[ \t]*(?:export[ \t]+)?(?P<name>[A-Z_][A-Z0-9_]{0,127})"
    r"[ \t]*=[ \t]*(?P<value>[^\s#\"'][^\s#]*)[ \t]*(?:#.*)?$"
)


def _masked(source: str, *, comments: bool, strings: bool, hash_comments: bool = False) -> str:
    """Mask comments/quoted strings while preserving offsets and line numbers."""
    result = list(source)
    index = 0
    while index < len(source):
        start = index
        if source[index] in "\"'`":
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            should_mask = strings
        elif source.startswith("//", index) or (hash_comments and source[index] == "#"):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            should_mask = comments
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 2
            should_mask = comments
        else:
            index += 1
            continue
        if should_mask:
            for position in range(start, min(index, len(source))):
                if result[position] != "\n":
                    result[position] = " "
    return "".join(result)


def _literal(value: str) -> bool:
    value = value.strip()
    if len(value) < 2 or value[0] not in "\"'`" or value[-1] != value[0]:
        return False
    if value[0] == "`" and "${" in value:
        return False
    index = 1
    while index < len(value):
        if value[index] == "\\":
            index += 2
        elif value[index] == value[0]:
            return index == len(value) - 1
        else:
            index += 1
    return False


def _arguments(source: str, opening: int) -> list[str]:
    """Read balanced call arguments, bounded to avoid expensive malformed input."""
    stack = [")"]
    arguments: list[str] = []
    start = opening + 1
    index = start
    limit = min(len(source), start + 16_384)
    while index < limit:
        character = source[index]
        if character in "\"'`":
            quote = character
            index += 1
            while index < limit:
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    break
                else:
                    index += 1
        elif character in "([{":
            stack.append({"(": ")", "[": "]", "{": "}"}[character])
        elif character in ")]}":
            if not stack or character != stack.pop():
                return []
            if not stack:
                arguments.append(source[start:index].strip())
                return arguments
        elif character == "," and len(stack) == 1:
            arguments.append(source[start:index].strip())
            start = index + 1
        index += 1
    return []


def _placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        len(value) < 8
        or lowered in {
            "password", "password123", "changeme", "change-me", "change_me",
            "replace_me", "replaceme", "placeholder", "example", "example123",
            "undefined", "not-a-secret", "not_a_secret", "redacted", "supersecret",
            "testpassword", "test-password", "test_secret", "dummy-password",
        }
        or lowered.startswith(("your_", "your-", "replace_", "replace-", "example_", "example-"))
        or bool(re.fullmatch(r"[xX*._-]+", value))
        or any(marker in value for marker in ("${", "{{", "<", ">", "process.env", "os.environ"))
        or bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value))
    )


def _secret_name(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().replace("-", "_")
    return bool(re.search(
        r"(?:^|_)(?:password|passwd|pwd|secret(?:_?key)?|api_?key|access_?token|auth_?token|client_?secret)$",
        normalized,
    ))


def analyze_text(path: str, source: str) -> list[Finding]:
    """Return text-rule review candidates with stable locations and safe messages."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    line_starts = [0] + [match.end() for match in re.finditer("\n", source)]
    filename = PurePath(path).name.lower()
    extension = PurePath(path).suffix.lower()
    is_env = filename == ".env" or filename.startswith(".env.") or filename.endswith(".env")

    def add(rule_id: str, title: str, severity: str, confidence: str, offset: int,
            message: str, recommendation: str, cwe: str) -> None:
        line = bisect_right(line_starts, offset)
        if (rule_id, line) in seen:
            return
        seen.add((rule_id, line))
        findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, confidence=confidence,
            path=path, line=line, column=offset - line_starts[line - 1] + 1,
            message=message, recommendation=recommendation, cwe=cwe,
        ))

    # Explicit formats also matter in extensionless SSH keys, documentation, and
    # logs. Only the less certain assignment heuristic is extension restricted.
    credential_ranges: list[tuple[int, int]] = []
    for match in _PRIVATE_KEY.finditer(source):
        add("SEC001", "Private key material in a project file", "critical", "high", match.start(),
            "A private-key header is present. Confirm whether this is an active key or an intentional fixture.",
            "Remove active private keys from source control and rotate exposed keys; load them from protected storage.",
            "CWE-321")
    for match in _SERVICE_TOKEN.finditer(source):
        credential_ranges.append(match.span())
        add("SEC002", "Recognizable service credential", "high", "high", match.start(),
            "A value matches a known service-token format. Its validity has not been checked.",
            "If the credential is real, revoke or rotate it and load its replacement from protected configuration.",
            "CWE-798")
    if extension in _SECRET_EXTENSIONS or is_env or filename in {"dockerfile", "credentials"}:
        credential_starts = [start for start, _end in credential_ranges]
        patterns = [_SECRET_ASSIGNMENT]
        if is_env or extension in {".sh", ".bash", ".zsh", ".properties", ".ini", ".cfg", ".conf"}:
            patterns.append(_ENV_SECRET_ASSIGNMENT)
        secret_source = _masked(source, comments=True, strings=False, hash_comments=True)
        for pattern in patterns:
            for match in pattern.finditer(secret_source):
                if not _secret_name(match.group("name")) or _placeholder(match.group("value")):
                    continue
                preceding = bisect_right(credential_starts, match.end() - 1) - 1
                if preceding >= 0 and credential_ranges[preceding][1] > match.start():
                    continue
                add("SEC003", "Possible hardcoded credential", "high", "medium", match.start(),
                    "A credential-like configuration name has a literal value. Check whether this is sensitive or an intentional fixture.",
                    "Read real credentials from protected configuration and rotate any value that has been exposed.",
                    "CWE-798")

    if extension in _JS_EXTENSIONS:
        clean = _masked(source, comments=True, strings=False)
        code = _masked(source, comments=True, strings=True)
        for match in re.finditer(r"(?<![\w$.])(?:(?:window|globalThis)\s*\.\s*)?(eval|Function)\s*\(", code):
            arguments = _arguments(clean, match.end() - 1)
            value = (arguments[-1] if match.group(1) == "Function" else arguments[0]) if arguments else ""
            if value and not _literal(value):
                add("JS001", "Dynamic JavaScript code execution", "high", "medium", match.start(),
                    "Code is evaluated from a nonliteral expression. External input reaching this expression could execute JavaScript.",
                    "Replace dynamic code evaluation with explicit operations or a parser for the expected data format.",
                    "CWE-95")

        shell_names: set[str] = set()
        module_names: set[str] = set()
        for match in re.finditer(r"\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)", clean):
            if code[match.start():match.start() + 5].strip():
                module_names.add(match.group(1))
        for match in re.finditer(r"\bimport\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['\"](?:node:)?child_process['\"]", clean):
            if code[match.start():match.start() + 6].strip():
                module_names.add(match.group(1))
        imports = (
            r"\bimport\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?child_process['\"]",
            r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)",
        )
        for pattern in imports:
            for match in re.finditer(pattern, clean):
                if not code[match.start():match.start() + 5].strip():
                    continue
                for item in match.group(1).split(","):
                    binding = re.fullmatch(r"\s*(exec|execSync)(?:\s*(?::|as\b)\s*([\w$]+))?\s*", item)
                    if binding:
                        shell_names.add(binding.group(2) or binding.group(1))
        shell_patterns = [re.escape(name) for name in shell_names]
        shell_patterns.extend(re.escape(name) + r"\s*\.\s*(?:exec|execSync)" for name in module_names)
        if shell_patterns:
            pattern = r"(?<![\w$.])(?:" + "|".join(sorted(shell_patterns)) + r")\s*\("
            for match in re.finditer(pattern, code):
                arguments = _arguments(clean, match.end() - 1)
                if arguments and arguments[0] and not _literal(arguments[0]):
                    add("JS002", "Dynamic command passed to a shell", "high", "medium", match.start(),
                        "A child_process shell execution call receives a nonliteral command. Review the origins of its inputs.",
                        "Use execFile or spawn with a fixed executable and argument array, keep shell mode disabled, and validate arguments.",
                        "CWE-78")
        for match in re.finditer(r"\.\s*(?:query|execute)\s*\(", code):
            arguments = _arguments(clean, match.end() - 1)
            value = arguments[0] if arguments else ""
            if (re.match(r"[\"'`]\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b", value, re.I)
                    and not _literal(value) and ("${" in value or "+" in value)):
                add("JS003", "SQL assembled with dynamic values", "high", "medium", match.start(),
                    "A SQL query is built with string concatenation or template interpolation. Check whether external values can enter the query text.",
                    "Pass values separately with the database driver's parameterized-query interface.",
                    "CWE-89")
        for match in re.finditer(r"\brejectUnauthorized\s*:\s*false\b", clean):
            if code[match.start():match.start() + 1].strip():
                add("CFG001", "TLS certificate verification disabled", "high", "high", match.start(),
                    "A network option disables TLS certificate verification, allowing untrusted certificates.",
                    "Enable certificate verification and configure the required trusted certificate authorities.",
                    "CWE-295")

    if extension == ".php":
        clean = _masked(source, comments=True, strings=False, hash_comments=True)
        code = _masked(source, comments=True, strings=True, hash_comments=True)
        pattern = r"(?<![\w$>])(?:eval|exec|shell_exec|system|passthru|popen|unserialize)\s*\("
        for match in re.finditer(pattern, code, re.I):
            arguments = _arguments(clean, match.end() - 1)
            if arguments and re.search(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", arguments[0]):
                add("PHP001", "Request data passed to a dangerous operation", "high", "medium", match.start(),
                    "A code execution, shell execution, or deserialization operation directly references request data. Review validation and reachability.",
                    "Keep request data out of execution operations; use explicit commands or structured data parsing instead.",
                    "CWE-20")
        for match in re.finditer(r"\bCURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|\bCURLOPT_SSL_VERIFYHOST\s*,\s*0\b", clean, re.I):
            if code[match.start():match.start() + 1].strip():
                add("CFG001", "TLS certificate verification disabled", "high", "high", match.start(),
                    "A cURL option disables verification of the peer certificate or hostname.",
                    "Enable peer and hostname verification and configure trusted certificate authorities.",
                    "CWE-295")

    if is_env or extension in _JS_EXTENSIONS | {".sh", ".bash", ".yml", ".yaml"}:
        clean = _masked(source, comments=True, strings=False, hash_comments=True)
        for match in re.finditer(r"\bNODE_TLS_REJECT_UNAUTHORIZED[\"']?\s*[:=]\s*[\"']?0(?:[\"']|\b)", clean):
            add("CFG001", "Node TLS certificate verification disabled", "high", "high", match.start(),
                "Configuration disables Node.js TLS certificate verification process-wide.",
                "Remove this override and configure the required trusted certificate authorities.",
                "CWE-295")

    if extension in {".yaml", ".yml"}:
        clean = _masked(source, comments=True, strings=False, hash_comments=True)
        if re.fullmatch(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml", filename):
            for match in re.finditer(r"(?m)^[ \t]*privileged\s*:\s*(?:true|[\"']true[\"'])[ \t]*$", clean, re.I):
                add("CFG002", "Container runs in privileged mode", "high", "high", match.start(),
                    "A Compose service requests privileged mode, granting broad access to the host.",
                    "Remove privileged mode and grant only the individual capabilities and devices the service needs.",
                    "CWE-250")
        normalized = "/" + path.replace("\\", "/").lstrip("/")
        if "/.github/workflows/" in normalized:
            event_area = re.split(r"(?m)^jobs\s*:", clean, maxsplit=1)[0]
            has_target_event = re.search(r"(?m)^[ \t]*(?:[\"']?on[\"']?[ \t]*:[ \t]*(?:\[[^\]\n]*|\{[^}\n]*)?)?[\"']?pull_request_target[\"']?[ \t]*(?:[:,\]}]|$)", event_area)
            if has_target_event:
                checkout = re.compile(r"(?m)^(?P<indent>[ \t]*)(?:-\s*)?uses\s*:\s*[\"']?actions/checkout@[^\n]+")
                for match in checkout.finditer(clean):
                    key_column = clean[match.start():match.end()].find("uses")
                    following: list[str] = []
                    for line in clean[match.end():].splitlines()[1:33]:
                        if line.strip() and len(line) - len(line.lstrip()) < key_column:
                            break
                        following.append(line)
                    if re.search(r"\bref\s*:[^\n]*github\.event\.pull_request\.head\.(?:sha|ref)\b", "\n".join(following)):
                        add("CFG003", "Privileged workflow checks out pull-request code", "high", "medium", match.start(),
                            "A pull_request_target workflow checks out a pull request's head. Subsequent execution could expose the base repository's privileges or secrets.",
                            "Use pull_request for untrusted code, or keep privileged workflows separate and avoid executing pull-request content.",
                            "CWE-829")

    return findings
