"""Conservative, local Python AST checks; findings require human review.

These checks do not execute imports or follow code across files. Assignment
tracking is deliberately bounded and is not a whole-program taint analysis.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re

from .models import Finding


_SQL = re.compile(
    r"\b(?:SELECT\b.+?\bFROM|INSERT\s+INTO|UPDATE\b.+?\bSET|DELETE\s+FROM|"
    r"DROP\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|CREATE\s+TABLE)\b",
    re.IGNORECASE | re.DOTALL,
)
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
_INSTANCE_FACTORIES = {
    "requests.Session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient",
    "flask.Flask", "flask.app.Flask", "ssl.SSLContext", "ssl.create_default_context",
}
_HTTP_CALLS = {
    f"{library}.{method}"
    for library in ("requests", "requests.api", "httpx")
    for method in _HTTP_METHODS
} | {
    f"{owner}.{method}"
    for owner in ("requests.Session", "requests.sessions.Session")
    for method in _HTTP_METHODS | {"send"}
} | {
    "httpx.Client", "httpx.AsyncClient",
}
_UNSAFE_YAML_LOADERS = {
    "yaml.Loader", "yaml.CLoader", "yaml.UnsafeLoader", "yaml.CUnsafeLoader",
    "yaml.loader.Loader", "yaml.loader.UnsafeLoader",
}


@dataclass
class _Binding:
    symbol: str | None = None
    expression: ast.AST | None = None


@dataclass
class _Scope:
    kind: str
    names: dict[str, _Binding] = field(default_factory=dict)


class _Locals(ast.NodeVisitor):
    """Collect lexical locals without descending into nested scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.external: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(item.asname or item.name.split(".")[0] for item in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(item.asname or item.name for item in node.names if item.name != "*")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_Global(self, node: ast.Global) -> None:
        self.external.update(node.names)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        # Comprehension targets belong to their own scope.
        pass

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


class _Analyzer(ast.NodeVisitor):
    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source_lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.column_adjustments: dict[int, tuple[list[int], list[int]]] = {}
        self.scopes = [_Scope("module")]
        self.findings: list[Finding] = []

    def _lookup(self, name: str) -> _Binding | None:
        in_function = False
        for scope in reversed(self.scopes):
            if scope.kind == "class" and in_function:
                continue
            if name in scope.names:
                return scope.names[name]
            in_function |= scope.kind == "function"
        return None

    def _symbol(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            binding = self._lookup(node.id)
            if binding is not None:
                return binding.symbol
            if node.id in {"eval", "exec"}:
                return "builtins." + node.id
        elif isinstance(node, ast.Attribute):
            base = self._symbol(node.value)
            if base:
                return base + "." + node.attr
        elif isinstance(node, ast.Call):
            factory = self._symbol(node.func)
            if factory in _INSTANCE_FACTORIES:
                return factory
        return None

    def _expand(self, node: ast.AST | None) -> ast.AST | None:
        seen: set[str] = set()
        for _ in range(12):
            if not isinstance(node, ast.Name) or node.id in seen:
                break
            seen.add(node.id)
            binding = self._lookup(node.id)
            if binding is None or binding.expression is None:
                break
            node = binding.expression
        return node

    def _static(self, node: ast.AST | None, depth: int = 0) -> bool:
        if depth > 12:
            return False
        node = self._expand(node)
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._static(item, depth + 1) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(self._static(item, depth + 1) for item in node.keys + node.values)
        if isinstance(node, ast.UnaryOp):
            return self._static(node.operand, depth + 1)
        if isinstance(node, ast.BinOp):
            return self._static(node.left, depth + 1) and self._static(node.right, depth + 1)
        if isinstance(node, ast.JoinedStr):
            return all(self._static(item, depth + 1) for item in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._static(node.value, depth + 1) and (
                node.format_spec is None or self._static(node.format_spec, depth + 1)
            )
        if isinstance(node, ast.IfExp):
            return self._static(node.body, depth + 1) and self._static(node.orelse, depth + 1)
        return False

    def _boolean(self, node: ast.AST | None, value: bool) -> bool:
        node = self._expand(node)
        return isinstance(node, ast.Constant) and node.value is value

    @staticmethod
    def _argument(node: ast.Call, position: int, *names: str) -> ast.AST | None:
        if len(node.args) > position:
            return node.args[position]
        return next((kw.value for kw in node.keywords if kw.arg in names), None)

    @staticmethod
    def _keyword(node: ast.Call, name: str) -> ast.AST | None:
        return next((kw.value for kw in node.keywords if kw.arg == name), None)

    def _add(
        self, node: ast.AST, rule_id: str, title: str, severity: str,
        confidence: str, message: str, recommendation: str, cwe: str,
    ) -> None:
        # Python AST columns count UTF-8 bytes; report Unicode code points, like
        # the text checks. This also keeps SARIF locations consistent.
        source_line = self.source_lines[node.lineno - 1]
        column = node.col_offset + 1
        if not source_line.isascii():
            # Index a line once, rather than repeatedly decoding a long prefix
            # for every finding on an attacker-controlled source line.
            if node.lineno not in self.column_adjustments:
                ends, adjustments = [], []
                extra = 0
                for index, character in enumerate(source_line):
                    if ord(character) > 127:
                        extra += len(character.encode("utf-8")) - 1
                        ends.append(index + 1 + extra)
                        adjustments.append(extra)
                self.column_adjustments[node.lineno] = (ends, adjustments)
            ends, adjustments = self.column_adjustments[node.lineno]
            previous = bisect_right(ends, node.col_offset) - 1
            if previous >= 0:
                column -= adjustments[previous]
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity, confidence=confidence,
            path=self.path, line=node.lineno, column=column,
            message=message, recommendation=recommendation, cwe=cwe,
        ))

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.scopes[-1].names[item.asname or item.name.split(".")[0]] = _Binding(
                symbol=item.name if item.asname else item.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name != "*":
                symbol = f"{node.module}.{item.name}" if node.module and not node.level else None
                self.scopes[-1].names[item.asname or item.name] = _Binding(symbol=symbol)

    def _bind(self, target: ast.AST, value: ast.AST | None = None) -> None:
        if isinstance(target, ast.Name):
            self.scopes[-1].names[target.id] = _Binding(
                symbol=self._symbol(value), expression=self._expand(value)
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else []
            for index, item in enumerate(target.elts):
                self._bind(item, values[index] if index < len(values) else None)
        elif isinstance(target, ast.Starred):
            self._bind(target.value)

    def _assignment_check(self, target: ast.AST, value: ast.AST) -> None:
        symbol = self._symbol(target)
        if isinstance(target, ast.Attribute):
            owner = self._symbol(target.value)
            if target.attr == "verify" and owner in {"requests.Session", "requests.sessions.Session"}:
                if self._boolean(value, False):
                    self._tls(target)
            if target.attr == "verify_mode" and owner in {"ssl.SSLContext", "ssl.create_default_context"}:
                if self._symbol(value) == "ssl.CERT_NONE":
                    self._tls(target)
            if target.attr == "debug" and owner in {"flask.Flask", "flask.app.Flask"}:
                if self._boolean(value, True):
                    self._debug(target)
        if symbol == "django.conf.settings.DEBUG" and self._boolean(value, True):
            self._debug(target)
        if isinstance(target, ast.Name) and target.id == "DEBUG" and len(self.scopes) == 1:
            parts = PurePosixPath(self.path.replace("\\", "/")).parts
            if (parts[-1:] == ("settings.py",) or "settings" in parts[:-1]) and self._boolean(value, True):
                self._debug(target)
        if isinstance(target, ast.Subscript) and self._boolean(value, True):
            key = self._expand(target.slice)
            if isinstance(key, ast.Constant) and key.value == "DEBUG":
                if self._symbol(target.value) in {"flask.Flask.config", "flask.app.Flask.config"}:
                    self._debug(target)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
            self._assignment_check(target, node.value)
            self._bind(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._assignment_check(node.target, node.value)
            self._bind(node.target, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        self._bind(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind(node.target, node.value)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = self.scopes[-1].names.copy()
        for child in node.body:
            self.visit(child)
        left = self.scopes[-1].names
        self.scopes[-1].names = before.copy()
        for child in node.orelse:
            self.visit(child)
        right = self.scopes[-1].names
        merged: dict[str, _Binding] = {}
        for name in left.keys() | right.keys():
            first, second = left.get(name, _Binding()), right.get(name, _Binding())
            if first.expression is second.expression:
                expression = first.expression
            else:
                # Preserve both possible values. A later safe assignment in the
                # other branch must not hide dynamic input at an execution sink.
                expression = ast.IfExp(
                    test=node.test,
                    body=first.expression or ast.Name(id="<unknown>", ctx=ast.Load()),
                    orelse=second.expression or ast.Name(id="<unknown>", ctx=ast.Load()),
                )
            merged[name] = _Binding(
                symbol=first.symbol if first.symbol == second.symbol else None,
                expression=expression,
            )
        self.scopes[-1].names = merged

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._bind(node.target)
        for child in node.body + node.orelse:
            self.visit(child)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._bind(item.optional_vars, item.context_expr)
        for child in node.body:
            self.visit(child)

    visit_AsyncWith = visit_With

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
            self.visit(default)
        if not isinstance(node, ast.Lambda):
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.scopes[-1].names[node.name] = _Binding()
        collector = _Locals()
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        for child in body:
            collector.visit(child)
        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if node.args.vararg:
            args.append(node.args.vararg)
        if node.args.kwarg:
            args.append(node.args.kwarg)
        local_names = (collector.names - collector.external) | {arg.arg for arg in args}
        self.scopes.append(_Scope("function", {name: _Binding() for name in local_names}))
        for child in body:
            self.visit(child)
        self.scopes.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function
    visit_Lambda = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in node.decorator_list + node.bases:
            self.visit(item)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.scopes[-1].names[node.name] = _Binding()
        self.scopes.append(_Scope("class"))
        for child in node.body:
            self.visit(child)
        self.scopes.pop()

    def _comprehension(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        self.visit(node.generators[0].iter)
        self.scopes.append(_Scope("function"))
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self._bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.scopes.pop()

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def _tls(self, node: ast.AST) -> None:
        self._add(node, "PY006", "TLS certificate verification disabled", "high", "high",
                  "This setting disables certificate authentication; interception may be possible if used for HTTPS.",
                  "Enable certificate verification and configure the required certificate authority bundle.", "CWE-295")

    def _debug(self, node: ast.AST) -> None:
        self._add(node, "PY007", "Web application debug mode enabled", "medium", "medium",
                  "Debug mode is explicitly enabled; deployment exposure must be reviewed.",
                  "Disable debug mode in deployed configurations and keep development settings separate.", "CWE-489")

    def _sql_construction(self, node: ast.AST | None) -> bool:
        node = self._expand(node)
        if node is None or self._static(node):
            return False
        if isinstance(node, ast.IfExp):
            return self._sql_construction(node.body) or self._sql_construction(node.orelse)
        constructed = isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
        ) or (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"format", "format_map"}
        )
        if not constructed:
            return False
        fragments = [child.value for child in ast.walk(node)
                     if isinstance(child, ast.Constant) and isinstance(child.value, str)]
        return bool(_SQL.search(" ".join(fragments)))

    def visit_Call(self, node: ast.Call) -> None:
        symbol = self._symbol(node.func)
        first = self._argument(node, 0, "source", "object", "args", "command", "cmd")
        if symbol in {"builtins.eval", "builtins.exec"} and first is not None and not self._static(first):
            self._add(node, "PY001", "Dynamic Python code execution", "high", "medium",
                      "Nonliteral input reaches Python code execution; attacker influence has not been established.",
                      "Replace dynamic evaluation with explicit parsing or an allowlisted operation dispatcher.", "CWE-95")

        shell = symbol in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
        if symbol in {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}:
            shell = self._boolean(self._keyword(node, "shell"), True)
            if symbol == "subprocess.Popen" and len(node.args) > 8:
                shell |= self._boolean(node.args[8], True)
        command = self._expand(first)
        if shell and command is not None and not self._static(command):
            message = "A nonliteral command reaches a shell; review whether untrusted values can change its syntax."
            if isinstance(command, (ast.List, ast.Tuple)):
                message = (
                    "A command sequence containing nonliteral input is passed with shell=True; "
                    "Windows converts the sequence into a shell command string. Review platform and input trust."
                )
            self._add(node, "PY002", "Dynamic command passed to a shell", "high", "medium",
                      message,
                      "Use a subprocess argument list with shell=False and validate arguments for the target program.", "CWE-78")

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"}:
            query = self._argument(node, 0, "sql", "query", "operation")
            if self._sql_construction(query):
                self._add(node, "PY003", "SQL built with string interpolation", "high", "medium",
                          "A constructed SQL-like string reaches an execution method; confirm the receiver and input trust.",
                          "Use database parameter binding for values and an allowlist for dynamic SQL identifiers.", "CWE-89")

        if symbol in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads", "dill.load", "dill.loads"}:
            data = self._argument(node, 0, "file", "data", "str")
            if data is not None and not self._static(data):
                self._add(node, "PY004", "Potentially unsafe object deserialization", "high", "medium",
                          "Object deserialization can execute code if its input is attacker-controlled or tampered with.",
                          "Prefer a data-only format such as JSON; otherwise establish input integrity and trust before loading.", "CWE-502")

        if symbol in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}:
            data = self._argument(node, 0, "stream")
            loader = self._argument(node, 1, "Loader")
            loader_symbol = self._symbol(loader)
            unsafe = symbol in {"yaml.unsafe_load", "yaml.unsafe_load_all"} or loader_symbol in _UNSAFE_YAML_LOADERS
            unspecified = symbol in {"yaml.load", "yaml.load_all"} and loader is None
            if data is not None and not self._static(data) and (unsafe or unspecified):
                self._add(node, "PY005", "YAML loaded without a safe loader", "high", "medium",
                          "YAML object construction may execute code on untrusted input; an omitted loader also depends on the PyYAML version.",
                          "Use yaml.safe_load or yaml.safe_load_all for untrusted documents.", "CWE-502")

        if (symbol in _HTTP_CALLS and self._boolean(self._keyword(node, "verify"), False)) or symbol == "ssl._create_unverified_context":
            self._tls(node)
        if symbol in {"urllib3.PoolManager", "urllib3.HTTPSConnectionPool"}:
            cert_reqs = self._expand(self._keyword(node, "cert_reqs"))
            if self._symbol(cert_reqs) == "ssl.CERT_NONE" or (isinstance(cert_reqs, ast.Constant) and cert_reqs.value == "CERT_NONE"):
                self._tls(node)

        if symbol in {"flask.Flask.run", "flask.app.Flask.run"} and self._boolean(self._keyword(node, "debug"), True):
            self._debug(node)
        if symbol == "tempfile.mktemp":
            self._add(node, "PY008", "Temporary filename created without reserving the file", "medium", "high",
                      "Another process may create the temporary path before this program opens it.",
                      "Use tempfile.mkstemp, NamedTemporaryFile, or TemporaryDirectory for atomic creation.", "CWE-377")
        self.generic_visit(node)


def analyze_python(path: str, source: str) -> list[Finding]:
    """Return review candidates, raising SyntaxError for unsupported or invalid code."""
    tree = ast.parse(source, filename=path)
    analyzer = _Analyzer(path, source)
    analyzer.visit(tree)
    return analyzer.findings
