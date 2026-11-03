"""A small, deterministic rule pack for the security worker pack.

This is deliberately not a general-purpose static analyzer. It is the offline
baseline that lets the verifier run without any external service. The rules are
transparent and are meant to be extended or replaced by adapters.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..models import CheckFinding

SECRET_NAME = re.compile(r"(secret|password|passwd|api[_-]?key|token)", re.IGNORECASE)
SQL_METHODS = {"execute", "executemany"}
DANGEROUS_DESERIALIZERS = {"pickle.loads", "pickle.load", "dill.loads", "dill.load"}
YAML_LOADS = {"yaml.load", "yaml.load_all"}
URL_OPENERS = ("urlopen(", "requests.get(", "httpx.get(", "urllib.request.urlopen(")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in node.elts:
            names.extend(_target_names(element))
        return names
    return []


def _contains_string(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Constant) and isinstance(child.value, str) for child in ast.walk(node)
    )


def _dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _contains_string(node)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format" and _contains_string(node.func.value)
    return False


def _returns_html(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(child, ast.Constant) and isinstance(child.value, str) and "<" in child.value
            for child in ast.walk(node)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _contains_string(node) and "<" in ast.unparse(node)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _contains_string(node.func.value)
    ):
        return "<" in ast.unparse(node.func.value)
    return False


class BuiltinChecker:
    """Offline rule pack used as the default security checker."""

    tool = "acv-rules"
    version = "0.1.0"

    def scan(self, path: Path) -> list[CheckFinding]:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        findings: list[CheckFinding] = []
        findings.extend(self._command_injection(tree))
        findings.extend(self._path_traversal(source))
        findings.extend(self._sql_injection(tree))
        findings.extend(self._deserialization(tree))
        findings.extend(self._ssrf(source))
        findings.extend(self._hardcoded_secret(tree))
        findings.extend(self._xss(source, tree))
        findings.extend(self._unsafe_yaml(tree))
        findings.extend(self._insecure_random(source))
        findings.extend(self._open_redirect(source, tree))
        return findings

    def _command_injection(self, tree: ast.AST) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name in {"os.system", "os.popen"}:
                findings.append(
                    CheckFinding(
                        rule_id="ACV001",
                        cwe="CWE-78",
                        severity="high",
                        message="shell command built with os.system/os.popen",
                        line=node.lineno,
                    )
                )
            if name.startswith("subprocess."):
                shell = _keyword(node, "shell")
                if isinstance(shell, ast.Constant) and shell.value is True:
                    findings.append(
                        CheckFinding(
                            rule_id="ACV001",
                            cwe="CWE-78",
                            severity="high",
                            message="subprocess call uses shell=True",
                            line=node.lineno,
                        )
                    )
        return findings

    def _path_traversal(self, source: str) -> list[CheckFinding]:
        if "BASE /" not in source:
            return []
        if any(marker in source for marker in ("is_relative_to", "commonpath", "realpath")):
            return []
        line = next(
            (
                number
                for number, text in enumerate(source.splitlines(), start=1)
                if "BASE /" in text
            ),
            1,
        )
        return [
            CheckFinding(
                rule_id="ACV002",
                cwe="CWE-22",
                severity="high",
                message="path is joined from user input without a containment check",
                line=line,
            )
        ]

    def _sql_injection(self, tree: ast.AST) -> list[CheckFinding]:
        dynamic_names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not _dynamic_sql(node.value):
                continue
            rendered = ast.unparse(node.value).upper()
            if not any(keyword in rendered for keyword in ("SELECT", "INSERT", "UPDATE", "DELETE")):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    dynamic_names.add(target.id)

        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name.rsplit(".", 1)[-1] not in SQL_METHODS:
                continue
            if not node.args:
                continue
            argument = node.args[0]
            dynamic = _dynamic_sql(argument) or (
                isinstance(argument, ast.Name) and argument.id in dynamic_names
            )
            if dynamic:
                findings.append(
                    CheckFinding(
                        rule_id="ACV003",
                        cwe="CWE-89",
                        severity="high",
                        message="SQL statement is built with string interpolation",
                        line=node.lineno,
                    )
                )
        return findings

    def _deserialization(self, tree: ast.AST) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _dotted(node.func) in DANGEROUS_DESERIALIZERS:
                findings.append(
                    CheckFinding(
                        rule_id="ACV004",
                        cwe="CWE-502",
                        severity="high",
                        message="untrusted data is passed to a pickle loader",
                        line=node.lineno,
                    )
                )
        return findings

    def _ssrf(self, source: str) -> list[CheckFinding]:
        if not any(marker in source for marker in URL_OPENERS):
            return []
        safe = "urlparse" in source and "ALLOWED_HOSTS" in source and ".hostname" in source
        if safe:
            return []
        line = next(
            (
                number
                for number, text in enumerate(source.splitlines(), start=1)
                if any(marker in text for marker in URL_OPENERS)
            ),
            1,
        )
        return [
            CheckFinding(
                rule_id="ACV005",
                cwe="CWE-918",
                severity="high",
                message="URL fetch has no host allowlist",
                line=line,
            )
        ]

    def _hardcoded_secret(self, tree: ast.AST) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(
                    SECRET_NAME.search(name) for target in targets for name in _target_names(target)
                ):
                    findings.append(
                        CheckFinding(
                            rule_id="ACV006",
                            cwe="CWE-798",
                            severity="high",
                            message="secret-like name is assigned a string literal",
                            line=node.lineno,
                        )
                    )
            if isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name not in {"os.environ.get", "os.getenv"}:
                    continue
                if not node.args:
                    continue
                key = _constant_string(node.args[0])
                if key is None or not SECRET_NAME.search(key):
                    continue
                if len(node.args) >= 2 and _constant_string(node.args[1]) is not None:
                    findings.append(
                        CheckFinding(
                            rule_id="ACV006",
                            cwe="CWE-798",
                            severity="high",
                            message="secret environment variable has a string fallback",
                            line=node.lineno,
                        )
                    )
        return findings

    def _xss(self, source: str, tree: ast.AST) -> list[CheckFinding]:
        if any(marker in source for marker in ("html.escape", "markupsafe.escape", "escape(")):
            return []
        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Return)
                and node.value is not None
                and _returns_html(node.value)
            ):
                findings.append(
                    CheckFinding(
                        rule_id="ACV007",
                        cwe="CWE-79",
                        severity="high",
                        message="HTML is returned from a template without escaping",
                        line=node.lineno,
                    )
                )
        return findings

    def _unsafe_yaml(self, tree: ast.AST) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _dotted(node.func) not in YAML_LOADS:
                continue
            loader = _keyword(node, "Loader")
            if loader is not None:
                loader_name = _dotted(loader)
                if loader_name.endswith("SafeLoader"):
                    continue
            findings.append(
                CheckFinding(
                    rule_id="ACV008",
                    cwe="CWE-94",
                    severity="high",
                    message="YAML is loaded without a safe loader",
                    line=node.lineno,
                )
            )
        return findings

    def _insecure_random(self, source: str) -> list[CheckFinding]:
        if "random." not in source:
            return []
        lower = source.lower()
        if not any(word in lower for word in ("token", "password", "reset", "secret")):
            return []
        if not any(
            marker in source
            for marker in (
                "random.choice",
                "random.choices",
                "random.randint",
                "random.randrange",
                "random.random",
            )
        ):
            return []
        line = next(
            (
                number
                for number, text in enumerate(source.splitlines(), start=1)
                if "random." in text and not text.lstrip().startswith("#")
            ),
            1,
        )
        return [
            CheckFinding(
                rule_id="ACV009",
                cwe="CWE-338",
                severity="high",
                message="security token uses the predictable random module",
                line=line,
            )
        ]

    def _open_redirect(self, source: str, tree: ast.AST) -> list[CheckFinding]:
        if "urlparse" in source and "ALLOWED_HOSTS" in source:
            return []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Name)
                and node.value.id == "target"
            ):
                return [
                    CheckFinding(
                        rule_id="ACV010",
                        cwe="CWE-601",
                        severity="high",
                        message="redirect target is returned without a host allowlist",
                        line=node.lineno,
                    )
                ]
        return []
