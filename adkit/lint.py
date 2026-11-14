"""Checker-safety linter for generated probes.

The linter is intentionally conservative: a probe that can change server state,
call the checker, spawn a process or write a file is rejected. It is a filter,
not a proof of safety.
"""
from __future__ import annotations

import ast

BANNED_NAMES = {"eval", "exec", "compile", "__import__"}
BANNED_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "shutil.rmtree",
    "shutil.move",
)
STATE_CHANGING_HTTP = {
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
}
BANNED_STRINGS = (
    "/_checker",
    "putflag",
    "getflag",
    "checkflag",
    "systemctl",
    "docker restart",
    "rm -rf",
    "drop table",
    "delete from",
    "insert into",
    "update ",
    "truncate ",
)
WRITE_MODES = ("w", "a", "x", "+")


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class _Visitor(ast.NodeVisitor):
    def __init__(self, docstrings: set[int]) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.docstrings = docstrings

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        line = getattr(node, "lineno", 0)

        if name in BANNED_NAMES:
            self.errors.append(f"line {line}: {name}() is banned")
        if any(name.startswith(prefix) for prefix in BANNED_PREFIXES):
            self.errors.append(f"line {line}: {name}() can change the host")
        if name in STATE_CHANGING_HTTP:
            self.errors.append(f"line {line}: {name}() changes state")

        if name == "open":
            mode = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = keyword.value.value
            if isinstance(mode, str) and any(flag in mode for flag in WRITE_MODES):
                self.errors.append(f"line {line}: open(..., {mode!r}) writes a file")

        if name == "urllib.request.urlopen":
            has_data = False
            for keyword in node.keywords:
                if keyword.arg == "data" and not isinstance(keyword.value, ast.Constant):
                    has_data = True
                elif keyword.arg == "data" and isinstance(keyword.value, ast.Constant) and keyword.value.value is not None:
                    has_data = True
            if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                has_data = True
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value is not None:
                has_data = True
            if has_data:
                self.errors.append(f"line {line}: urlopen(..., data=...) sends a request body")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and id(node) not in self.docstrings:
            lowered = node.value.lower()
            for marker in BANNED_STRINGS:
                if marker in lowered:
                    self.errors.append(f"line {node.lineno}: string contains {marker!r}")
        self.generic_visit(node)


def _docstrings(tree: ast.AST) -> set[int]:
    """Identifiers of string constants used as module/class/function docstrings.

    Documentation never becomes a request, so a docstring is exempt from the
    string scan. Everything else in the module is fair game.
    """
    found: set[int] = set()
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def lint_code(code: str) -> dict:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"ok": False, "errors": [f"syntax error: {exc.msg} (line {exc.lineno})"], "warnings": []}
    visitor = _Visitor(_docstrings(tree))
    visitor.visit(tree)
    return {
        "ok": not visitor.errors,
        "errors": visitor.errors,
        "warnings": visitor.warnings,
    }
