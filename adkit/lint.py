"""Checker-safety linter for generated artifacts.

Two modes:

- `probe` (default): the strict filter. State-changing requests, file writes,
  process spawns, eval and checker references are errors.
- `scaffold`: the artifact needs a non-GET request to be useful. Process
  spawns, eval and checker references stay hard errors; state-changing calls
  and payload literals become warnings so the caller sees exactly what the
  scaffold will do.

The linter is a filter, not a proof.
"""
from __future__ import annotations

import ast

MODES = ("probe", "scaffold")

BANNED_NAMES = {"eval", "exec", "compile", "__import__"}
GUARD_NAMES = {"BLOCKED", "GUARD", "DENY", "DENYLIST"}
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
HARD_STRINGS = ("/_checker", "putflag", "getflag", "checkflag")
SOFT_STRINGS = (
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
    def __init__(self, docstrings: set[int], mode: str) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.docstrings = docstrings
        self.mode = mode

    def flag(self, hard: bool, message: str) -> None:
        if hard or self.mode == "probe":
            self.errors.append(message)
        else:
            self.warnings.append(message)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        line = getattr(node, "lineno", 0)

        if name in BANNED_NAMES:
            self.flag(True, f"line {line}: {name}() is banned")
        if any(name.startswith(prefix) for prefix in BANNED_PREFIXES):
            self.flag(True, f"line {line}: {name}() can change the host")
        if name in STATE_CHANGING_HTTP:
            self.flag(False, f"line {line}: {name}() changes state")

        if name == "open":
            mode = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = keyword.value.value
            if isinstance(mode, str) and any(flag in mode for flag in WRITE_MODES):
                self.flag(False, f"line {line}: open(..., {mode!r}) writes a file")

        if name in ("urllib.request.Request", "Request"):
            for keyword in node.keywords:
                if keyword.arg == "data" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None):
                    self.flag(False, f"line {line}: Request(..., data=...) sends a body")
            if len(node.args) >= 4 and not (isinstance(node.args[3], ast.Constant) and node.args[3].value is None):
                self.flag(False, f"line {line}: Request with a positional data argument")

        if name == "urllib.request.urlopen":
            has_data = False
            for keyword in node.keywords:
                if keyword.arg == "data" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None):
                    has_data = True
            if len(node.args) >= 2 and not (isinstance(node.args[1], ast.Constant) and node.args[1].value is None):
                has_data = True
            if has_data:
                self.flag(False, f"line {line}: urlopen(..., data=...) sends a request body")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and id(node) not in self.docstrings:
            lowered = node.value.lower()
            for marker in HARD_STRINGS:
                if marker in lowered:
                    self.errors.append(f"line {node.lineno}: string contains {marker!r}")
            for marker in SOFT_STRINGS:
                if marker in lowered:
                    self.flag(False, f"line {node.lineno}: string contains {marker!r}")
            if node.value.strip().upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                self.flag(False, f"line {node.lineno}: state-changing method {node.value.strip().upper()!r}")
        self.generic_visit(node)


def _docstrings(tree: ast.AST) -> set[int]:
    """Identifiers of string constants that are documentation or guard lists.

    Documentation never becomes a request. A module-level deny-list named
    BLOCKED/GUARD/DENY is a filter, not a target, so its literals are exempt
    from the marker scan — otherwise the script's own guard trips the linter.
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

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if not any(name.upper() in GUARD_NAMES for name in names):
            continue
        if isinstance(node.value, (ast.Tuple, ast.List, ast.Set)):
            for element in node.value.elts:
                found.add(id(element))
    return found


def lint_code(code: str, mode: str = "probe") -> dict:
    if mode not in MODES:
        raise ValueError(f"unknown lint mode: {mode}")
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"ok": False, "mode": mode, "errors": [f"syntax error: {exc.msg} (line {exc.lineno})"], "warnings": []}
    visitor = _Visitor(_docstrings(tree), mode)
    visitor.visit(tree)
    return {
        "ok": not visitor.errors,
        "mode": mode,
        "errors": visitor.errors,
        "warnings": visitor.warnings,
    }
