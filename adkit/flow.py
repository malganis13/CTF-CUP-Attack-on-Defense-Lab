"""Поток значений и логика ветвления: то, что регулярка не видит.

Правила в `patterns.py` смотрят на строку. Этот модуль смотрит на файл целиком
и отвечает на два вопроса, которые строкой не решаются:

1. **Откуда пришло значение.** Переменная, взятая из запроса на строке 12,
   доезжает до `execute` на строке 40 через два присваивания. Строка 40 сама по
   себе выглядит безобидно: в ней нет ни `request`, ни кавычек. Поток это видит.
2. **Что стоит между проверкой и возвратом.** Если функция проверяет подпись,
   но в одной ветке возвращает разобранные данные до вызова `compare_digest`,
   дыра не в строке — дыра в порядке веток. Это ловится разбором области
   видимости, а не шаблоном.

Третий, самый слабый детектор — авторизация равенством объекта, собранного из
ввода (`cube.multiply(...) != stored`). Он не доказывает дыру: он показывает
место, где решение об авторизации принимается сравнением структуры, которую
пользователь может собрать сам.

Всё intra-procedural: присваивания в пределах файла, без межфайлового анализа
и без вызова по функциям. Это осознанный предел: глубже — уже интерпретатор.

Находки помечаются `flow: true` и правилом `flow-*`; уверенность у них ниже,
чем у прямого совпадения sink'а, потому что поток — эвристика, а не доказательство.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- источники ввода -------------------------------------------------------

SOURCES = {
    "python": re.compile(
        r"request\.(?:args|form|values|json|data|files|headers|cookies|get_json)\b"
        r"|flask\.request\b|self\.request\b|input\s*\(",
    ),
    "javascript": re.compile(
        r"\breq\.(?:query|body|params|headers|cookies|url)\b"
        r"|\brequest\.(?:query|body|params|headers)\b"
        r"|\bctx\.request\b|\blocation\.(?:search|hash)\b",
    ),
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),
    "go": re.compile(
        r"\br\.URL\.Query\(\)|\br\.FormValue\b|\br\.PostFormValue\b|\br\.Header\.Get\b"
        r"|\bc\.(?:Query|Param|PostForm|GetHeader)\b|\bctx\.(?:Query|Param)\b",
    ),
    "ruby": re.compile(r"\bparams\[|\brequest\.(?:params|body|query)\b"),
    "csharp": re.compile(r"\bRequest\.(?:Query|Form|Body|Headers)\b|\bHttpContext\b"),
    "java": re.compile(r"\brequest\.get(?:Parameter|Header|Cookies)\b"),
}

# --- очистка от проверок ---------------------------------------------------

SANITIZERS = re.compile(
    r"\bint\s*\(|\bfloat\s*\(|\bparseInt\b|\bparseFloat\b|\bNumber\s*\("
    r"|\bintval\b|\bstrconv\.(?:Atoi|ParseInt|ParseFloat)\b|\bInteger\.parseInt\b"
    r"|\bToInt32\b|\bTryParse\b|\bto_i\b"
    r"|secure_filename|\bbasename\b|\brealpath\b|\bresolve\s*\(|\bis_relative_to\b"
    r"|\bescape\b|\bhtmlspecialchars\b|\bbleach\.clean\b|\bquote\s*\(|\bshlex\.quote\b"
    r"|\bfullmatch\b|\bmatches\s*\(|\bre\.match\b|\bisdigit\b|\bisnumeric\b"
    r"|\ballowed\b|\bwhitelist\b|\bvalidate\w*\b|\bsanitiz\w*\b",
    re.I,
)

# --- стоки ----------------------------------------------------------------

SINKS = (
    # (класс, вид, важность, регулярка вызова)
    ("sql", "SQL injection", "high",
     re.compile(r"\b(?:execute|executemany|raw|query|prepare)\s*\(", re.I)),
    ("cmd", "Command injection", "high",
     re.compile(r"\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output|check_call)"
                r"|child_process\.exec\w*|shell_exec|system|popen|exec|spawn)\s*\(", re.I)),
    ("path", "Path traversal", "medium",
     re.compile(r"\b(?:open|send_file|readFile\w*|file_get_contents|include|require"
                r"|os\.path\.join|Path|join)\s*\(", re.I)),
    ("code", "Code execution", "high",
     re.compile(r"\b(?:eval|exec|Function|pickle\.loads|yaml\.load|unserialize|Marshal\.load)\s*\(", re.I)),
    ("ssrf", "SSRF", "medium",
     re.compile(r"\b(?:requests\.(?:get|post|put|head)|urlopen|fetch|axios\.\w+|http\.Get|HttpClient)\s*\(", re.I)),
    ("template", "Template injection", "high",
     re.compile(r"\b(?:render_template_string|Template|render|compile)\s*\(", re.I)),
)

ASSIGN = re.compile(
    r"^\s*(?:var|let|const|my|local|public|private|protected|static|final|val|auto|"
    r"let\s+mut|mut|Dim|set)\s+"
    r"([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=]+)?=\s*(.+)$"
    r"|^\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=]+)?(?:=|:=)\s*(.+)$",
)

VERIFY = re.compile(
    r"hmac\.compare_digest|compare_digest|hash_equals|hmac\.Equal|timingSafeEqual"
    r"|secure_compare|signature\.verify|\.verify\(|jwt\.decode|jwt\.verify"
    r"|check_password|bcrypt|password_verify|is_valid_signature|validate_signature"
    r"|verify_signature|check_signature",
    re.I,
)

DECODER = re.compile(
    r"\b(?:json\.loads|_json\.loads|JSON\.parse|loads|b64decode|urlsafe_b64decode"
    r"|base64_decode|decodeURIComponent|Decode|Unmarshal|JSON\.parse)\b",
    re.I,
)

FUNC_PY = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
FUNC_CURLY = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("
    r"|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>)",
)

AUTH_NAME = re.compile(r"(?:^|_)(?:login|auth|verify|check|signin|sign_in|validate)(?:$|_)", re.I)
COMPARE = re.compile(r"(==|!=|===|!==)")
NUM = re.compile(r"(?:<=|>=|<|>|==|!=|===|!==)\s*(\d{1,6})\b")
VALUE_COMPARE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(?:multiply|pow|hash|digest|encrypt|decrypt|sign)\s*\(",
    re.I,
)

MAX_FLOW_PER_FILE = 24


@dataclass
class Taint:
    var: str
    source_line: int
    chain: str


def _language(reference: str, hint: str) -> str:
    if hint:
        return hint
    name = reference.lower()
    if name.endswith(".py"):
        return "python"
    if name.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")):
        return "javascript"
    if name.endswith(".php"):
        return "php"
    if name.endswith(".go"):
        return "go"
    if name.endswith(".rb"):
        return "ruby"
    if name.endswith(".cs"):
        return "csharp"
    if name.endswith(".java"):
        return "java"
    return "any"


def _code(raw: str, language: str) -> str:
    """Строка без комментария. Строки не трогаем: кавычки нужны для sink'ов."""
    stripped = raw.strip()
    if stripped.startswith(("#", "//", "/*", "*", "--")):
        return ""
    if language in ("python", "ruby"):
        cut = raw.find(" #")
        if cut > 0:
            return raw[:cut]
        return raw
    for marker in (" //", "\t//"):
        cut = raw.find(marker)
        if cut > 0:
            return raw[:cut]
    return raw


def _assignments(code: str) -> tuple[list[str], str] | None:
    match = ASSIGN.match(code)
    if not match:
        return None
    names = (match.group(1) or match.group(3) or "").strip()
    value = (match.group(2) or match.group(4) or "").strip()
    if not names or not value:
        return None
    return [part.strip() for part in names.split(",") if part.strip()], value


def _mentions(text: str, name: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text) is not None


def _scope_python(lines: list[str], start: int) -> int:
    indent = len(lines[start]) - len(lines[start].lstrip())
    for index in range(start + 1, len(lines)):
        raw = lines[index]
        if not raw.strip():
            continue
        current = len(raw) - len(raw.lstrip())
        if current <= indent:
            return index - 1
    return len(lines) - 1


def _scope_curly(lines: list[str], start: int) -> int:
    depth = 0
    opened = False
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if "{" in lines[index]:
            opened = True
        if opened and depth <= 0:
            return index
    return len(lines) - 1


def _scopes(lines: list[str], language: str) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []
    if language == "python":
        for index, raw in enumerate(lines):
            match = FUNC_PY.match(raw)
            if not match:
                continue
            result.append((match.group(2), index, _scope_python(lines, index)))
        return result
    if language in ("javascript", "php", "go", "csharp", "java", "ruby"):
        for index, raw in enumerate(lines):
            match = FUNC_CURLY.search(raw)
            if not match:
                continue
            name = match.group(1) or match.group(2) or match.group(3) or "?"
            result.append((name, index, _scope_curly(lines, index)))
    return result


def _tainted(value: str, taint: dict[str, Taint], language: str) -> Taint | None:
    source = SOURCES.get(language)
    if source and source.search(value):
        return None  # прямой источник: его ловит обычное правило
    for name, entry in taint.items():
        if _mentions(value, name):
            return entry
    return None


def _source_line(value: str, language: str) -> bool:
    source = SOURCES.get(language) or SOURCES["python"]
    return bool(source.search(value))


def _string_only(argument: str) -> bool:
    """Аргумент — строковый литерал без склейки, форматирования и подстановки."""
    text = argument.strip()
    match = re.match(r"""^[rbfu]?(['"])(.*?)\1\s*(?:,|$)""", text, re.S)
    if not match:
        return False
    body = match.group(2)
    return not re.search(r"\{|\$\{|\+\s*[A-Za-z_$]", body)


def _first_argument(code: str, start: int) -> str:
    depth = 0
    quote = ""
    for index in range(start, len(code)):
        char = code[index]
        if quote:
            if char == quote and code[index - 1] != "\\":
                quote = ""
            continue
        if char in "'\"`":
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return code[start + 1:index]
        if char == "," and depth == 1:
            return code[start + 1:index]
    return code[start + 1:]


def _finding(rule: str, kind: str, severity: str, path: str, number: int,
             raw: str, lines: list[str], language: str, why: str,
             patch: str, **extra) -> dict:
    start = max(0, number - 4)
    return {
        "id": f"{rule}-{number}",
        "rule": rule,
        "kind": kind,
        "severity": severity,
        "file": path,
        "line": number + 1,
        "snippet": raw.strip()[:240],
        "context": lines[start: number + 3],
        "context_start": start + 1,
        "why": why,
        "patch": patch,
        "checker_risk": "low",
        "language": language,
        "flow": True,
        **extra,
    }


def taint(path: str, text: str, language: str = "") -> list[dict]:
    """Переменная из запроса доезжает до опасного вызова через присваивания."""
    language = _language(path, language)
    lines = text.splitlines()
    taint_map: dict[str, Taint] = {}
    findings: list[dict] = []

    for number, raw in enumerate(lines):
        code = _code(raw, language)
        if not code.strip():
            continue

        assignment = _assignments(code)
        if assignment:
            names, value = assignment
            if SANITIZERS.search(value):
                for name in names:
                    taint_map.pop(name, None)
                continue
            source_line = _source_line(value, language)
            entry = _tainted(value, taint_map, language)
            if source_line:
                for name in names:
                    taint_map[name] = Taint(name, number + 1, f"строка {number + 1}: источник ввода")
                continue
            if entry:
                for name in names:
                    taint_map[name] = Taint(name, entry.source_line,
                                            f"{entry.chain} → строка {number + 1}: {name}")
                continue
            for name in names:
                taint_map.pop(name, None)

        for cls, kind, severity, sink in SINKS:
            match = sink.search(code)
            if not match:
                continue
            argument = _first_argument(code, match.end() - 1)
            entry = _tainted(argument, taint_map, language)
            direct = _source_line(argument, language)
            if not entry and not direct:
                continue
            # Параметризованный запрос: значение ушло во второй аргумент, а
            # первый — литерал. Это не дыра, это правильный код.
            if cls == "sql" and _string_only(argument) and "," in code[match.end():]:
                continue
            if entry is None:
                continue  # прямой источник на строке sink'а ловит patterns.py
            why = (
                f"значение пришло из запроса и дошло до опасного вызова без проверки: "
                f"{entry.chain}. Строка вызова сама по себе выглядит обычно — "
                f"поэтому шаблон её и пропускает."
            )
            findings.append(_finding(
                f"flow-taint-{cls}", kind, severity, path, number, raw, lines, language,
                why,
                "Приведите значение к типу на входе (int/parse), используйте "
                "параметризованный запрос или белый список — правка та же, что у "
                "одноимённого шаблонного правила.",
                source_line=entry.source_line,
                variable=entry.var,
            ))
            if len(findings) >= MAX_FLOW_PER_FILE:
                return findings
            break
    return findings


def _params(signature: str) -> list[str]:
    """Имена параметров из строки сигнатуры (без типов и значений по умолчанию)."""
    start = signature.find("(")
    if start < 0:
        return []
    depth = 0
    end = len(signature)
    for index in range(start, len(signature)):
        if signature[index] == "(":
            depth += 1
        elif signature[index] == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    inner = signature[start + 1:end]
    names: list[str] = []
    for part in inner.split(","):
        token = part.strip()
        if not token:
            continue
        token = token.split("=")[0].strip()
        token = token.split(":")[0].strip()
        token = token.lstrip("*&").strip()
        if re.fullmatch(r"[A-Za-z_]\w*", token):
            names.append(token)
    return names


def _file_derived(lines: list[str], language: str) -> set[str]:
    """Переменные файла, которые принимают значение из запроса.

    Нужны, чтобы понять, что аргумент вызова пришёл из ввода: `_parse(cursor,
    limit_raw)` — параметры этой функции тоже управляются запросом.
    """
    derived: set[str] = set()
    for _ in range(2):  # два прохода: присваивание от присваивания
        for raw in lines:
            code = _code(raw, language)
            assignment = _assignments(code)
            if not assignment:
                continue
            names, value = assignment
            if _source_line(value, language) or any(_mentions(value, item) for item in derived):
                derived.update(names)
    return derived


def _balanced(code: str, open_index: int) -> str:
    """Содержимое скобок с учётом вложенности: `parse(a, req.get("x"))` целиком."""
    depth = 0
    quote = ""
    for index in range(open_index, len(code)):
        char = code[index]
        if quote:
            if char == quote and code[index - 1] != "\\":
                quote = ""
            continue
        if char in "'\"`":
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return code[open_index + 1:index]
    return code[open_index + 1:]


def _param_derived(lines: list[str], language: str, known: set[str]) -> dict[str, set[str]]:
    """Функции, которым из запроса приходит аргумент: их параметры — вход."""
    result: dict[str, set[str]] = {}
    signatures: dict[str, list[str]] = {}
    for raw in lines:
        match = FUNC_PY.match(raw) or FUNC_CURLY.search(raw)
        if not match:
            continue
        name = match.group(2) if match.re is FUNC_PY else (
            match.group(1) or match.group(2) or match.group(3))
        if name:
            signatures[name] = _params(raw)
    for raw in lines:
        code = _code(raw, language)
        for name, params in signatures.items():
            for match in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
                arguments = _balanced(code, match.end() - 1)
                if _source_line(arguments, language) or any(
                        _mentions(arguments, item) for item in known):
                    result.setdefault(name, set()).update(params)
    return result


def guard(path: str, text: str, language: str = "") -> list[dict]:
    """Ветка, которая возвращает данные до проверки подписи."""
    language = _language(path, language)
    lines = text.splitlines()
    findings: list[dict] = []
    file_derived = _file_derived(lines, language)
    param_derived = _param_derived(lines, language, file_derived)

    for name, start, end in _scopes(lines, language):
        verify_lines = [index for index in range(start, end + 1)
                        if VERIFY.search(_code(lines[index], language))]
        if not verify_lines:
            continue
        first_verify = verify_lines[0]

        # Переменные, которыми управляет запрос: тип приводить можно, значение —
        # всё равно из ввода, поэтому int() их не «очищает» для логики веток.
        derived: set[str] = set(param_derived.get(name, set()))
        for index in range(start, first_verify):
            code = _code(lines[index], language)
            if not code.strip():
                continue
            assignment = _assignments(code)
            if not assignment:
                continue
            names, value = assignment
            if _source_line(value, language):
                derived.update(names)
            elif any(_mentions(value, item) for item in derived):
                derived.update(names)

        if not derived:
            continue

        for index in range(start, first_verify):
            code = _code(lines[index], language)
            if not code.strip():
                continue
            if not re.match(r"^\s*(?:if|elif|else if|when)\b", code):
                continue
            condition = code[code.find("if") + 2:] if "if" in code else code
            if not NUM.search(condition):
                continue
            if not any(_mentions(condition, item) for item in derived):
                continue

            body_end = _branch_end(lines, index, end, language)
            body = "\n".join(lines[index + 1: body_end + 1])
            if not re.search(r"\b(?:return|raise|continue|break)\b", body):
                continue
            early = body_end < first_verify
            decoder = bool(DECODER.search(body))
            if not early and not decoder:
                continue

            why = (
                f"в функции {name} проверка подписи стоит на строке {first_verify + 1}, "
                f"а ветка на строке {index + 1} реагирует на значение из запроса и "
                f"выходит раньше неё"
                + (", разбирая данные без проверки" if decoder else "")
                + ". Подпись проверяется, но не на этом пути — этого достаточно для обхода."
            )
            findings.append(_finding(
                "flow-guard-bypass", "Broken authentication", "high",
                path, index, lines[index], lines, language, why,
                "Проверку подписи/токена вынесите до любой ветки, которая читает "
                "данные: сначала verify, потом разбор. Значение из запроса не "
                "должно менять порядок проверок.",
                verify_line=first_verify + 1,
                function=name,
            ))
            break
    return findings


def _branch_end(lines: list[str], start: int, limit: int, language: str) -> int:
    """Конец тела ветки: отступ для Python, скобки для остальных."""
    if language == "python":
        indent = len(lines[start]) - len(lines[start].lstrip())
        for index in range(start + 1, limit + 1):
            raw = lines[index]
            if not raw.strip():
                continue
            current = len(raw) - len(raw.lstrip())
            if current <= indent:
                return index - 1
        return limit
    depth = 0
    opened = False
    for index in range(start, limit + 1):
        depth += lines[index].count("{") - lines[index].count("}")
        if "{" in lines[index]:
            opened = True
        if opened and depth <= 0:
            return index
    return limit


def value_auth(path: str, text: str, language: str = "") -> list[dict]:
    """Авторизация сравнением структуры, которую пользователь может собрать."""
    language = _language(path, language)
    lines = text.splitlines()
    findings: list[dict] = []

    for name, start, end in _scopes(lines, language):
        if not AUTH_NAME.search(name):
            continue
        verify_lines = [index for index in range(start, end + 1)
                        if VERIFY.search(_code(lines[index], language))]
        if verify_lines:
            continue  # есть нормальная проверка — не наш случай
        for index in range(start, end + 1):
            code = _code(lines[index], language)
            if not re.match(r"^\s*if\b", code):
                continue
            if not COMPARE.search(code):
                continue
            if not VALUE_COMPARE.search(code):
                continue
            if not _source_line("\n".join(lines[start: index + 1]), language):
                continue
            findings.append(_finding(
                "flow-auth-by-value", "Broken authentication", "medium",
                path, index, lines[index], lines, language,
                f"в функции {name} решение об авторизации принимается сравнением "
                f"объекта, собранного из ввода, с сохранённым значением. Если "
                f"структура допускает сборку эквивалента без секрета, проверка "
                f"обходится без подбора пароля.",
                "Сравнивайте не объект, а результат проверки секрета: подпись "
                "HMAC, хеш пароля, серверный токен. Если протокол обязан "
                "сравнивать структуру — проверьте, что её нельзя собрать из "
                "открытых данных.",
                function=name,
            ))
            break
    return findings


def analyze(path: str, text: str, language: str = "") -> list[dict]:
    """Все потоковые находки по файлу, без повторов по строке и правилу."""
    result: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for detector in (taint, guard, value_auth):
        for finding in detector(path, text, language):
            key = (finding["rule"], finding["line"])
            if key in seen:
                continue
            seen.add(key)
            result.append(finding)
    return result[:MAX_FLOW_PER_FILE]
