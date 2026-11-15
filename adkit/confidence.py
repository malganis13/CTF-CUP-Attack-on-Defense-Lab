"""Насколько инструмент уверен, что находка — настоящая дыра.

Сканер видит форму кода, а не намерение автора. «`WHERE id = ?` без владельца»
— кандидат: владелец может проверяться в middleware, объект может быть публичным
по замыслу. Поэтому у каждой находки есть уровень уверенности и план ручной
проверки: что отправить, что увидеть, что закроет находку.

Три уровня:

- `certain` — совпадение на самом опасном вызове, вход из запроса виден рядом.
  Проверять всё равно надо, но это почти всегда дыра.
- `likely` — конструкция опасная, но между входом и вызовом может стоять
  проверка; либо правило эвристическое (владелец объекта, логика).
- `unsure` — совпадение по форме: бинарник без исходников, инфраструктурный
  манифест, зависимость без версии, правило по пути файла. Может быть и не дыра.

Оценка детерминированная: одни и те же входные данные дают один и тот же ответ.
Ничего не отправляется и не читается — только текст находки.
"""
from __future__ import annotations

# Правила, у которых совпадение — сам опасный вызов.
DIRECT = frozenset({
    "sql-fstring", "sql-format", "php-sql-request", "php-sql-concat",
    "js-sql-template", "go-sql-sprintf", "rust-sql-format", "java-sql-concat",
    "cs-sql-concat", "rb-sql-interp", "sql-exec-var", "py-sql-concat",
    "cmd-shell", "php-shell", "js-exec-request", "go-exec-user", "cs-process",
    "c-shell", "rb-shell", "lua-exec", "rust-command-format", "py-eval",
    "php-eval", "js-eval", "rb-eval", "lua-loadstring",
    "path-join", "path-sink", "go-path-sink", "rust-path", "js-path",
    "php-include", "java-path", "rust-path-join",
    "ssti", "xxe", "deserialization", "php-unserialize",
    "cs-unsafe-deserialization", "cpp-boost-archive",
    "jwt-none", "js-jwt-noverify", "py-jwt-noverify",
    "ssrf", "php-laravel-ssrf", "nginx-cookie-upstream",
    "upload", "php-upload", "open-redirect",
    "c-unsafe-copy", "c-memcpy-length", "c-index-from-input",
})

# Эвристики: форма кода похожа на дыру, но решает контекст.
HEURISTIC = frozenset({
    "idor-id-only", "logic-missing-owner-check", "logic-balance-update",
    "php-laravel-idor", "go-owner-from-request", "py-owner-from-request",
    "cs-model-binding", "mass-assign", "dj-auto-approved",
    "mongo-nosql-request", "py-dynamic-dispatch", "cpp-unsigned-index",
    "c-prefix-compare", "fs-compare-oracle", "cs-dead-ttl",
    "js-weak-sanitizer", "ext-check-bypass", "static-sensitive-file",
    "cs-plaintext-password",
})

# Совсем косвенные признаки.
INDIRECT = frozenset({
    "dep-cve", "infra-image-latest", "infra-privileged", "infra-hostpath",
    "secret-minio-default", "debug-on", "debug-path", "cs-debug-page",
    "hardcoded-secret", "checker-ref", "flag-literal", "rust-unwrap-input",
    "cs-unsafe-pointer", "py-md5-token", "pas-md5-token", "cs-weak-token",
    "pas-static-secret", "py-static-iv", "py-xor-reuse", "py-key-truncation",
    "crypto-custom-cipher",
})

REQUEST_WORDS = (
    "request", "req.", "params", "query", "body", "form", "cookie",
    "args", "input", "param", "$_get", "$_post", "$_request",
)

SANITIZER_WORDS = (
    "int(", "intval", "parseint", "integer.parseint", "strconv.",
    "escape", "sanitize", "secure_filename", "basename", "shlex.quote",
    "realpath", "resolve(", "is_relative_to", "allowed", "allowlist",
    "whitelist", "validate", "parametrized", "prepared",
    "htmlspecialchars", "bleach.clean", "escapehtml",
)

LEVEL_RU = {
    "certain": "уверен",
    "likely": "скорее да",
    "unsure": "не уверен",
}

LEVEL_HINT = {
    "certain": "опасный вызов совпал целиком; проверь одним запросом и закрывай",
    "likely": "похоже на дыру, но решает контекст: между входом и вызовом может быть проверка",
    "unsure": "совпадение по форме; сначала прочитай код вокруг, дыра это или нет",
}


def _window(finding: dict) -> str:
    parts = [str(finding.get("snippet") or "")]
    context = finding.get("context") or []
    if isinstance(context, list):
        parts.extend(str(line) for line in context)
    parts.append(str(finding.get("why") or ""))
    return "\n".join(parts).lower()


def assess(finding: dict) -> dict:
    """Уровень уверенности и план проверки для одной находки."""
    rule = str(finding.get("rule") or "")
    severity = str(finding.get("severity") or "medium")
    window = _window(finding)
    score = 50
    reasons: list[str] = []

    if rule.startswith("flow-taint-"):
        score += 30
        reasons.append("поток значений: связь видна по присваиваниям между строками, "
                       "а не по одному вызову")
    elif rule == "flow-guard-bypass":
        score += 15
        reasons.append("порядок веток: проверка в функции есть, но один путь выходит раньше неё")
    elif rule == "flow-auth-by-value":
        score -= 20
        reasons.append("авторизация сравнением структуры: дыра только если структуру "
                       "можно собрать из открытых данных")
    elif rule in DIRECT:
        score += 40
        reasons.append("правило указывает на сам опасный вызов, а не на похожую форму")
    elif rule in HEURISTIC:
        score -= 20
        reasons.append("эвристика: правило смотрит на форму кода, владельца или связи, а не на конкретный sink")
    elif rule in INDIRECT:
        score -= 30
        reasons.append("косвенный признак: сам по себе не доказывает дыру")

    if finding.get("binary"):
        score -= 30
        reasons.append("бинарь без исходников: разобраны только таблицы и строки, не поток данных")
    if rule.startswith("elf-"):
        score -= 10
        reasons.append("защита сборки — факт о бинаре, не уязвимость сама по себе")
    if rule.startswith("infra-") or rule.startswith("dep-"):
        score -= 10
        reasons.append("находка в манифесте: зависит от того, как сервис развёрнут на площадке")

    if finding.get("param"):
        score += 15
        reasons.append("виден параметр запроса — есть что проверить руками")
    if finding.get("endpoint"):
        score += 10
        reasons.append("виден маршрут — пробу можно отправить сразу")

    if any(word in window for word in REQUEST_WORDS):
        score += 10
        reasons.append("рядом видно чтение запроса")
    else:
        score -= 10
        reasons.append("источник значения в окне не виден: возможно, это конфиг или литерал")

    if any(word in window for word in SANITIZER_WORDS) and rule not in (
            "flow-guard-bypass", "flow-auth-by-value"):
        score -= 20
        reasons.append("рядом есть проверка или экранирование — вероятно, ложное срабатывание")
    if rule == "flow-guard-bypass" and finding.get("verify_line"):
        score += 5
        reasons.append("видна строка проверки, которую эта ветка обходит")

    if severity == "info":
        score -= 15
    if severity == "high" and rule in DIRECT:
        score += 5

    score = max(0, min(100, score))
    if score >= 75:
        level = "certain"
    elif score >= 45:
        level = "likely"
    else:
        level = "unsure"
    # Поток и ветвление — эвристика по определению: подтверждает пробой человек,
    # поэтому «уверен» у них не бывает даже при высоком счёте.
    if rule.startswith("flow-") and level == "certain":
        level = "likely"
        reasons.append("поток — эвристика: вывод подтверждается пробой, а не одним совпадением")

    return {
        "level": level,
        "level_ru": LEVEL_RU[level],
        "hint": LEVEL_HINT[level],
        "score": score,
        "reasons": reasons[:5],
        "plan": plan_for(finding),
        "disproof": disproof_for(finding),
    }


def plan_for(finding: dict) -> list[str]:
    """Что именно сделать руками. Короткие шаги, без теории."""
    kind = str(finding.get("kind") or "")
    rule = str(finding.get("rule") or "")
    endpoint = finding.get("endpoint") or "/путь"
    param = finding.get("param") or "параметр"
    file = finding.get("file") or "файл"
    line = finding.get("line") or 0

    if rule == "flow-guard-bypass":
        return [
            f"открой {file}:{line}: найди проверку подписи и ветку, которая выходит раньше неё",
            "воспроизведи обход: подставь неподписанный токен и добавь параметр, "
            "который включает раннюю ветку",
            "убедись, что ветка реагирует именно на данные запроса, а не на константу",
            "если данные приняли без проверки — это обход аутентификации, а не теория",
        ]
    if rule == "flow-auth-by-value":
        return [
            f"прочитай {file}:{line} и выпиши, что именно сравнивается: объект, хеш или подпись",
            "попробуй собрать эквивалент объекта из открытых данных (публичный ключ, "
            "сохранённое значение, ответ сервера)",
            "если эквивалент принимается без секрета — проверка обходится",
            "если для сборки нужен секрет — это не дыра, а нормальная проверка",
        ]
    if "SQL" in kind:
        return [
            f"открой {file}:{line} и проверь, что {param} действительно приходит из запроса",
            f"отправь {endpoint}?{param}=1%27 — 500 или текст ошибки базы значит дыра",
            f"сравни размеры: {param}=1%20AND%201=1 и {param}=1%20AND%201=2 — разница значит дыра",
            "прочитай таблицу через UNION или ошибку: сначала имена колонок, потом данные",
        ]
    if "NoSQL" in kind:
        return [
            f"отправь {endpoint}?{param}%5B%24regex%5D=.%2A — если набор записей изменился, фильтр собирается из ввода",
            "попробуй {param}[$ne]=null и {param}[$gt]= — обход условия",
            "сверь с ответом без нагрузки: должен быть другой набор",
        ]
    if "Path traversal" in kind or "file inclusion" in kind.lower():
        return [
            f"отправь {endpoint}?{param}=../../../../etc/passwd",
            "если режет — попробуй ....//....//etc/passwd (после replace снова ../)",
            "ищи в ответе root:x:0:0:; затем читай конфиг сервиса и строку подключения",
        ]
    if "Command injection" in kind or "code execution" in kind.lower():
        return [
            f"отправь {endpoint}?{param}=127.0.0.1;id — ищи uid=",
            "если ; режет — пробуй |id, &&id, $(id), `id`, %0aid",
            "проверь, что без нагрузки ответ обычный: это контроль",
        ]
    if "template injection" in kind.lower():
        return [
            f"отправь {endpoint}?{param}={{7*7}} — ответ 49 значит шаблон исполняется",
            "дальше {{config}} или {{''.__class__.__mro__}} для Python",
            "если 49 нет — проверь ${7*7} и <%= 7*7 %>",
        ]
    if "IDOR" in kind or "owner" in kind.lower():
        return [
            "нужны два своих аккаунта: A и B (второй — обычная регистрация)",
            f"создай объект под A, запомни номер из {endpoint}",
            "запроси тот же номер под B: 200 и тот же ответ значит объекта не привязан к владельцу",
            "для проверки без второго аккаунта: тот же запрос без куки — 200 значит маршрут открыт",
        ]
    if "JWT" in kind or rule.startswith("py-jwt") or rule.startswith("js-jwt"):
        return [
            "собери токен с alg=none: header и payload в base64url, подпись пустая",
            "подставь в Authorization или куку и повтори запрос",
            "если приняли — проверки подписи нет; если 401 — ищи слабый секрет в конфиге",
        ]
    if "deserialization" in kind.lower():
        return [
            f"посмотри {file}:{line}: что именно десериализуется и откуда берутся байты",
            "если источник — сеть, отправь безвредный маркер (например, pickle-строку с известным классом)",
            "признак дыры: сервер отвечает 500 с трейсом, где виден загруженный класс",
        ]
    if "Mass assignment" in kind or "owner from request" in kind.lower():
        return [
            "под своим аккаунтом отправь POST с дополнительным полем: role=admin, userId=1, isAdmin=true",
            "проверь ответ и профиль: если поле приняли — объект пишется с чужими правами",
            "повтори без поля: профиль должен остаться прежним",
        ]
    if "Weak session token" in kind or "secret" in kind.lower():
        return [
            f"прочитай {file}:{line} и выпиши, из чего собирается токен",
            "попробуй собрать такой же для другого пользователя и подставить",
            "если получилось — это подделка сессии, а не просто «слабый секрет»",
        ]
    if "Business logic" in kind:
        return [
            f"прочитай обработчик {file}:{line} целиком: какие проверки есть до записи",
            "повтори операцию дважды и с отрицательным/огромным значением",
            "смотри, меняется ли состояние: баланс, владелец, счётчик, статус",
        ]
    if "Debug" in kind or "Sensitive route" in kind:
        return [
            f"открой маршрут {endpoint} без сессии",
            "ищи в ответе трейс, переменные окружения, пути к файлам",
            "если отдаёт — закрывай маршрут или выключай debug",
        ]
    if finding.get("binary"):
        return [
            f"запусти файл {file} в песочнице и посмотри, какие входные данные он читает",
            "проверь импорты: system/strcpy — это ещё не дыра, нужен путь от ввода",
            "если исходников нет, дальше только Ghidra и отладчик",
        ]
    return [
        f"прочитай {file}:{line} и найди, откуда приходит значение",
        "проверь, есть ли между входом и вызовом проверка: приведение типа, белый список, basename",
        f"отправь контрольный запрос на {endpoint} и запрос с нагрузкой по {param}",
        "сравни ответы: разница в статусе, размере или тексте — сигнал",
    ]


def disproof_for(finding: dict) -> list[str]:
    """Что закроет находку, если это ложное срабатывание."""
    kind = str(finding.get("kind") or "")
    base = [
        "значение приходит из конфига или литерала, а не из запроса — правило не про этот случай",
        "между входом и вызовом стоит приведение типа или белый список, и его нельзя обойти",
    ]
    if "SQL" in kind:
        base.append("запрос параметризован: `?`/`$1`/`%s`, а не склейка")
    if "IDOR" in kind or "owner" in kind.lower():
        base.append("маршрут отвечает 404 на чужой объект под вторым аккаунтом")
    if "NoSQL" in kind:
        base.append("в фильтр попадает только строка: объект из JSON не принимается")
    if "Path traversal" in kind:
        base.append("путь проходит через secure_filename/basename и проверку корня")
    if "Command injection" in kind:
        base.append("вызов идёт списком аргументов без shell, вход — из белого списка")
    return base[:4]


def assess_many(findings: list[dict]) -> dict:
    """Раскладывает находки по уверенности и считает сводку."""
    counts = {"certain": 0, "likely": 0, "unsure": 0}
    for finding in findings:
        if not finding.get("confidence"):
            finding["confidence"] = assess(finding)
        level = finding["confidence"].get("level", "unsure")
        counts[level] = counts.get(level, 0) + 1
    total = max(1, len(findings))
    return {
        "counts": counts,
        "clearly_worth_checking": counts["certain"],
        "manual_read_needed": counts["unsure"],
        "share_unsure": round(100 * counts["unsure"] / total),
    }
