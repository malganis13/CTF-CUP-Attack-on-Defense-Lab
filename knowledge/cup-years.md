# Кубок CTF, A/D: что было в сервисах 2019–2026

Карта собрана по публичным репозиториям `acisoru`: рядом с каждым сервисом
лежит каталог `sploits/` с готовым эксплойтом и его описанием. Ниже — что
именно было заложено, что из этого видит инструмент и что остаётся руками.

Проверяется машинно: `python tools/test_cup_years.py`. Тест берёт ожидания из
`EXPECTED` в `tools/check_cup.py` и падает, если заложенный класс перестал
находиться. Корпуса, которых нет на диске, пропускаются.

## 2026 — финал СПО, 4 декабря

Публичных A/D-репозиториев 2026 года нет: будет свой набор сервисов. Для
подготовки взяты два ближайших корпуса того же сезона.

| корпус | сервис | язык | заложено | видит инструмент |
|---|---|---|---|---|
| GoCTF-2026 | `starpost` | Python | mass assignment, обход проверки при `limit <= 3`, SQL-склейка | mass assignment, SQL injection, обход баланса |
| GoCTF-2026 | `lighthouse` | C | командная инъекция, `strcpy` | command injection, unsafe string |
| GoCTF-2026 | `greenhouse` | Go | IDOR по номеру объекта | IDOR / BOLA |
| GoCTF-2026 | `orbital_navigation` | Rust | путь из запроса | path traversal (одна точка) |
| letoctf26 | `smc` | Python | SQL-склейка, debug, обход пути | SQL injection ×5, debug, path traversal |
| letoctf26 | `tuzemun` | Node | SQL через переменную, XSS в статике | SQL injection, XSS |
| letoctf26 | `skychat` | C++ | `system()` из команды чата, IDOR в SQL | command injection, IDOR ×3 |

Ветвление логики (`if limit <= 3` в starpost) регуляркой не берётся: это
решение, а не шаблон. Такое ищется чтением обработчика, и в отчёте помечено
как ручное.

## 2025 — сезон A/D

| сервис | язык | заложено | видит инструмент |
|---|---|---|---|
| `veladora` | Go | владелец объекта из тела, XSS, IDOR | owner from request, XSS, IDOR, плавающий тег |
| `warehouse` | Go + React, TLS | SSRF через gateway, IDOR, SQL | SSRF, IDOR, SQL, секрет |
| `archive` | C++ | boost-архив из сети, `boost 1.74` | unsafe deserialization, CVE-2023-34399 |
| `prototype` | Python | SQL-склейка, привилегированный контейнер, hostPath | SQL injection, infra-правила |

## 2024

| корпус | сервис | язык | заложено | видит инструмент |
|---|---|---|---|---|
| school | `filtranator` | Python + C | SQLi в логине, переполнение стека в `filterer`, DoS задержкой | SQL injection ×3, секрет; переполнение — только по бинарнику |
| school | `flysim` | Python | NoSQL-инъекция `$match`, CRC32-токен, `globals().get` из плана полёта | NoSQL injection, unsafe dynamic call |
| LetoCTF24 | `crud` | C++ | отрицательный индекс, сравнение токена по длине, ROP, shutdown по HTTP | out of bounds, prefix compare, command injection |

`filterer` — собранный бинарник без исходников: работает разбор ELF
(импорты, стек, канарейка, PIE), но не дизассемблер. Переполнение
подтверждается руками.

## 2023, 2022 — квалификации, не A/D

`ctfcup2023-quals` и `ctfcup22-quals` — task-based наборы (crypto, pwn, web,
reverse). Сервисов с чекером там нет, поэтому в корпус A/D они не входят.
Полезны как материал для правил: `web/waf`, `web/novosti`, `web/scanner`.

## 2021 — battle

Формат battle: сервисы лежат не в `services/*`, а каталогами в корне
(`bra-ket`, `data-saver`, `web`, `remote-server`, `zadness`). Сканер это
понимает: если `services/` нет, сервисами считаются каталоги верхнего уровня
кроме служебных (`checkers`, `sploits`, `scoreboard`, …).

| сервис | язык | заложено | видит инструмент |
|---|---|---|---|
| `web` | Python (FastAPI) | предсказуемый `JWT_SECRET_KEY` в настройках, `DEBUG=True`, админ-маршрут без проверки | hardcoded secret, debug mode |
| `data-saver` | C++ | pwn по бинарнику, привилегированный контейнер | infra: privileged |
| `bra-ket` | Python | криптография на кубике, подмена `priv_cube` | — (руками) |

## 2020 — финал и отбор

| корпус | сервис | язык | заложено | видит инструмент |
|---|---|---|---|---|
| отбор | `ChessBase` | Python (Sanic) | сборка чужого объекта по id, `pickle` в хранилище | unsafe deserialization; сборка объекта — руками |
| отбор | `QExecute` | C# | свой бинарный протокол, `cookie → upstream` в nginx | SSRF (cookie map), unsafe pointer |
| отбор | `cubic` | Python | авторизация по умножению кубика Рубика | — (руками) |
| финал | `barker` | Python (Django) | IDOR `/get_bark/<id>`, дружба `default=True`, приватные комментарии, предсказуемый токен | object owner, auto-approved relation, owner from request, weak token, debug |
| финал | `VaporService` | C# | TTL-очистка не срабатывает, `UseDeveloperExceptionPage` | dead branch, debug mode |

## 2019

| корпус | сервис | язык | заложено | видит инструмент |
|---|---|---|---|---|
| финал | `medlink` | C# | `Path.Combine` из запроса, слабый токен сессии | path traversal, weak token, debug |
| финал | `planner` | Node | SQL-склейка, свой «фильтр» ввода | SQL injection ×7, manual filter |
| финал | `qdb` | Python | повтор ключа XOR, статический IV, слабый ключ | три крипто-правила |
| тренировка | `chocowrappers` | C# | mass assignment `UserId`, пароли открытым текстом, `.db` в `wwwroot` | mass assignment ×2, секрет |
| тренировка | `icecreams` | Pascal | `secret := 'keepitsecret'`, `md5(user + secret)` | секрет, слабый токен |
| тренировка | `rushmallow` | F# | оракул сравнения `filling` | оракул сравнения |
| тренировка | `kozipipe` | Python | SSRF, гонка, права на файл | path, SSRF |

## Что из этого следует для игры

1. **Шаблон побеждает глубину.** Во всех корпусах 60–70 % заложенного — это
   SQL-склейка, обход пути, `system()`, IDOR по номеру и открытый служебный
   файл. Они закрываются за минуты и находятся первыми.
2. **Языки не выбирают.** C#, F#, Pascal, Rust, C++ и Go встречаются наравне
   с Python. Сканер поэтому языко-агностик: правило привязано к конструкции,
   а не к стеку.
3. **Объект без владельца — самая частая дыра.** `barker`, `greenhouse`,
   `veladora`, `warehouse`, `crud`, `skychat` — один класс: маршрут берёт
   объект по идентификатору и не сверяет владельца. Проверяется парой двух
   аккаунтов, а не чтением кода.
4. **Логика — руками.** TTL, который никогда не срабатывает; обход проверки
   при малом `limit`; админ-маршрут без проверки роли; сборка чужого объекта.
   Регулярка видит форму кода, но не намерение. Это то, что читает человек, и
   именно поэтому в приложении есть ручной регламент.
5. **Чекер важнее находки.** После каждой правки — сначала чекер, потом
   повторный аудит. Правка, после которой сервис красный, — откат.
