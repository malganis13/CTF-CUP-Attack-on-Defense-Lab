# Языки: что сканер реально видит

Задача A/D не гарантирует язык. Сервис может быть на Python, Go, PHP, Node,
Java, C# — админ выбирает то, что быстрее поднять. Поэтому сканер читает исходники
как текст и держит отдельный набор правил под каждый язык.

## Таблица

Полная таблица с числом правил — в интерфейсе, вкладка **Rules → Coverage**.
Ниже — то же самое словами.

| Язык | Что ищется |
|---|---|
| Python | SQL (f-string, конкатенация, `.execute(var)`), IDOR, path traversal, `shell=True`, `os.system`, pickle, SSTI, JWT `verify=False`, upload, redirect |
| Go | SQL через `fmt.Sprintf`, `exec.Command` с данными запроса, `os.ReadFile`, роуты `net/http`, gin, chi, echo, fiber |
| Rust | SQL через `format!`, `.arg(format!(…))`, `Command::new` с вводом, `fs::read_to_string`, `unwrap` на разборе, роуты axum, actix, rocket |
| JavaScript / TypeScript | SQL через шаблонные строки, `eval(req…)`, `fs.readFile(req…)`, `exec`/`execSync`, `innerHTML`, `jwt.decode` без ключа, роуты express, koa, fastify, nest |
| PHP | `$_GET`/`$_POST` в запрос, `system`/`exec`/`eval`/`include`, `move_uploaded_file`, `unserialize`, `Route::` |
| Java / Kotlin | SQL конкатенацией, `new File(request…)`, `Runtime.exec`, `ObjectInputStream`, `@GetMapping`/`@RequestMapping` |
| C# | `SqlCommand` конкатенацией, `Process.Start`, `[HttpGet]` |
| C / C++ | `strcpy`/`sprintf`/`gets`, `system`/`popen`, `memcpy` без `sizeof` |
| Ruby | `where("… #{…}")`, `system(params…)`, `eval(params…)`, `YAML.load`, роуты Rails и Sinatra |
| Lua | `loadstring`, `os.execute` |

## Как читать «правило сработало»

Правило привязано к языку и запускается только на файлах этого языка —
`Rule(languages=(...))` в `adkit/patterns.py`. Файл без расширения определяется
по shebang (`#!/usr/bin/env python3`).

Универсальные правила (SQL по ключевым словам, IDOR, секреты, ссылки на чекер)
работают везде.

## Чего сканер не делает

- Не разбирает AST для Go, Rust, Java, C# — только регулярки по строкам.
- Не отслеживает поток данных между файлами и функциями.
- Не читает бинарники: только исходники и манифесты.
- Не понимает шаблоны вроде Jinja внутри HTML — только код.

Поэтому находка — это адрес, а не приговор. Открыть файл, прочитать ±5 строк,
решить самому.

## Манифесты

Сканер отдельно читает `go.mod`, `Cargo.toml`, `package.json`, `composer.json`,
`pom.xml`, `build.gradle`, `Gemfile`, `requirements.txt`, `pyproject.toml`,
`Pipfile`, `*.csproj`, `Dockerfile` и выводит стек сервиса в колонке **stack**:
`go/gin`, `php/laravel`, `rust/axum`, `javascript/express`, `java/spring`,
`ruby/sinatra`. Это отвечает на вопрос «что тут вообще крутится» до чтения кода.
