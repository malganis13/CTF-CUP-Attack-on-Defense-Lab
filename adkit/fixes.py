"""Конкретные способы закрыть находку.

Аудит отвечает на вопрос «где дыра». Этот модуль отвечает на второй вопрос —
«как закрыть, не сломав сервис». Для каждого класса уязвимости здесь лежит:

  before   — как выглядит опасный код (шаблон);
  after    — как выглядит безопасный, на языке сервиса;
  steps    — порядок правки и проверки;
  breaks   — что может отвалиться у чекера и клиентов;
  risk     — насколько правка опасна для раунда.

Никакой автоматической записи на цель: правка показывается, применяет её
человек. Это осознанно — аудит read-only, и остаётся таким.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Fix:
    key: str
    title: str
    before: tuple[str, ...]
    after: dict[str, tuple[str, ...]]      # язык -> строки кода
    steps: tuple[str, ...]
    breaks: str
    risk: str = "low"


def _sql() -> Fix:
    return Fix(
        key="sql",
        title="Параметризованный запрос вместо склейки",
        before=("cursor.execute(f\"SELECT ... WHERE title LIKE '%{q}%'\")",),
        after={
            "python": (
                'cursor.execute(',
                '    "SELECT id, title, body FROM notes WHERE title LIKE ?",',
                '    ("%" + q + "%",),',
                ')',
            ),
            "javascript": (
                "db.query(",
                '  "SELECT id, title FROM files WHERE title LIKE ?",',
                '  [`%${term}%`],',
                ");",
            ),
            "php": (
                '$stmt = $db->prepare("SELECT id, name, price FROM items WHERE id = :id");',
                '$stmt->bindValue(":id", (int) $_GET["id"], SQLITE3_INTEGER);',
                "$row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);",
            ),
            "go": (
                'row := db.QueryRow("SELECT name FROM items WHERE id = ?", r.URL.Query().Get("id"))',
            ),
            "java": (
                'PreparedStatement ps = conn.prepareStatement(',
                '    "SELECT * FROM items WHERE id = ?");',
                'ps.setString(1, request.getParameter("id"));',
            ),
            "csharp": (
                'var cmd = new SqlCommand("SELECT * FROM Items WHERE Id = @id", conn);',
                'cmd.Parameters.AddWithValue("@id", Request.Query["id"].ToString());',
            ),
            "ruby": (
                'DB[:items].where(id: params[:id]).all',
            ),
            "rust": (
                'sqlx::query_scalar("SELECT name FROM items WHERE id = $1")',
                '    .bind(id)',
                '    .fetch_one(&pool).await?;',
            ),
        },
        steps=(
            "найди все места, где в SQL попадает строка из запроса",
            "замени склейку на bind/placeholder; имя таблицы или сортировку бери из белого списка, не из параметра",
            "перезапусти сервис: systemctl restart <unit>",
            "прогони пробу заново — находка должна исчезнуть, ответ ручки остаться прежним",
            "дождись раунда чекера: сервис должен отдать флаг",
        ),
        breaks="если ручка принимает произвольный SQL (админ-консоль, отчёты) — параметризация сломает такой ввод; такие места переводи на отдельный whitelisted-конструктор",
    )


def _path() -> Fix:
    return Fix(
        key="path",
        title="Канонический путь и проверка префикса",
        before=('open(os.path.join(DATA_DIR, name), "rb")',),
        after={
            "python": (
                "base = os.path.realpath(DATA_DIR)",
                "target = os.path.realpath(os.path.join(base, name))",
                "if not target.startswith(base + os.sep):",
                '    raise PermissionError("path outside root")',
                'return open(target, "rb").read()',
            ),
            "javascript": (
                "const base = fs.realpathSync(DATA);",
                "const target = fs.realpathSync(path.join(base, name));",
                "if (!target.startsWith(base + path.sep)) {",
                '  return send(res, 403, "path outside root");',
                "}",
            ),
            "php": (
                "$base = realpath('/srv/warehouse/files');",
                "$target = realpath($base . '/' . basename($_GET['name']));",
                "if ($target === false || !str_starts_with($target, $base . DIRECTORY_SEPARATOR)) {",
                '    http_response_code(403); exit("path outside root");',
                "}",
            ),
            "go": (
                'name := filepath.Base(r.URL.Query().Get("name"))',
                'target := filepath.Join(root, name)',
                'if !strings.HasPrefix(target, root+string(os.PathSeparator)) {',
                '    http.Error(w, "forbidden", http.StatusForbidden); return',
                "}",
            ),
            "rust": (
                "let name = Path::new(param).file_name().ok_or(Error::BadName)?;",
                "let target = root.join(name);",
                "if !target.starts_with(&root) { return Err(Error::Forbidden); }",
            ),
        },
        steps=(
            "вычисли realpath и проверь, что он внутри каталога сервиса",
            "имена файлов бери через basename или строгий regex, не как путь",
            "перезапусти сервис и повтори пробу",
            "проверь, что чекер по-прежнему читает свой файл: путь флага не должен попасть под запрет",
        ),
        breaks="если сервис легально отдаёт файлы из нескольких каталогов — сделай список разрешённых корней, а не один",
    )


def _cmd() -> Fix:
    return Fix(
        key="cmd",
        title="Аргументы вместо строки, никакого shell",
        before=('os.system("ping -c 1 " + host)',),
        after={
            "python": (
                "subprocess.run(",
                '    ["ping", "-c", "1", "-W", "1", host],',
                "    capture_output=True, timeout=5, check=False,",
                ")",
            ),
            "javascript": (
                "execFile('/usr/bin/ping', ['-c', '1', '-W', '1', host], { timeout: 4000 },",
                "  (error, stdout, stderr) => { /* ... */ });",
            ),
            "php": (
                '$host = escapeshellarg($_GET["host"]);',
                "$out = shell_exec(\"/usr/bin/ping -c 1 -W 1 \" . $host);",
            ),
            "go": (
                'out, err := exec.Command("ping", "-c", "1", "-W", "1", host).CombinedOutput()',
            ),
            "ruby": (
                'out, status = Open3.capture2("ping", "-c", "1", "-W", "1", host)',
            ),
            "csharp": (
                'var psi = new ProcessStartInfo("ping") { UseShellExecute = false };',
                'psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("1"); psi.ArgumentList.Add(host);',
            ),
        },
        steps=(
            "убери shell: argv-массив или escapeshellarg",
            "проверь сам аргумент: hostname-regex, без пробелов, кавычек, ; | & $()",
            "перезапусти сервис, прогони пробу — инъекция не должна выполняться",
            "проверь легальный вызов: ping по нормальному адресу должен отвечать",
        ),
        breaks="если сервис принимает составную команду (флаги+цель одной строкой) — разбей на отдельные параметры формы",
    )


def _deser() -> Fix:
    return Fix(
        key="deser",
        title="Формат без исполнения кода",
        before=("pickle.loads(base64.b64decode(raw))",),
        after={
            "python": (
                "import json",
                'state = json.loads(base64.b64decode(raw))   # или его own-формат',
                'allowed = {"theme", "page", "lang"}',
                "state = {k: v for k, v in state.items() if k in allowed}",
            ),
            "php": (
                "$cart = json_decode($_COOKIE['cart'] ?? '[]', true, 8);",
                "// unserialize не использовать; если очень нужно — allowed_classes => false",
            ),
            "java": (
                "// ObjectInputStream на входе — запрещён; используй JSON-маппер",
                "ObjectMapper mapper = new ObjectMapper();",
                "State state = mapper.readValue(body, State.class);",
            ),
            "ruby": (
                "state = JSON.parse(cookies[:cart])",
            ),
        },
        steps=(
            "замени бинарный/нативный формат на JSON",
            "проверь поля по белому списку, не восстанавливай произвольные объекты",
            "перезапусти и повтори пробу",
            "убедись, что чекер не кладёт в этот параметр своё состояние",
        ),
        breaks="старые cookie/сессии перестанут читаться — это нормально, но предупреди команду, если состояние общее",
    )


def _jwt() -> Fix:
    return Fix(
        key="jwt",
        title="Проверка подписи и фиксированный алгоритм",
        before=("jwt.decode(token)  # без verify",),
        after={
            "javascript": (
                "const claims = jwt.verify(token, PUBLIC_KEY, {",
                '  algorithms: ["RS256"],',
                "  issuer: 'archive',",
                "});",
            ),
            "python": (
                "claims = jwt.decode(",
                "    token, PUBLIC_KEY, algorithms=['RS256'],",
                "    options={'require': ['exp', 'iss']},",
                ")",
            ),
            "java": (
                "Jws<Claims> jws = Jwts.parserBuilder()",
                "    .setSigningKey(publicKey)",
                "    .requireIssuer(\"archive\")",
                "    .build()",
                "    .parseClaimsJws(token);",
            ),
        },
        steps=(
            "перейди с decode на verify",
            "зафиксируй алгоритм белым списком (RS256/ES256), убери none",
            "проверь exp, iss, aud",
            "перезапусти и прогони пробу: подделанный токен должен получать 401",
            "легальный токен проверь отдельно — чекер может ходить с ним",
        ),
        breaks="если сервис выдаёт HS256, а ключ публичный — это другая дыра; смени пару ключей",
    )


def _ssrf() -> Fix:
    return Fix(
        key="ssrf",
        title="Белый список адресов и запрет служебных сетей",
        before=("requests.get(request.args['url'])",),
        after={
            "python": (
                "import ipaddress, urllib.parse",
                "host = urllib.parse.urlparse(target).hostname or ''",
                "ip = ipaddress.ip_address(socket.gethostbyname(host))",
                "if ip.is_private or ip.is_loopback or ip.is_link_local:",
                '    raise PermissionError("internal address")',
                "if host not in ALLOWED_HOSTS:",
                '    raise PermissionError("host not allowed")',
            ),
            "javascript": (
                "const parsed = new URL(target);",
                "if (!ALLOWED.has(parsed.hostname)) return send(res, 403, 'host not allowed');",
                "const ip = await dns.promises.lookup(parsed.hostname);",
                "if (isPrivate(ip.address)) return send(res, 403, 'internal address');",
            ),
            "php": (
                "$host = parse_url($_GET['url'], PHP_URL_HOST);",
                "$ip = gethostbyname($host);",
                "if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {",
                '    http_response_code(403); exit("internal address");',
                "}",
            ),
            "go": (
                'host := parsed.Hostname()',
                'if !allowedHosts[host] {',
                '    http.Error(w, "host not allowed", http.StatusForbidden)',
                '    return',
                '}',
                'if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {',
                '    http.Error(w, "internal address", http.StatusForbidden)',
                '    return',
                '}',
            ),
        },
        steps=(
            "ограничь хост белым списком",
            "запрети private/loopback/link-local и 169.254.169.254",
            "разрешай только http/https, без file/dict/gopher",
            "проверь пробу: ответ на loopback должен стать отказом",
        ),
        breaks="если сервис легально ходит на внутренние адреса (балансировщик, кэш) — добавь их в список явно",
    )


def _upload() -> Fix:
    return Fix(
        key="upload",
        title="Имя генерируется сервером, тип проверяется",
        before=("uploaded.save(os.path.join(UPLOAD_DIR, uploaded.filename))",),
        after={
            "python": (
                "name = f\"{uuid.uuid4().hex}.{ext}\"",
                "target = os.path.join(UPLOAD_DIR, name)",
                "if ext not in {'png', 'jpg', 'pdf'}:",
                '    raise ValueError("extension not allowed")',
                "uploaded.save(target)",
            ),
            "javascript": (
                "const ext = path.extname(file.originalname).toLowerCase();",
                "if (!['.png', '.jpg', '.pdf'].includes(ext)) return res.status(400).end();",
                "const name = crypto.randomUUID() + ext;",
                "fs.writeFileSync(path.join(UPLOAD_DIR, name), buffer);",
            ),
            "php": (
                "$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));",
                "if (!in_array($ext, ['png', 'jpg', 'pdf'], true)) { http_response_code(400); exit; }",
                "$name = bin2hex(random_bytes(16)) . '.' . $ext;",
                "move_uploaded_file($_FILES['f']['tmp_name'], UPLOAD_DIR . '/' . $name);",
            ),
        },
        steps=(
            "имя файла генерируй сам, оригинальное храни в метаданных",
            "проверяй расширение и MIME, храни вне webroot",
            "запрети исполнение из каталога загрузок (nginx: location ^~ /uploads { deny all; })",
            "проверь, что чекер не загружает файлы через эту ручку",
        ),
        breaks="если на файлы ссылаются по оригинальному имени — обнови ссылки на новое имя или храни маппинг",
    )


def _redirect() -> Fix:
    return Fix(
        key="redirect",
        title="Только относительный путь",
        before=("res.redirect(req.query.next)",),
        after={
            "javascript": (
                "const next = String(req.query.next || '/');",
                "if (!next.startsWith('/') || next.startsWith('//')) return res.redirect('/');",
                "res.redirect(next);",
            ),
            "python": (
                "next_url = request.args.get('next', '/')",
                "if not next_url.startswith('/') or next_url.startswith('//'):",
                "    next_url = '/'",
                "return redirect(next_url)",
            ),
            "php": (
                "$next = $_GET['next'] ?? '/';",
                "if (!str_starts_with($next, '/') || str_starts_with($next, '//')) { $next = '/'; }",
                "header('Location: ' . $next);",
            ),
        },
        steps=(
            "принимай только путь, начинающийся с одного /",
            "отбрасывай //, /\\, схему и host",
            "при необходимости — белый список известных адресов",
            "проверь, что после логина редирект ведёт туда же, куда и раньше",
        ),
        breaks="если на этот параметр завязан SSO-возврат с абсолютным URL — добавь его в белый список",
    )


def _secret() -> Fix:
    return Fix(
        key="secret",
        title="Секрет из окружения и ротация",
        before=('SECRET_KEY = "notes-dev-secret-2026"',),
        after={
            "python": ("SECRET_KEY = os.environ[\"SECRET_KEY\"]",),
            "javascript": ("const SECRET_KEY = process.env.SECRET_KEY;",),
            "php": ("$secret = getenv('SECRET_KEY') ?: throw new RuntimeException('no secret');",),
            "go": ('secret := os.Getenv("SECRET_KEY")',),
            "java": ('String secret = System.getenv("SECRET_KEY");',),
            "csharp": ('var secret = Environment.GetEnvironmentVariable("SECRET_KEY");',),
            "ruby": ('SECRET_KEY = ENV.fetch("SECRET_KEY")',),
        },
        steps=(
            "вынеси значение в env или в файл с правами 0600",
            "смени сам секрет: старый уже в исходниках и в отчёте",
            "перезапусти сервис с новым env",
            "проверь, что подписи/сессии, выданные до ротации, не нужны команде",
        ),
        breaks="ротация секрета рвёт живые сессии — делай её до старта раундов, не в середине",
        risk="medium",
    )


def _debug() -> Fix:
    return Fix(
        key="debug",
        title="Отладка только по флагу окружения",
        before=("DEBUG = True",),
        after={
            "python": ('DEBUG = os.environ.get("DEBUG") == "1"',),
            "javascript": ('const DEBUG = process.env.DEBUG === "1";',),
            "php": ("$debug = getenv('DEBUG') === '1';",),
        },
        steps=(
            "включи debug только через env",
            "на боевом запуске флаг не выставляй",
            "проверь, что трассировка больше не отдаётся в ответе",
        ),
        breaks="если чекер читает /debug-страницу — он перестанет; сверься с его исходником",
    )


def _eval() -> Fix:
    return Fix(
        key="eval",
        title="Убрать исполнение строки",
        before=("eval($_GET['code'])",),
        after={
            "php": (
                "// вместо eval — разбор выражения",
                "$n = filter_var($_GET['n'] ?? 0, FILTER_VALIDATE_INT);",
                "echo json_encode(['result' => $n * 2]);",
            ),
            "python": ("result = ast.literal_eval(node)  # только литералы, без вызовов",),
            "javascript": ("const value = Number(req.query.n); // без eval",),
        },
        steps=(
            "замени eval на разбор известных операций",
            "если нужен язык выражений — используй библиотеку с песочницей",
            "перезапусти, прогони пробу: код в параметре не должен исполняться",
        ),
        breaks="если eval — часть легальной фичи (калькулятор), перепиши её на явный парсер; тесты калькулятора покроют",
        risk="medium",
    )


def _idor() -> Fix:
    return Fix(
        key="idor",
        title="Проверка владельца объекта",
        before=("SELECT id, title, body FROM notes WHERE id = ?",),
        after={
            "python": (
                "\"SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?\"",
                "(note_id, request.user_id),",
            ),
            "javascript": (
                "db.query(\"SELECT id, title FROM files WHERE id = ? AND owner_id = ?\",",
                "         [id, req.user.id]);",
            ),
            "php": (
                "$stmt = $db->prepare('SELECT * FROM items WHERE id = :id AND owner_id = :owner');",
                "$stmt->bindValue(':owner', $_SESSION['uid'], SQLITE3_INTEGER);",
            ),
            "go": (
                'row := db.QueryRowContext(ctx,',
                '    "SELECT id, title, body FROM notes WHERE id = $1 AND owner_id = $2", id, userID)',
            ),
            "java": (
                'PreparedStatement ps = conn.prepareStatement(',
                '    "SELECT * FROM notes WHERE id = ? AND owner_id = ?");',
                'ps.setLong(1, noteId);',
                'ps.setLong(2, session.getUserId());',
            ),
            "csharp": (
                "var note = await db.Notes.FirstOrDefaultAsync(",
                "    n => n.Id == id && n.OwnerId == userId);",
            ),
        },
        steps=(
            "добавь в запрос условие по владельцу или арендатору",
            "проверяй права на уровне ручки, не только в UI",
            "убедись, что чекер ходит от того же пользователя, что кладёт объект",
        ),
        breaks="если чекер забирает объект другим пользователем — он получит 403; сверься с его логикой до правки",
        risk="medium",
    )


def _xss() -> Fix:
    return Fix(
        key="xss",
        title="Экранирование на выходе",
        before=("res.send('<h1>' + req.query.q + '</h1>')",),
        after={
            "javascript": (
                "const escapeHtml = (s) => String(s).replace(/[&<>\"']/g, (c) => ({",
                "  '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;'",
                "}[c]));",
                "res.send('<h1>' + escapeHtml(req.query.q) + '</h1>');",
            ),
            "python": (
                "from markupsafe import escape",
                "return f\"<h1>{escape(q)}</h1>\"",
            ),
            "php": ("echo '<h1>' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . '</h1>';",),
            "go": ('fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(q))',),
        },
        steps=(
            "экранируй на выходе, в контексте HTML",
            "не собирай HTML конкатенацией — используй шаблон с автоэкранированием",
            "проверь, что легальные значения отображаются так же",
        ),
        breaks="если сервис легально отдаёт HTML из пользовательского ввода (редактор) — нужен санитайзер, не escape",
    )


def _xxe() -> Fix:
    return Fix(
        key="xxe",
        title="Отключить внешние сущности",
        before=("etree.parse(source)",),
        after={
            "python": (
                "parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)",
                "tree = etree.parse(source, parser)",
            ),
            "java": (
                "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();",
                "f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
                "f.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);",
                "f.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
            ),
            "php": (
                "$prev = libxml_disable_entity_loader(true);",
                "$xml = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NONET);",
            ),
        },
        steps=(
            "запрети DOCTYPE и внешние сущности",
            "ограничь размер и глубину XML",
            "проверь легальный XML чекера — он должен разбираться",
        ),
        breaks="если сервис принимает XML с DTD по контракту — согласуй замену, обычно DTD не нужен",
    )


def _memory() -> Fix:
    return Fix(
        key="memory",
        title="Границы буфера и snprintf",
        before=("strcpy(dst, src);",),
        after={
            "c": (
                "if (snprintf(dst, sizeof(dst), \"%s\", src) >= (int)sizeof(dst)) {",
                "    return -EINVAL;",
                "}",
                "memcpy(dst, src, strnlen(src, sizeof(dst) - 1));",
                "dst[sizeof(dst) - 1] = '\\0';",
            ),
            "cpp": (
                "if (src.size() + 1 > dst.size()) return false;",
                "std::memcpy(dst.data(), src.data(), src.size());",
                "dst[src.size()] = '\\0';",
            ),
        },
        steps=(
            "замени неограниченные функции на snprintf/strlcpy/span",
            "проверь все длины, приходящие из сети, до копирования",
            "прогони с ASan: -fsanitize=address,undefined",
            "проверь, что легальный ввод чекера не обрезается",
        ),
        breaks="если формат строки длиннее буфера легально — увеличь буфер, а не молча обрезай",
        risk="medium",
    )


def _checker_ref() -> Fix:
    return Fix(
        key="checker",
        title="Убрать упоминание чекера из кода сервиса",
        before=("// checker pulls /_checker/round",),
        after={
            "any": (
                "# интеграция с чекером: см. ops-документ, не код сервиса",
                "# адрес и токен чекера — только в конфиге чекера",
            )
        },
        steps=(
            "убери путь и токен чекера из исходников и комментариев",
            "перенеси в отдельный ops-конфиг вне webroot",
            "проверь, что сервис не ходит в /_checker",
        ),
        breaks="ничего: сервис не должен знать про чекер",
    )


def _flag() -> Fix:
    return Fix(
        key="flag",
        title="Флаг не должен лежать в исходниках",
        before=('FLAG = "ctfcup{...}"',),
        after={
            "any": (
                "# флаг приходит от чекера в рантайме и живёт в БД/файле с правами 0600",
                "# в git и в образах его быть не должно",
            )
        },
        steps=(
            "убери флаг из репозитория и из образа",
            "ротируй флаг у организаторов, если он уже был в исходниках",
            "проверь историю git: git log -S 'ctfcup{'",
        ),
        breaks="ничего, если сервис читает флаг из рантайм-источника",
    )


def _mass_assign() -> Fix:
    return Fix(
        key="massassign",
        title="Белый список полей",
        before=("user.update(request.json)",),
        after={
            "python": (
                "allowed = {'display_name', 'locale'}",
                "payload = {k: v for k, v in request.json.items() if k in allowed}",
                "user.update(payload)",
            ),
            "javascript": (
                "const allowed = ['displayName', 'locale'];",
                "const payload = Object.fromEntries(",
                "  Object.entries(req.body).filter(([k]) => allowed.includes(k)));",
            ),
            "php": (
                "$allowed = ['display_name', 'locale'];",
                "$payload = array_intersect_key($_POST, array_flip($allowed));",
            ),
            "go": (
                'type ProfilePatch struct {',
                '    DisplayName string `json:"display_name"`',
                '    Locale      string `json:"locale"`',
                '}',
                'var patch ProfilePatch  // role и balance сюда не попадают по типу',
                'if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {',
                '    http.Error(w, "bad request", http.StatusBadRequest)',
                '    return',
                '}',
            ),
        },
        steps=(
            "перечисли разрешённые поля явно",
            "права и роли меняй отдельной ручкой с проверкой",
            "проверь, что легальное обновление профиля работает",
        ),
        breaks="если чекер обновляет поле, которого нет в списке, — он сломается; список сверь с его запросами",
        risk="medium",
    )


def _ssti() -> Fix:
    return Fix(
        key="ssti",
        title="Шаблон фиксирован, данные — только значения",
        before=("render_template_string(user_template, name=name)",),
        after={
            "python": (
                "# шаблон хранится файлом и не приходит от пользователя",
                "return render_template('hello.html', name=name)",
            ),
            "javascript": (
                "// вместо компиляции строки — фиксированный шаблон",
                "res.render('hello', { name });",
            ),
        },
        steps=(
            "убери компиляцию пользовательских шаблонов",
            "передавай данные как переменные, не как текст шаблона",
            "проверь, что {{7*7}} в параметре возвращается как текст",
        ),
        breaks="если шаблоны — легальная фича (письма, отчёты), нужна песочница и белый список тегов",
    )


def _debug_route() -> Fix:
    return Fix(
        key="debugroute",
        title="Служебный маршрут закрыт",
        before=('@app.route("/debug/vars")',),
        after={
            "python": (
                "@app.route('/debug/vars')",
                "@require_local_or_token",
                "def debug_vars(): ...",
            ),
            "javascript": ("app.get('/debug/vars', requireAdminToken, handler);",),
            "go": (
                'mux.Handle("/debug/vars", localOnly(requireAdminToken(debugVars)))',
            ),
        },
        steps=(
            "закрой маршрут токеном или локальным адресом",
            "убери его из публичной сети",
            "проверь, что он не отдаёт env и конфиг",
        ),
        breaks="если чекер дергает этот маршрут — он получит 401; сверься с чекером",
    )


def _nosql() -> Fix:
    return Fix(
        key="nosql",
        title="Скалярный вход и фильтр, собранный на сервере",
        before=("db.drones.aggregate([{'$match': json.loads(request.args['what'])}])",),
        after={
            "python": (
                "what = request.args.get('what', '')",
                "if not what or len(what) > 64:",
                "    return jsonify(error='bad filter'), 400",
                "# поле фиксировано, значение — строка, операторы недоступны",
                'rows = list(db.drones.find({"label": {"$eq": what}}))',
            ),
            "javascript": (
                "const label = String(req.query.what || '');",
                "if (!label || label.length > 64) return send(res, 400, 'bad filter');",
                "const rows = await db.collection('drones').find({ label: { $eq: label } }).toArray();",
            ),
            "go": (
                'label := r.URL.Query().Get("what")',
                "if label == \"\" || len(label) > 64 {",
                '    http.Error(w, "bad filter", 400)',
                "    return",
                "}",
                'rows, err := coll.Find(ctx, bson.M{"label": label})',
            ),
        },
        steps=(
            "замени приём объекта от клиента на приём одной строки",
            "собери фильтр на сервере: имя поля — константа, значение — скаляр",
            "отвергай ключи, начинающиеся с `$`, если объект всё же приходит",
            "прогони прежнюю пробу: `$regex` не должен менять набор записей",
        ),
        breaks="если чекер присылает сложный фильтр, он получит 400; сверься с чекером",
    )


def _dispatch() -> Fix:
    return Fix(
        key="dispatch",
        title="Таблица команд вместо поиска по globals",
        before=("func = globals().get(command_name); func(drone)",),
        after={
            "python": (
                "COMMANDS = {",
                '    "BOOSTX": lambda drone, arg: drone.boost("x", int(arg)),',
                '    "BOOSTY": lambda drone, arg: drone.boost("y", int(arg)),',
                '    "FIRE": lambda drone, arg: drone.fire(),',
                "}",
                "handler = COMMANDS.get(command_name)",
                "if handler is None:",
                '    raise ValueError(f"unknown command {command_name!r}")',
                "handler(drone, arg)",
            ),
        },
        steps=(
            "выпиши список команд, которые сервис действительно исполняет",
            "замени globals()/getattr на словарь из этого списка",
            "неизвестное имя — ошибка, а не пропуск",
            "проверь, что каждая команда из плана полёта по-прежнему работает",
        ),
        breaks="новая команда без записи в таблицу перестанет исполняться — это и есть цель",
    )


def _prefix() -> Fix:
    return Fix(
        key="prefix",
        title="Полная длина и сравнение за постоянное время",
        before=("if (strncmp(token, secret, strlen(token)) == 0) { auth_ok(); }",),
        after={
            "c": (
                "if (strlen(token) != strlen(secret)) {",
                "    return 0;",
                "}",
                "unsigned char diff = 0;",
                "for (size_t i = 0; i < strlen(secret); i++) {",
                "    diff |= (unsigned char)(token[i] ^ secret[i]);",
                "}",
                "return diff == 0;",
            ),
            "cpp": (
                "if (token.size() != secret.size()) return false;",
                "unsigned char diff = 0;",
                "for (std::size_t i = 0; i < secret.size(); ++i) {",
                "    diff |= static_cast<unsigned char>(token[i] ^ secret[i]);",
                "}",
                "return diff == 0;",
            ),
        },
        steps=(
            "сначала сравни длину: разная — сразу отказ",
            "затем пройди всю строку целиком, без выхода на первом несовпадении",
            "не логируй длину совпавшего префикса",
            "проверь пустой токен: он должен отвергаться",
        ),
        breaks="пустой токен перестанет приниматься — это и есть дыра",
    )


def _bounds() -> Fix:
    return Fix(
        key="bounds",
        title="Проверка индекса до обращения",
        before=("item = items[atoi(param)];",),
        after={
            "c": (
                "long index = strtol(param, NULL, 10);",
                "if (index < 0 || (size_t)index >= items_len) {",
                '    send_error(conn, 400, "bad index");',
                "    return;",
                "}",
                "item = items[index];",
            ),
            "cpp": (
                "const int index = std::stoi(param);",
                "if (index < 0 || static_cast<std::size_t>(index) >= items.size()) {",
                '    return send_error(conn, 400, "bad index");',
                "}",
                "const auto& item = items[index];",
            ),
        },
        steps=(
            "разбери индекс в знаковое число и проверь границы до доступа",
            "отрицательное значение — отказ, а не обратный индекс",
            "используй знаковый тип: беззнаковый спрячет отрицательное в огромное",
            "проверь пустой список: индекс 0 тоже должен отвергаться",
        ),
        breaks="обратный доступ по -1, если он использовался для «последнего элемента», сломается",
    )


def _approve() -> Fix:
    return Fix(
        key="approve",
        title="Подтверждение связи отдельным действием",
        before=('status = models.BooleanField(default=True)',),
        after={
            "python": (
                "class Friendship(models.Model):",
                "    requester = models.ForeignKey(User, related_name='sent', on_delete=models.CASCADE)",
                "    target = models.ForeignKey(User, related_name='received', on_delete=models.CASCADE)",
                "    status = models.BooleanField(default=False)",
                "    created_at = models.DateTimeField(auto_now_add=True)",
                "",
                "# принятие — отдельный маршрут, вызывает только вторая сторона",
                "def accept(request, friendship_id):",
                "    link = get_object_or_404(Friendship, pk=friendship_id, target=request.user)",
                "    link.status = True",
                "    link.save(update_fields=['status'])",
            ),
        },
        steps=(
            "поставь default=False в модели",
            "создание связи оставь без подтверждения, принятие — отдельным маршрутом",
            "принятие разрешай только второй стороне: фильтр по target=request.user",
            "проверь, что приватный объект без принятой связи отдаёт 404",
        ),
        breaks="уже существующие связи в базе останутся True; проверь, что это те, что были приняты",
    )


FIXES: dict[str, Fix] = {
    fix.key: fix
    for fix in (
        _sql(), _path(), _cmd(), _deser(), _jwt(), _ssrf(), _upload(), _redirect(),
        _secret(), _debug(), _eval(), _idor(), _xss(), _xxe(), _memory(),
        _checker_ref(), _flag(), _mass_assign(), _ssti(), _debug_route(),
        _nosql(), _dispatch(), _prefix(), _bounds(), _approve(),
    )
}

RULE_TO_FIX: dict[str, str] = {
    "sql-fstring": "sql", "sql-format": "sql", "sql-exec-var": "sql",
    "go-sql-sprintf": "sql", "rust-sql-format": "sql", "php-sql-request": "sql",
    "php-sql-concat": "sql", "js-sql-template": "sql", "java-sql-concat": "sql",
    "cs-sql-concat": "sql", "rb-sql-interp": "sql",
    "path-join": "path", "path-sink": "path", "go-path-sink": "path",
    "rust-path": "path", "js-path": "path", "php-include": "path",
    "java-path": "path",
    "cmd-shell": "cmd", "go-exec-user": "cmd", "rust-command-format": "cmd",
    "rust-command-user": "cmd", "php-shell": "cmd", "js-exec-request": "cmd",
    "cs-process": "cmd", "c-shell": "cmd", "rb-shell": "cmd", "lua-exec": "cmd",
    "deserialization": "deser", "php-unserialize": "deser",
    "jwt-none": "jwt", "js-jwt-noverify": "jwt",
    "ssrf": "ssrf",
    "upload": "upload", "php-upload": "upload",
    "open-redirect": "redirect",
    "hardcoded-secret": "secret",
    "debug-on": "debug",
    "php-eval": "eval", "js-eval": "eval", "rb-eval": "eval", "lua-loadstring": "eval",
    "idor-id-only": "idor",
    "js-xss": "xss", "go-template-html": "xss", "autoescape-off": "xss",
    "xxe": "xxe",
    "c-unsafe-copy": "memory", "c-memcpy-length": "memory",
    "checker-ref": "checker",
    "flag-literal": "flag",
    "mass-assign": "massassign",
    "ssti": "ssti",
    "debug-path": "debugroute",
    "mongo-nosql-request": "nosql",
    "py-dynamic-dispatch": "dispatch",
    "c-prefix-compare": "prefix",
    "c-index-from-input": "bounds",
    "cpp-unsigned-index": "bounds",
    "py-sql-concat": "sql",
    "py-owner-from-request": "idor",
    "dj-auto-approved": "approve",
    "nginx-cookie-upstream": "ssrf",
    "py-eval": "eval",
    "py-jwt-noverify": "jwt",
}

LANGUAGE_LABELS = {
    "python": "Python", "javascript": "Node.js", "typescript": "TypeScript",
    "php": "PHP", "go": "Go", "java": "Java", "kotlin": "Kotlin",
    "csharp": "C#", "ruby": "Ruby", "rust": "Rust", "c": "C", "cpp": "C++",
    "lua": "Lua", "any": "универсально",
}


def build_fix(rule_id: str, language: str, snippet: str = "") -> dict:
    """Готовит объяснение правки под конкретную находку."""
    key = RULE_TO_FIX.get(rule_id)
    if key is None:
        return {
            "available": False,
            "title": "Общий порядок правки",
            "steps": [
                "найди sink в строке находки и убери попадание пользовательских данных",
                "проверь класс: SQL, путь, команда, десериализация — правило подсказывает",
                "перезапусти сервис и прогони ту же пробу: сигнала быть не должно",
                "дождись раунда чекера: сервис должен отдать флаг",
            ],
            "risk": "low",
        }

    fix = FIXES[key]
    samples = fix.after
    if language in samples:
        sample_language = language
    elif "any" in samples:
        sample_language = "any"
    else:
        sample_language = next(iter(samples))
    code = samples[sample_language]
    language_label = LANGUAGE_LABELS.get(language, language)

    return {
        "available": True,
        "key": fix.key,
        "title": fix.title,
        "language": language,
        "language_label": language_label,
        # Язык, на котором рецепт действительно написан. Если он не совпадает
        # с языком находки, diff не собирается: питон в .go-файле — не патч.
        "sample_language": sample_language,
        "sample_label": LANGUAGE_LABELS.get(sample_language, sample_language),
        "exact": sample_language in {language, "any"},
        "before": fix.before,
        "after": code,
        "snippet": snippet.strip()[:400],
        "steps": list(fix.steps),
        "breaks": fix.breaks,
        "risk": fix.risk,
    }
