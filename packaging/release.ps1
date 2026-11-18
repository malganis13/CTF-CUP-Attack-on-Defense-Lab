# Создаёт GitHub Release и прикрепляет AD-Audit.exe.
# Токен берётся из git credential manager и не печатается.
#   .\packaging\release.ps1            # тег и заметки из аргументов ниже
$ErrorActionPreference = "Stop"

$repo = "malganis13/CTF-CUP-Attack-on-Defense-Lab"
$tag = "v1.12.1"
$exe = "D:\ad-audit-dist\AD-Audit.exe"

$raw = "protocol=https`nhost=github.com`n`n" | git credential fill
$token = ($raw | Select-String -Pattern "^password=(.+)$").Matches[0].Groups[1].Value
if (-not $token) { throw "токен не найден в credential manager" }

$headers = @{
    Authorization = "token $token"
    "User-Agent"  = "ad-audit-release"
    Accept        = "application/vnd.github+json"
}

$notes = @"
Инструмент для финала X Кубка CTF России (Attack-Defense).

Новое в 1.12.1
- интерфейс перестал зависеть от старого Edge: убраны `??` и спред-объекты,
  на которых EdgeHTML падал при разборе app.js и оставлял мёртвые кнопки;
- обработчики вкладок и таблиц навешиваются до первого запроса к серверу:
  медленный или недоступный localhost больше не делает страницу некликабельной;
- если скрипт не загрузился, упал или открыт старый Edge/режим IE, сверху
  появляется баннер с причиной и подсказкой, а не пустой интерфейс;
- app.js проверяется как ES2017 (acorn) и на отсутствие ES2020-синтаксиса;
- мелочь: встроенная иконка, без 404 на favicon.

Новое в 1.12
- вход по паролю: поле видно всегда, пароль живёт только в памяти; в exe
  paramiko уже внутри, отдельная установка не нужна;
- «Проверить связь» печатает точный адрес и бэкенд (root@host:port), поэтому
  видно, к какой машине на самом деле было подключение;
- смена пароля на цели: chpasswd со stdin, без пароля в аргументах процесса и
  в config.json; после смены — проверка входа новым паролем отдельным
  соединением и показ политики PermitRootLogin;
- «Сервисы на цели» на вкладке «Стенд»: ss -lntp, юниты systemd, каталоги
  /srv, /opt, /home, docker ps — один SSH-заход, без сканирования снаружи;
  кнопка «в стенд» переносит найденные порты в модель;
- knowledge/vuln.md: как устроен вулнбокс (один хост, много сервисов), какие
  учётки менять, как не сломать чекер.

Новое в 1.11
- разбор потока значений: переменная из запроса, доехавшая до опасного вызова
  через присваивания, теперь находится (правила flow-taint-*): видно исходную
  строку и цепочку, а не только место вызова;
- разбор порядка веток: проверка подписи, которую обходит ранний возврат
  (flow-guard-bypass) — так ловится обход HMAC в starpost при limit <= 3;
- авторизация сравнением структуры (flow-auth-by-value) — cubic (2020);
- находки потока помечены фиолетовой плашкой «проверить» и никогда не получают
  «уверен»: это эвристика, её подтверждает проба; фильтр «проверить: N»,
  объяснение в детали, плашка в карте и на стенде;
- регрессия по корпусам теперь считает поток: GoCTF-2026 34 находки вместо 31,
  2020 — 5 вместо 4, 2024 — 8 вместо 7; на 2025 и leto26 поток не шумит.

Новое в 1.10.1
- «Правила сканера»: кнопка «сбросить» снимает текстовый фильтр, фильтр по
  важности и сортировку столбцов одним нажатием; стрелки возвращаются в «↕»,
  строки — в исходный порядок каталога.

Новое в 1.10
- стенд турнира: сервер в центре, вокруг карточки сервисов с портом, языком,
  полосой важности, лампой живости и риском 0-100; линии окрашены по худшей
  находке сервиса;
- клик по карточке показывает находки сервиса с уверенностью и строкой, клик по
  находке открывает её разбор и правку;
- модель стенда правится в интерфейсе и живёт в state/topology.json: событие,
  наша команда, число команд на поле, состав, длина раунда, сервер, сервисы;
- «заполнить из аудита» добавляет недостающие сервисы и заполняет пустые поля,
  ручные правки не перезаписывает; находки привязываются по каталогу сервиса;
- поле и команда: точки команд (наша подсвечена) и чипы состава;
- в 1.9: уверенность у находок, журнал находок, карта, поиск, сортировка.

Что внутри
- read-only аудит вулнбокса по SSH и без SSH (каталог, zip, tar): сервисы,
  исходники, находки с файлом и строкой;
- живость сервисов: лампа «не лежит / лежит / ошибки», время ответа, один GET;
- пробы-детекторы, пара «без сессии / с сессией», два аккаунта (BOLA), POST за флагом;
- вкладка «Как закрыть»: код до/после на языке сервиса, риск для раунда, unified diff;
- 94 правила по 11 языкам и стекам; CVE через OSV с кэшем и встроенной таблицей;
  ELF-разбор защит сборки;
- журнал трафика с потолками — доказательство, что это не флуд;
- тренировочный полигон sim/: python/node/php сервисы и чекер по раундам;
- приложение без консоли: AD-Audit.exe для Windows, packaging/linux/install.sh для Arch/Nyarch.

Проверено
- корпуса Кубка 2018–2026: 11 репозиториев, заложенные дыры находятся,
  регрессия закреплена tools/test_cup_years.py;
- тесты: smoke 131/131, probe 42/42, authdiff 18/18, deps+cve 21/21,
  offline+patch 12/12, confidence 9/9, journal 18/18, topology 34/34,
  flow 20/20, remote 20/20, ui 23/23;
- compileall и node --check чистые.

Запуск
- Windows: скачать AD-Audit.exe из ассетов, двойной клик — откроется браузер;
- Linux: git clone -b ad-audit-1.1, затем packaging/linux/install.sh.
"@

$body = @{
    tag_name         = $tag
    target_commitish = "ad-audit-1.1"
    name             = "AD Audit 1.12.1 — интерфейс в старом Edge и живой до сервера"
    body             = $notes
} | ConvertTo-Json -Depth 4

try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases" -Method Post `
        -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType "application/json; charset=utf-8"
} catch {
    Write-Host "release create failed: HTTP $($_.Exception.Response.StatusCode.value__)"
    Write-Host $_.ErrorDetails.Message
    exit 2
}

Write-Host "release: $($release.html_url)"

if (Test-Path $exe) {
    $upload = "https://uploads.github.com/repos/$repo/releases/$($release.id)/assets?name=AD-Audit.exe"
    try {
        $asset = Invoke-RestMethod -Uri $upload -Method Post -Headers $headers `
            -InFile $exe -ContentType "application/vnd.microsoft.portable-executable"
        Write-Host "asset: $($asset.browser_download_url) ($([math]::Round($asset.size/1MB,1)) MB)"
    } catch {
        Write-Host "asset upload failed: HTTP $($_.Exception.Response.StatusCode.value__)"
        Write-Host $_.ErrorDetails.Message
        exit 3
    }
} else {
    Write-Host "exe не найден: $exe"
}
