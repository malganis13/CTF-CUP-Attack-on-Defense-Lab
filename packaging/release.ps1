# Создаёт GitHub Release и прикрепляет AD-Audit.exe.
# Токен берётся из git credential manager и не печатается.
#   .\packaging\release.ps1            # тег и заметки из аргументов ниже
$ErrorActionPreference = "Stop"

$repo = "malganis13/CTF-CUP-Attack-on-Defense-Lab"
$tag = "v1.9.0"
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

Новое в 1.9
- уверенность у каждой находки: «уверен / скорее да / не уверен», причина оценки
  и план ручной проверки — что отправить, что увидеть, что закроет находку;
- журнал находок в SQLite (state/journal.db): что было до патча, что после,
  что закрыли, что вернулось; отпечаток «правило + файл + текст строки», поэтому
  сдвиг строк патчем находку не теряет;
- карта уязвимостей: класс -> файл -> строка, цвет по важности, статус, фильтры
  «только открытые» и «только уверен», клик открывает находку с правкой;
- поиск в шапке: одним запросом по находкам, правилам и базе знаний;
- сортировка на вкладках: заголовки таблиц и селект у находок (приоритет,
  важность вверх/вниз, уверенность, файл, строка);
- сводка уверенности над списком находок и доля «не уверен» в процентах.

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
- тесты: smoke 115/115, probe 42/42, authdiff 18/18, deps+cve 21/21,
  offline+patch 12/12, confidence 9/9, journal 18/18, ui 12/12;
- compileall и node --check чистые.

Запуск
- Windows: скачать AD-Audit.exe из ассетов, двойной клик — откроется браузер;
- Linux: git clone -b ad-audit-1.1, затем packaging/linux/install.sh.
"@

$body = @{
    tag_name         = $tag
    target_commitish = "ad-audit-1.1"
    name             = "AD Audit 1.9 — уверенность, карта, журнал"
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
