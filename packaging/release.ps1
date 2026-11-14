# Создаёт GitHub Release и прикрепляет AD-Audit.exe.
# Токен берётся из git credential manager и не печатается.
#   .\packaging\release.ps1            # тег и заметки из аргументов ниже
$ErrorActionPreference = "Stop"

$repo = "malganis13/CTF-CUP-Attack-on-Defense-Lab"
$tag = "v1.3.0"
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

Что внутри
- read-only аудит вулнбокса по SSH: сервисы, исходники, находки с файлом и строкой;
- живость сервисов: лампа «не лежит / лежит / ошибки», время ответа, один GET на сервис;
- пробы-детекторы (GET, маркер в ответе), заготовки для ручных классов;
- вкладка «Как закрыть»: код до/после на языке сервиса и риск для раунда;
- журнал трафика с потолками — доказательство, что это не флуд;
- тренировочный полигон sim/: python/node/php сервисы и чекер по раундам;
- приложение без консоли: AD-Audit.exe для Windows, packaging/linux/install.sh для Arch/Nyarch.

Проверено на полигоне
- аудит трёх сервисов: 1.1 с, 18 находок;
- подтверждено пробами: SQLi x2, path traversal, command injection x2, LFI PHP;
- живость: 0.7 с на три сервиса, остановка сервиса -> «лежит», возврат -> «не лежит»;
- после лечения одной дыры: 18 -> 17 находок, чекер зелёный, ручка отвечает 200;
- тесты: smoke.py 80/80, test_probe.py 38/38, compileall и node --check чистые.

Запуск
- Windows: скачать AD-Audit.exe из ассетов, двойной клик — откроется браузер;
- Linux: git clone -b ad-audit-1.1, затем packaging/linux/install.sh.
"@

$body = @{
    tag_name         = $tag
    target_commitish = "ad-audit-1.1"
    name             = "AD Audit 1.1 — репетиция финала"
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
