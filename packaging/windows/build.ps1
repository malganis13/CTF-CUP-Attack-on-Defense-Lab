# build.ps1 — собирает AD-Audit.exe без окна консоли.
#
#   .\packaging\windows\build.ps1                 # в dist рядом с проектом
#   .\packaging\windows\build.ps1 -OutDir D:\dist # на другой диск
#
# Требуется: Python 3.10+, pyinstaller (pip install pyinstaller).

param(
    [string]$OutDir = "",
    [string]$WorkDir = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path

if (-not $OutDir) { $OutDir = Join-Path $root "dist" }
if (-not $WorkDir) { $WorkDir = Join-Path $env:TEMP "ad-audit-build" }

Write-Host "== python: $((python --version) 2>&1)"
python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "== ставлю pyinstaller"
    python -m pip install --quiet pyinstaller
}

Write-Host "== сборка -> $OutDir\AD-Audit.exe"
# PyInstaller пишет прогресс в stderr; при ErrorActionPreference=Stop это
# выглядит как ошибка. На время вызова глушим строгий режим и смотрим код.
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
python -m PyInstaller `
    --noconfirm --clean --onefile --noconsole `
    --name AD-Audit `
    --add-data "$root\web;web" `
    --add-data "$root\knowledge;knowledge" `
    --add-data "$root\demo;demo" `
    --distpath "$OutDir" `
    --workpath "$WorkDir" `
    --specpath "$WorkDir" `
    (Join-Path $root "launcher.py")
$code = $LASTEXITCODE
$ErrorActionPreference = $previous
if ($code -ne 0) { throw "pyinstaller завершился с кодом $code" }

$exe = Join-Path $OutDir "AD-Audit.exe"
if (-not (Test-Path $exe)) { throw "exe не собрался" }
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "== готово: $exe ($size МБ)"
Write-Host "   двойной клик — приложение поднимется и откроет браузер."
Write-Host "   config.json появится рядом с exe; на диск больше ничего не пишется."
