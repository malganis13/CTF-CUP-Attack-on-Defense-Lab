<#
.SYNOPSIS
    Аудит A/D — лаунчер для Windows 11.

.DESCRIPTION
    Поднимает локальный веб-интерфейс на 127.0.0.1. Аудит только на чтение.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Demo
    .\run.ps1 -Port 9000

.NOTES
    Если PowerShell блокирует запуск скрипта:
    powershell -ExecutionPolicy Bypass -File .\run.ps1
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [int]$Port = 8765,
    [string]$Bind = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Кириллица в консоли Windows ломается без этого.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$env:PYTHONIOENCODING = "utf-8"

$candidates = @()
foreach ($name in @("python", "py", "python3")) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
}
if (-not $candidates) {
    throw "python не найден в PATH; поставьте Python 3.10+ (winget install Python.Python.3.12)"
}

$python = $null
foreach ($candidate in $candidates) {
    $output = $null
    try {
        $output = & $candidate -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch {
        continue
    }
    if ($LASTEXITCODE -ne 0 -or -not $output) { continue }
    $parts = $output.Trim().Split(".")
    if ([int]$parts[0] -ge 3 -and [int]$parts[1] -ge 10) {
        $python = $candidate
        break
    }
}
if (-not $python) {
    throw "нужен Python 3.10 или новее; найденное не подошло: $($candidates -join ', ')"
}

$arguments = @("app.py", "--host", $Bind, "--port", $Port)
if ($Demo) { $arguments += "--demo" }

Write-Host "Аудит A/D  ->  http://${Bind}:${Port}" -ForegroundColor Cyan
Write-Host "python: $python"
if ($Demo) { Write-Host "демо-режим: фикстуры, без SSH" -ForegroundColor Yellow }

& $python @arguments
