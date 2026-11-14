<#
.SYNOPSIS
    AD Audit — launcher for Windows 11.

.DESCRIPTION
    Starts the local web UI on 127.0.0.1. Read-only audit only.

.EXAMPLE
    .\run.ps1
    .\run.ps1 -Demo
    .\run.ps1 -Port 9000
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [int]$Port = 8765,
    [string]$Bind = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = $null
foreach ($candidate in @("python", "py", "python3")) {
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($command) { $python = $command.Source; break }
}
if (-not $python) {
    throw "python not found in PATH; install Python 3.10+ and retry"
}

& $python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.10 or newer is required"
}

$arguments = @("app.py", "--host", $Bind, "--port", $Port)
if ($Demo) { $arguments += "--demo" }

Write-Host "AD Audit  ->  http://${Bind}:${Port}" -ForegroundColor Cyan
if ($Demo) { Write-Host "demo mode: fixture audit, no SSH" -ForegroundColor Yellow }

& $python @arguments
