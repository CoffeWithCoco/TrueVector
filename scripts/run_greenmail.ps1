<#
.SYNOPSIS
  Starts or stops GreenMail (a test SMTP+IMAP server) using Java.
  No Docker required. Downloads the jar on first run.

.EXAMPLE
  pwsh scripts\run_greenmail.ps1 start   # starts in the background
  pwsh scripts\run_greenmail.ps1 stop    # stops it

  Ports: SMTP 3025 · IMAP-SSL 3993 · auth disabled (any credentials work).
#>
param([ValidateSet('start', 'stop')][string]$Action = 'start')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root '.tools'
$jar = Join-Path $tools 'greenmail-standalone.jar'
$pidFile = Join-Path $tools 'greenmail.pid'

if ($Action -eq 'stop') {
    $port = Get-NetTCPConnection -State Listen -LocalPort 3025 -ErrorAction SilentlyContinue
    if ($port) { Stop-Process -Id $port.OwningProcess -Force; Write-Host "GreenMail stopped." }
    else { Write-Host "GreenMail was not running." }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    return
}

# start
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    throw "Java not found in PATH. Install a JRE 17+ (e.g. Temurin)."
}
New-Item -ItemType Directory -Force -Path $tools | Out-Null

if (-not (Test-Path $jar)) {
    Write-Host "Downloading GreenMail standalone..."
    $meta = Invoke-RestMethod 'https://repo1.maven.org/maven2/com/icegreen/greenmail-standalone/maven-metadata.xml'
    $v = $meta.metadata.versioning.release
    Invoke-WebRequest "https://repo1.maven.org/maven2/com/icegreen/greenmail-standalone/$v/greenmail-standalone-$v.jar" -OutFile $jar
    Write-Host "GreenMail $v downloaded."
}

if (Get-NetTCPConnection -State Listen -LocalPort 3025 -ErrorAction SilentlyContinue) {
    Write-Host "GreenMail is already listening on 3025."; return
}

# The jar path may contain spaces -> quote it inside the argument
$p = Start-Process java `
    -ArgumentList '-Dgreenmail.setup.test.all', '-Dgreenmail.auth.disabled', '-jar', "`"$jar`"" `
    -RedirectStandardOutput (Join-Path $tools 'greenmail.log') `
    -RedirectStandardError  (Join-Path $tools 'greenmail.err') `
    -PassThru -WindowStyle Hidden
$p.Id | Out-File $pidFile
Start-Sleep -Seconds 3
Write-Host "GreenMail started (PID $($p.Id))."
Write-Host "  SMTP 127.0.0.1:3025  ·  IMAP-SSL 127.0.0.1:3993  ·  auth disabled"
Write-Host "Now you can run:  python scripts\greenmail_test.py"
