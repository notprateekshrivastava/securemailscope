
# Stops the API if it is running, starts it again with the current code, waits
# until it answers, then runs the sample test.
#
# Run this EVERY time you change a Python file. If the API is already running and
# you do not restart it, Python keeps the old code in memory and every new upload
# keeps producing the old result.
#
# Usage:
#   .\scripts\restart_and_test.ps1
#   .\scripts\restart_and_test.ps1 -Port 8000 -UploadedBy ntro
#   .\scripts\restart_and_test.ps1 -SkipTests          (only restart the API)
#   .\scripts\restart_and_test.ps1 -StartupTimeout 300 (slow machine / cold start)

param(
    [int]$Port = 8000,
    [string]$BindHost = "0.0.0.0",
    [string]$UploadedBy = "team",
    [int]$StartupTimeout = 180,
    [switch]$SkipTests
)
# Error handling is set after param(): PowerShell requires param() to be the
# first statement in the file, otherwise it is parsed as a command named "param".
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Api = "http://localhost:$Port"
$LogDirectory = Join-Path $Root "data"
New-Item -ItemType Directory -Force $LogDirectory | Out-Null
$OutLog = Join-Path $LogDirectory "api.out.log"
$ErrLog = Join-Path $LogDirectory "api.err.log"

Write-Host "Project        : $Root"
Write-Host "API port       : $Port"
Write-Host ""

# --- 1. Stop whatever is listening on the API port ---------------------------
$ListenerPids = @()
try {
    $Listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop
    $ListenerPids = @($Listeners.OwningProcess | Sort-Object -Unique)
} catch {
    # Get-NetTCPConnection is missing on some Windows builds, so fall back to
    # netstat. Nothing here may abort the script: if neither tool answers, the
    # worst case is that an old API keeps running, which is what the port check
    # before starting is there to report.
    if (Get-Command netstat -ErrorAction SilentlyContinue) {
        try {
            $NetstatLines = netstat -ano | Select-String -Pattern (":{0}\s" -f $Port) | Select-String -Pattern "LISTENING"
            foreach ($Match in $NetstatLines) {
                $Parts = @(($Match.Line -split "\s+") | Where-Object { $_ -ne "" })
                if ($Parts.Count -ge 5) { $ListenerPids += [int]$Parts[$Parts.Count - 1] }
            }
            $ListenerPids = @($ListenerPids | Sort-Object -Unique)
        } catch {
            Write-Warning ("Could not inspect port {0} ({1}). Continuing." -f $Port, $_.Exception.Message)
        }
    } else {
        Write-Warning "Neither Get-NetTCPConnection nor netstat is available; skipping the port check."
    }
}

if ($ListenerPids.Count -gt 0) {
    foreach ($ProcessId in $ListenerPids) {
        try {
            $ProcessName = (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
        } catch {
            $ProcessName = "unknown"
        }
        Write-Host ("Stopping previous process on port {0} (PID {1}, {2})..." -f $Port, $ProcessId, $ProcessName)
        try {
            Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        } catch {
            Write-Warning ("Could not stop PID {0}: {1}" -f $ProcessId, $_.Exception.Message)
        }
    }
    Start-Sleep -Seconds 2
} else {
    Write-Host "Nothing was listening on port $Port."
}

# --- 2. Start the API with the current code ---------------------------------
$Python = (Get-Command python).Source
Write-Host "Starting API with $Python ..."

$ApiProcess = Start-Process -FilePath $Python `
    -ArgumentList @("-u", "-m", "uvicorn", "app.main:app", "--host", $BindHost, "--port", "$Port") `
    -WorkingDirectory $Root `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -PassThru

# --- 3. Wait until it answers ------------------------------------------------
# The first start after extracting a new bundle, or after a reboot, has to import
# FastAPI, scikit-learn, reportlab and Jinja2 from disk. On a laptop with antivirus
# checking every file that can easily take more than a minute, so the wait is
# generous and prints progress instead of failing silently.
$Health = $null
$Started = Get-Date
$NextNotice = 10
while (((Get-Date) - $Started).TotalSeconds -lt $StartupTimeout) {
    if ($ApiProcess.HasExited) { break }
    try {
        $Health = Invoke-RestMethod -Uri "$Api/api/v1/health" -TimeoutSec 3
        break
    } catch {
        $Health = $null
    }
    $Elapsed = [int]((Get-Date) - $Started).TotalSeconds
    if ($Elapsed -ge $NextNotice) {
        Write-Host ("  still starting... {0}s (limit {1}s)" -f $Elapsed, $StartupTimeout)
        $NextNotice += 10
    }
    Start-Sleep -Milliseconds 500
}

if ($null -eq $Health) {
    $Waited = [int]((Get-Date) - $Started).TotalSeconds
    Write-Host ""
    if ($ApiProcess.HasExited) {
        Write-Host ("The API exited after {0}s (exit code {1})." -f $Waited, $ApiProcess.ExitCode) -ForegroundColor Red
        Write-Host "A real error was raised, and it is in the error log:" -ForegroundColor Red
    } else {
        Write-Host ("The API was still starting after {0}s and never answered." -f $Waited) -ForegroundColor Red
        Write-Host "Stopping it, so the next run starts from a clean state..."
        try { Stop-Process -Id $ApiProcess.Id -Force -ErrorAction Stop } catch { }
        Write-Host "The most common cause is a slow first start: Windows Defender scans every"
        Write-Host "library on first use. Run the script again, or use a longer wait:"
        Write-Host "    .\scripts\restart_and_test.ps1 -StartupTimeout 300"
    }
    foreach ($Log in @($OutLog, $ErrLog)) {
        if (Test-Path $Log) {
            Write-Host ""
            Write-Host ("Last lines of {0} :" -f $Log)
            $Lines = @(Get-Content $Log -Tail 20 -ErrorAction SilentlyContinue)
            if ($Lines.Count -eq 0) {
                Write-Host "  (the log is empty - Python had not written anything yet)"
            } else {
                $Lines | ForEach-Object { Write-Host "  $_" }
            }
        }
    }
    exit 1
}

Write-Host ""
Write-Host ("API is up (PID {0})" -f $ApiProcess.Id) -ForegroundColor Green
Write-Host ("  status           : {0}" -f $Health.status)
Write-Host ("  TShark available : {0}" -f $Health.tshark_available)
Write-Host ("  ML model         : {0}" -f $Health.ml_model_status)
if ($Health.ml_model_note) {
    Write-Host ("  ML note          : {0}" -f $Health.ml_model_note) -ForegroundColor Yellow
}
# Any version string other than these means a trained model is loaded. Checking for
# one exact name would warn about a false problem the moment the version is bumped.
if ($Health.ml_model_status -in @("not_loaded", "load_failed", "stale", "")) {
    Write-Host "  The trained model is not in use, so rule-based classification is applied." -ForegroundColor Yellow
    Write-Host "  Fix it with: python -m app.ml.train"
}
Write-Host ""
Write-Host "Swagger UI        : $Api/docs"
Write-Host "API log           : $OutLog"
Write-Host "To stop the API   : Stop-Process -Id $($ApiProcess.Id)"
Write-Host ""

if ($Health.tshark_available -eq $false) {
    Write-Host "TShark was not found, so no PCAP can be parsed." -ForegroundColor Red
    Write-Host "Install Wireshark, or set TSHARK_PATH to tshark.exe, then run this script again."
    exit 1
}

# --- 4. Run the sample test --------------------------------------------------
if ($SkipTests) {
    Write-Host "Skipping the sample test (-SkipTests)."
    exit 0
}

& (Join-Path $PSScriptRoot "test_all_samples.ps1") -Port $Port -UploadedBy $UploadedBy
exit $LASTEXITCODE
