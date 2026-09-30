
# Uploads every capture in .\samples and .\samples\lab to the SecureMailScope API
# and prints a per-file summary: sessions, TLS/plaintext/STARTTLS counts, findings,
# posture, risk class, evidence completeness and whether the ML class agrees with
# the rule findings. The full JSON answer of each analysis is saved under
# .\data\sample-results\.
#
# Usage:
#   .\scripts\test_all_samples.ps1
#   .\scripts\test_all_samples.ps1 -Port 8000
#   .\scripts\test_all_samples.ps1 -OnlyPublic      (skip the lab captures)

param(
    [int]$Port = 8000,
    [string]$UploadedBy = "team",
    [switch]$OnlyPublic
)
# Error handling is set after param(): PowerShell requires param() to be the
# first statement in the file, otherwise it is parsed as a command named "param".
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Api = "http://localhost:$Port"
$Output = Join-Path $Root "data\sample-results"
New-Item -ItemType Directory -Force $Output | Out-Null

# --- 1. Is the API up, and is a trained model in use? ------------------------
try {
    $Health = Invoke-RestMethod -Uri "$Api/api/v1/health" -TimeoutSec 5
} catch {
    Write-Host ""
    Write-Host "The API is not answering at $Api" -ForegroundColor Red
    Write-Host "Start it first, or use the combined script:"
    Write-Host "    .\scripts\restart_and_test.ps1"
    exit 1
}

Write-Host "SecureMailScope sample test"
Write-Host "API            : $Api"
Write-Host ("TShark         : {0}" -f $(if ($Health.tshark_available) { "available" } else { "NOT AVAILABLE" }))
Write-Host ("ML model       : {0}" -f $Health.ml_model_status)
if ($Health.ml_model_note) {
    Write-Host ("ML note        : {0}" -f $Health.ml_model_note) -ForegroundColor Yellow
}
if ($Health.ml_model_status -in @("not_loaded", "load_failed", "stale", "")) {
    $HealthWarning = "The trained model is not in use. Rule-based classification is applied instead."
    Write-Host $HealthWarning -ForegroundColor Yellow
    Write-Host "Fix it with: python -m app.ml.train"
}

# --- 2. Find the captures ----------------------------------------------------
$Directories = @(".\samples")
if (-not $OnlyPublic) { $Directories += ".\samples\lab" }

$Files = @()
foreach ($Directory in $Directories) {
    if (-not (Test-Path $Directory)) { continue }
    $Files += Get-ChildItem $Directory -File | Where-Object {
        $_.Extension -in ".pcap", ".pcapng", ".cap"
    }
}

if ($Files.Count -eq 0) {
    Write-Host "No .pcap/.pcapng/.cap files found in: $($Directories -join ', ')" -ForegroundColor Red
    Write-Host "Run .\scripts\download_samples.ps1 to fetch the public samples."
    exit 1
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "curl.exe was not found. It ships with Windows 10 and later." -ForegroundColor Red
    exit 1
}

Write-Host ("Captures       : {0}" -f $Files.Count)
Write-Host ""

# --- 3. Analyse every capture ------------------------------------------------
$Summary = @()
$AgreementProblems = @()

foreach ($File in $Files) {
    $OutputFile = Join-Path $Output ($File.BaseName + ".json")
    $SizeMb = [math]::Round($File.Length / 1MB, 2)
    Write-Host ("Uploading {0} ({1} MB)..." -f $File.Name, $SizeMb)

    $Timer = [System.Diagnostics.Stopwatch]::StartNew()
    $Json = curl.exe -s -X POST "$Api/api/v1/analyses/upload" `
        -F "file=@$($File.FullName)" `
        -F "uploaded_by=$UploadedBy"
    $Timer.Stop()
    $Seconds = [math]::Round($Timer.Elapsed.TotalSeconds, 1)

    $Json | Out-File -FilePath $OutputFile -Encoding utf8

    try {
        $Result = $Json | ConvertFrom-Json
    } catch {
        Write-Host ("  The API did not return JSON (see {0})" -f $OutputFile) -ForegroundColor Red
        Write-Host $Json
        continue
    }

    if ($Result.detail) {
        Write-Host ("  API error: {0}" -f $Result.detail) -ForegroundColor Red
        continue
    }

    $Summary += [pscustomobject]@{
        File        = $Result.source_filename
        Seconds     = $Seconds
        Sessions    = $Result.summary.total_sessions
        TLS         = $Result.summary.tls_sessions
        Plaintext   = $Result.summary.plaintext_sessions
        StartTLS    = $Result.summary.starttls_sessions
        Upgraded    = $Result.summary.successful_upgrades
        Findings    = $Result.summary.total_findings
        Posture     = $Result.summary.overall_posture_score
        Risk        = $Result.summary.overall_risk_class
        Evidence    = $Result.summary.evidence_completeness
    }

    $SeverityBits = @()
    foreach ($Severity in @("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
        $Count = $Result.summary.findings_by_severity.$Severity
        if ($Count -gt 0) { $SeverityBits += ("{0} {1}" -f $Count, $Severity) }
    }

    Write-Host ("  {0}: {1} session(s), {2} TLS, {3} findings, posture {4}/100 ({5}), {6}s" -f `
        $Result.source_filename,
        $Result.summary.total_sessions,
        $Result.summary.tls_sessions,
        $Result.summary.total_findings,
        $Result.summary.overall_posture_score,
        $Result.summary.overall_risk_class,
        $Seconds)
    if ($SeverityBits.Count -gt 0) {
        Write-Host ("    severities: {0}" -f ($SeverityBits -join ", "))
    }

    # Highest-severity findings, so a wrong detection is visible immediately.
    foreach ($Finding in ($Result.findings | Select-Object -First 4)) {
        Write-Host ("    [{0}] {1} - {2}" -f $Finding.severity, $Finding.code, $Finding.title)
    }

    # Does the ML class agree with the rule findings for every session?
    foreach ($Session in $Result.sessions) {
        if ($Session.ml.risk_class -ne $Session.policy_risk_class) {
            $AgreementProblems += ("{0} / {1}: rules={2} ml={3}" -f `
                $Result.source_filename, $Session.session_id, $Session.policy_risk_class, $Session.ml.risk_class)
        }
    }
}

# --- 4. Summary table -------------------------------------------------------
# Printed with fixed column widths instead of Format-Table, because Format-Table
# silently drops columns when the console window is narrow.
Write-Host ""
Write-Host "Summary"
$HeaderFormat = "{0,-32} {1,5} {2,5} {3,4} {4,6} {5,5} {6,4} {7,5} {8,7} {9,-9} {10,5}"
Write-Host ($HeaderFormat -f "Capture", "Sec", "Sess", "TLS", "Plain", "STLS", "Upg", "Find", "Posture", "Risk", "Evid")
Write-Host ($HeaderFormat -f ("-" * 32), "-----", "-----", "----", "------", "-----", "----", "-----", "-------", "---------", "-----")
foreach ($Row in $Summary) {
    $Name = $Row.File
    if ($Name.Length -gt 32) { $Name = $Name.Substring(0, 29) + "..." }
    Write-Host ($HeaderFormat -f $Name, $Row.Seconds, $Row.Sessions, $Row.TLS, $Row.Plaintext, $Row.StartTLS, $Row.Upgraded, $Row.Findings, $Row.Posture, $Row.Risk, $Row.Evidence)
}
Write-Host ""
Write-Host "Sec = seconds | Sess = sessions | Plain = cleartext sessions | STLS = STARTTLS/STLS requested"
Write-Host "Upg = successful upgrades | Find = findings | Evid = evidence completeness (0-1)"

# --- 5. Honest verdict ------------------------------------------------------
if ($AgreementProblems.Count -eq 0) {
    Write-Host "ML classification agrees with the rule findings for every session." -ForegroundColor Green
} else {
    Write-Host "ML and rule classification disagree for:" -ForegroundColor Yellow
    foreach ($Problem in $AgreementProblems) { Write-Host ("  {0}" -f $Problem) }
    Write-Host "The rule findings are the evidence-based result. Retrain with: python -m app.ml.train"
}

$TotalSessions = ($Summary | Measure-Object -Property Sessions -Sum).Sum
Write-Host ("Analysed {0} capture(s), {1} session(s) in total." -f $Files.Count, $TotalSessions)
Write-Host "Full JSON results saved to $Output"
