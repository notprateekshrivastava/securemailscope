# Exports the JSON, HTML and PDF reports for analyses, into a .\reports\ folder.
#
# Use this to produce the deliverable evidence for the submission: the problem
# statement requires JSON, HTML and PDF output, and this script generates all
# three from the same analysis, with a manifest that maps each report to the
# capture it came from.
#
# Usage:
#   # 1. export reports for every analysis the API already knows about
#   .\scripts\export_reports.ps1
#
#   # 2. export only the analyses whose source file name matches a pattern
#   .\scripts\export_reports.ps1 -Match "lab"
#
#   # 3. upload these captures first, then export their reports
#   .\scripts\export_reports.ps1 -Capture ".\samples\lab\imaps-tls10-legacy.pcapng", ".\samples\imap-ssl.pcapng"
#
#   # 4. limit how many analyses are exported (newest first)
#   .\scripts\export_reports.ps1 -Limit 6
#
#   # 5. export EVERY stored analysis, including older ones from previous runs
#   .\scripts\export_reports.ps1 -All
#
# By default only the newest analysis of each capture is exported. Every time you
# run test_all_samples.ps1 a new analysis is stored, so without this you would get
# one copy per run - and any analysis produced by an older build of the code along
# with it.

param(
    [int]$Port = 8000,
    [string]$UploadedBy = "team",
    [string[]]$Capture = @(),
    [string]$Match = "",
    [int]$Limit = 0,
    [int]$MaxSizeMB = 25,
    [string]$OutDir = "reports",
    [switch]$All
)

# Error handling is set after param(): PowerShell requires param() to be the
# first statement in the file, otherwise it is parsed as a command named "param".
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Api = "http://localhost:$Port"
$OutputPath = Join-Path $Root $OutDir
New-Item -ItemType Directory -Force $OutputPath | Out-Null

try {
    $Health = Invoke-RestMethod -Uri "$Api/api/v1/health" -TimeoutSec 5
} catch {
    Write-Host "The API is not answering at $Api" -ForegroundColor Red
    Write-Host "Start it first:  .\scripts\restart_and_test.ps1 -SkipTests"
    exit 1
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "curl.exe was not found. It ships with Windows 10 and later." -ForegroundColor Red
    exit 1
}

# --- Optional: upload specific captures first --------------------------------
if ($Capture.Count -gt 0) {
    foreach ($File in $Capture) {
        if (-not (Test-Path $File)) {
            Write-Host ("Skipping missing capture: {0}" -f $File) -ForegroundColor Yellow
            continue
        }
        Write-Host ("Uploading {0} ..." -f (Split-Path -Leaf $File))
        $Json = curl.exe -s -X POST "$Api/api/v1/analyses/upload" `
            -F "file=@$File" `
            -F "uploaded_by=$UploadedBy"
        $Result = $Json | ConvertFrom-Json
        if ($Result.detail) { Write-Host ("  API error: {0}" -f $Result.detail) -ForegroundColor Red }
        else { Write-Host ("  analysed {0} ({1} session(s))" -f $Result.source_filename, $Result.summary.total_sessions) }
    }
}

# --- Collect the analyses to export ------------------------------------------
$Analyses = Invoke-RestMethod -Uri "$Api/api/v1/analyses" -TimeoutSec 60
if ($null -eq $Analyses) { $Analyses = @() }
$Analyses = @($Analyses | Sort-Object created_at -Descending)
$Stored = $Analyses.Count

$CurrentVersion = $Health.version

# Older analyses stay on disk forever, and a result produced before a parser fix
# can contradict a correct one (for example a session count from before the
# mail-only filter existed). Two guards below: keep the newest analysis of each
# capture, and never export one whose analyzer version is not the running one.
$Stale = @($Analyses | Where-Object { $_.analyzer_version -ne $CurrentVersion })
$Analyses = @($Analyses | Where-Object { $_.analyzer_version -eq $CurrentVersion })

if (-not $All) {
    $Newest = @{}
    foreach ($Analysis in $Analyses) {
        if (-not $Newest.ContainsKey($Analysis.source_filename)) {
            $Newest[$Analysis.source_filename] = $Analysis       # already newest first
        }
    }
    $Analyses = @($Newest.Values | Sort-Object created_at -Descending)
}

if ($Match -ne "") {
    $Analyses = @($Analyses | Where-Object { $_.source_filename -like "*$Match*" })
}
if ($Limit -gt 0) {
    $Analyses = @($Analyses | Select-Object -First $Limit)
}

Write-Host ""
Write-Host ("Analyzer version : {0}" -f $CurrentVersion)
Write-Host ("Stored analyses  : {0}" -f $Stored)
if ($Stale.Count -gt 0) {
    Write-Host ("Skipped (old analyzer version, not exported): {0}" -f $Stale.Count) -ForegroundColor Yellow
    foreach ($Old in @($Stale | Select-Object -First 5)) {
        Write-Host ("    v{0}  {1}  ({2} session(s))" -f $Old.analyzer_version, $Old.source_filename, $Old.summary.total_sessions)
    }
    Write-Host "  These came from an older build of the code. Remove them with:"
    Write-Host "      .\scripts\clear_analyses.ps1 -StaleOnly -Force"
}
Write-Host ("To export            : {0} analysis/analyses" -f $Analyses.Count)

if ($Analyses.Count -eq 0) {
    Write-Host "No analyses to export." -ForegroundColor Yellow
    Write-Host "Upload a capture first, or use -Capture <path>."
    exit 1
}

Write-Host ""
Write-Host ("Exporting {0} analysis/analyses to {1}" -f $Analyses.Count, $OutputPath)
Write-Host ""

$Manifest = @()
$Failed = 0

foreach ($Analysis in $Analyses) {
    $Id = $Analysis.analysis_id
    $Base = "{0}_{1}" -f $Analysis.source_filename, $Id.Substring(0, 8)
    $Base = ($Base -replace '[\\/:*?"<>|]', '_')

    Write-Host ("{0}  ({1} session(s), posture {2}/100 {3})" -f `
            $Analysis.source_filename, $Analysis.summary.total_sessions,
            $Analysis.summary.overall_posture_score, $Analysis.summary.overall_risk_class)

    $SessionCount = $Analysis.summary.total_sessions
    if ($SessionCount -gt 5000) {
        # A capture of email traffic cannot plausibly hold this many sessions. This
        # is the signature of a result stored before the mail-only traffic filter was
        # added, and its JSON can run to hundreds of megabytes.
        Write-Host ("   SKIPPED: {0} sessions - this result predates the traffic filter." -f $SessionCount) -ForegroundColor Red
        Write-Host "   Remove it with:  .\scripts\clear_analyses.ps1 -StaleOnly -Force"
        $Failed++
        continue
    }

    foreach ($Format in @("json", "html", "pdf")) {
        $Target = Join-Path $OutputPath ("{0}.{1}" -f $Base, $Format)
        $Url = "$Api/api/v1/analyses/$Id/reports/$Format"
        try {
            curl.exe -s -f -o $Target $Url | Out-Null
            $Size = (Get-Item $Target).Length
            $SizeMB = [math]::Round($Size / 1MB, 2)
            if ($SizeMB -ge $MaxSizeMB) {
                Write-Host ("   {0,-4} {1,8:N0} bytes  {2}" -f $Format, $Size, (Split-Path -Leaf $Target)) -ForegroundColor Yellow
                Write-Host ("        (large: {0} MB for {1} sessions - check the capture was filtered to mail traffic)" -f $SizeMB, $SessionCount) -ForegroundColor Yellow
            } else {
                Write-Host ("   {0,-4} {1,8:N0} bytes  {2}" -f $Format, $Size, (Split-Path -Leaf $Target))
            }
        } catch {
            Write-Host ("   {0,-4} FAILED" -f $Format) -ForegroundColor Red
            $Failed++
        }
    }

    $Manifest += [pscustomobject]@{
        capture      = $Analysis.source_filename
        analysis_id  = $Id
        created_at   = $Analysis.created_at
        uploaded_by  = $Analysis.uploaded_by
        source_sha256 = $Analysis.source_sha256
        sessions     = $Analysis.summary.total_sessions
        tls_sessions = $Analysis.summary.tls_sessions
        cleartext    = $Analysis.summary.plaintext_sessions
        findings     = $Analysis.summary.total_findings
        posture      = $Analysis.summary.overall_posture_score
        risk_class   = $Analysis.summary.overall_risk_class
        evidence     = $Analysis.summary.evidence_completeness
        files        = ("{0}.json; {0}.html; {0}.pdf" -f $Base)
    }
}

# --- Manifest for the submission folder --------------------------------------
$ManifestPath = Join-Path $OutputPath "REPORT_MANIFEST.csv"
$Manifest | Export-Csv -Path $ManifestPath -NoTypeInformation -Encoding UTF8

$ReadmePath = Join-Path $OutputPath "README.md"
$ReadmeLines = @()
$ReadmeLines += "# Report exports"
$ReadmeLines += ""
$ReadmeLines += ("Generated by ``scripts\export_reports.ps1`` on {0}." -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
$ReadmeLines += ""
$ReadmeLines += "Every analysis is exported in the three required formats from the same result:"
$ReadmeLines += ""
$ReadmeLines += "| File type | Contains |"
$ReadmeLines += "|---|---|"
$ReadmeLines += "| ``.json`` | The full machine-readable result: upload provenance (file name, SHA-256, uploader), summary, every session with its feature vector, TLS and certificate evidence, findings, ML assessment and recommendations |"
$ReadmeLines += "| ``.html`` | The same result as a self-contained web page for viewing and screenshots |"
$ReadmeLines += "| ``.pdf`` | The same result as a printable report for the submission pack |"
$ReadmeLines += ""
$ReadmeLines += "File names follow ``<capture name>_<analysis id prefix>.<format>``. The full mapping,"
$ReadmeLines += "including the capture SHA-256 that proves which file was analysed, is in ``REPORT_MANIFEST.csv``."
$ReadmeLines += ""
$ReadmeLines += "## Analyses included"
$ReadmeLines += ""
$ReadmeLines += "| Capture | Sessions | Findings | Posture | Risk class | Evidence completeness | Uploaded as |"
$ReadmeLines += "|---|---|---|---|---|---|---|"
foreach ($Row in $Manifest) {
    $ReadmeLines += ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
            $Row.capture, $Row.sessions, $Row.findings, $Row.posture, $Row.risk_class, $Row.evidence, $Row.uploaded_by)
}
$ReadmeLines += ""
$ReadmeLines += "## How to reproduce"
$ReadmeLines += ""
$ReadmeLines += '```powershell'
$ReadmeLines += ".\scripts\restart_and_test.ps1 -SkipTests"
$ReadmeLines += ".\scripts\export_reports.ps1"
$ReadmeLines += '```'
$ReadmeLines += ""
$ReadmeLines += "The traceability requirement is met by the ``source_sha256`` column: the same"
$ReadmeLines += "capture file always produces the same hash, so a report can be tied back to the"
$ReadmeLines += "exact bytes that were analysed."
$ReadmeLines += ""
$ReadmeLines | Out-File -FilePath $ReadmePath -Encoding utf8

Write-Host ""
Write-Host ("Manifest : {0}" -f $ManifestPath)
Write-Host ("Readme   : {0}" -f $ReadmePath)
if ($Failed -gt 0) {
    Write-Host ("{0} export(s) failed - check that the API is still running." -f $Failed) -ForegroundColor Red
    exit 1
}
Write-Host ("Exported {0} analysis/analyses ({1} files)." -f $Manifest.Count, ($Manifest.Count * 3))
