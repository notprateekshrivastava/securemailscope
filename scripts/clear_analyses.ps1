# Shows what analyses are stored, and removes the ones you do not want.
#
# Why this exists: every upload is stored in data\analyses\ and stays there. After
# a few runs the folder holds several copies of each capture, and it also holds
# results produced by older builds of the code. Those old results can contradict
# the current ones - for example an analysis made before the mail-only traffic
# filter existed reports every TCP stream in the capture instead of the email
# sessions, which makes the reports folder enormous and the numbers wrong.
#
# Usage:
#   .\scripts\clear_analyses.ps1                     # list only, delete nothing
#   .\scripts\clear_analyses.ps1 -StaleOnly -Force   # delete results from older builds
#   .\scripts\clear_analyses.ps1 -Keep 13 -Force     # keep the 13 newest, delete the rest
#   .\scripts\clear_analyses.ps1 -All -Force         # delete every stored analysis
#
# -Force is required for anything that deletes, so a mistyped command can never
# destroy results you wanted.
#
# What is NOT touched: data\uploads\ (the original PCAPs), models\, samples\ and
# of course the reports\ folder you already exported.

param(
    [string]$DataDir = "data",
    [int]$Keep = 0,
    [switch]$StaleOnly,
    [switch]$All,
    [switch]$Force
)

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$AnalysisDir = Join-Path $Root $DataDir
$AnalysisDir = Join-Path $AnalysisDir "analyses"

if (-not (Test-Path $AnalysisDir)) {
    Write-Host "No analysis folder at $AnalysisDir - nothing to do." -ForegroundColor Yellow
    exit 0
}

# The running version, straight from the code, so this script never guesses.
$VersionFile = Join-Path $Root "app\version.py"
if (Test-Path $VersionFile) {
    $VersionLine = Select-String -Path $VersionFile -Pattern '^ANALYZER_VERSION\s*=' | Select-Object -First 1
    $CurrentVersion = if ($VersionLine) { ($VersionLine.Line -split '"')[1] } else { "unknown" }
} else {
    $CurrentVersion = "unknown"
}

$Rows = @()
foreach ($File in Get-ChildItem $AnalysisDir -Filter *.json -File) {
    try {
        # Read only the head of the file: an old unfiltered result can be 100 MB+
        # and parsing it whole is slow and unnecessary for a listing.
        $Head = Get-Content $File.FullName -TotalCount 40 -ErrorAction Stop
        $Text = $Head -join "`n"
        $Capture = if ($Text -match '"source_filename"\s*:\s*"([^"]+)"') { $Matches[1] } else { "(unreadable)" }
        $Version = if ($Text -match '"analyzer_version"\s*:\s*"([^"]+)"') { $Matches[1] } else { "unknown" }
        $Created = if ($Text -match '"created_at"\s*:\s*"([^"]+)"') { $Matches[1] } else { "" }
        $Sessions = 0
        if ($Text -match '"total_sessions"\s*:\s*(\d+)') { $Sessions = [int]$Matches[1] }
    } catch {
        $Capture = "(unreadable)"; $Version = "unknown"; $Created = ""; $Sessions = 0
    }
    $Rows += [pscustomobject]@{
        File     = $File
        Name     = $File.Name
        Capture  = $Capture
        Version  = $Version
        Created  = $Created
        Sessions = $Sessions
        SizeMB   = [math]::Round($File.Length / 1MB, 2)
        IsStale  = ($Version -ne $CurrentVersion)
    }
}

if ($Rows.Count -eq 0) {
    Write-Host "No stored analyses in $AnalysisDir - nothing to do." -ForegroundColor Green
    exit 0
}

$Rows = $Rows | Sort-Object Created -Descending
$TotalMB = ($Rows | Measure-Object -Property SizeMB -Sum).Sum

Write-Host "Stored analyses : $AnalysisDir" -ForegroundColor Green
Write-Host ("Analyzer version in the code : {0}" -f $CurrentVersion)
Write-Host ("Files: {0}   Total size: {1} MB" -f $Rows.Count, [math]::Round($TotalMB, 2))
Write-Host ""
Write-Host ("{0,-38} {1,-9} {2,7} {3,9} {4,7}  {5}" -f "Capture", "Version", "Sessions", "Size MB", "Stale", "Created (UTC)")
Write-Host ("{0,-38} {1,-9} {2,7} {3,9} {4,7}  {5}" -f ("-" * 38), ("-" * 9), ("-" * 7), ("-" * 9), ("-" * 7), ("-" * 19))
foreach ($Row in $Rows) {
    $StaleFlag = if ($Row.IsStale) { "yes" } else { "no" }
    $Capture = if ($Row.Capture.Length -gt 36) { $Row.Capture.Substring(0, 36) } else { $Row.Capture }
    Write-Host ("{0,-38} {1,-9} {2,7} {3,9} {4,7}  {5}" -f $Capture, $Row.Version, $Row.Sessions, $Row.SizeMB, $StaleFlag, $Row.Created)
}
Write-Host ""

# --- decide what to delete ---------------------------------------------------
$Targets = @()
$Reason = ""

if ($All) {
    $Targets = $Rows
    $Reason = "-All: every stored analysis"
} elseif ($StaleOnly) {
    $Targets = @($Rows | Where-Object { $_.IsStale })
    $Reason = "-StaleOnly: produced by an older analyzer version"
} elseif ($Keep -gt 0) {
    $Targets = @($Rows | Select-Object -Skip $Keep)
    $Reason = ("-Keep {0}: everything after the {0} newest" -f $Keep)
}

if ($Targets.Count -eq 0) {
    Write-Host "Nothing selected for deletion." -ForegroundColor Green
    if (-not $Force) {
        Write-Host "Add one of: -StaleOnly, -Keep <n>, -All   (with -Force to actually delete)"
    }
    exit 0
}

$TargetMB = [math]::Round((($Targets | Measure-Object -Property SizeMB -Sum).Sum), 2)
Write-Host ("Selected to delete: {0} file(s), {1} MB  ({2})" -f $Targets.Count, $TargetMB, $Reason) -ForegroundColor Yellow
foreach ($Row in $Targets) {
    Write-Host ("   {0}  ({1} sessions, {2} MB)" -f $Row.Name, $Row.Sessions, $Row.SizeMB)
}

if (-not $Force) {
    Write-Host ""
    Write-Host "Nothing was deleted. Add -Force to confirm:" -ForegroundColor Yellow
    Write-Host "   .\scripts\clear_analyses.ps1 -StaleOnly -Force"
    exit 0
}

$Deleted = 0
foreach ($Row in $Targets) {
    try {
        Remove-Item $Row.File.FullName -Force -ErrorAction Stop
        $Deleted++
    } catch {
        Write-Warning ("Could not delete {0}: {1}" -f $Row.Name, $_.Exception.Message)
    }
}

Write-Host ""
Write-Host ("Deleted {0} file(s), freed {1} MB." -f $Deleted, $TargetMB) -ForegroundColor Green
Write-Host "The API reads this folder on every request, so no restart is needed."
Write-Host "Next: .\scripts\restart_and_test.ps1   (regenerate fresh analyses)"
