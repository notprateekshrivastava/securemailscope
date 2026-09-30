# Checks that the project folder matches the update bundle you were sent.
#
# Why this exists: the usual problem after unzipping an update is not a broken
# file, it is a file that was never copied. When a script is missing, PowerShell
# says only "The term ... is not recognized", which does not tell you whether the
# update was applied at all. This script reads the bundle_manifest.txt that ships
# inside the zip and tells you exactly what is missing or out of date.
#
# Usage:
#   .\scripts\check_files.ps1
#   .\scripts\check_files.ps1 -ShowMissing     (list every missing file, not a sample)
#
# Exit codes: 0 = nothing missing, 1 = files are missing, 2 = no manifest found.

param(
    [switch]$ShowMissing,
    [int]$SampleSize = 15
)

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$ManifestPath = Join-Path $Root "bundle_manifest.txt"
if (-not (Test-Path $ManifestPath)) {
    Write-Host "No bundle_manifest.txt in $Root" -ForegroundColor Yellow
    Write-Host "That file is written by the update bundle. If you never extracted the bundle,"
    Write-Host "extract it into this folder (replace existing files), or copy bundle_manifest.txt"
    Write-Host "in by hand, then run this script again."
    exit 2
}

$Missing = @()
$Changed = @()
$Same = 0
$Checked = 0

foreach ($Line in Get-Content $ManifestPath) {
    if ($Line -match '^\s*#' -or $Line -match '^\s*$') { continue }
    $Parts = $Line -split '\s+', 2
    if ($Parts.Count -ne 2) { continue }
    $Expected = $Parts[0].Trim()
    $Relative = $Parts[1].Trim()
    $Checked++

    $Full = Join-Path $Root ($Relative -replace '/', '\')
    if (-not (Test-Path $Full -PathType Leaf)) {
        $Missing += $Relative
        continue
    }

    $Actual = (Get-FileHash -Algorithm SHA256 -Path $Full).Hash.ToLower()
    if ($Actual -ne $Expected.ToLower()) { $Changed += $Relative } else { $Same++ }
}

Write-Host "Bundle manifest : $ManifestPath"
Write-Host ("Files listed    : {0}" -f $Checked)
Write-Host ("Up to date      : {0}" -f $Same) -ForegroundColor Green
Write-Host ("Different       : {0}" -f $Changed.Count) -ForegroundColor Yellow
Write-Host ("Missing         : {0}" -f $Missing.Count) -ForegroundColor $(if ($Missing.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($Missing.Count -gt 0) {
    Write-Host "These files are in the bundle but not on this machine:" -ForegroundColor Red
    $List = if ($ShowMissing) { $Missing } else { $Missing | Select-Object -First $SampleSize }
    $List | ForEach-Object { Write-Host ("  MISSING  {0}" -f $_) }
    if (-not $ShowMissing -and $Missing.Count -gt $SampleSize) {
        Write-Host ("  ... and {0} more (use -ShowMissing to list them all)" -f ($Missing.Count - $SampleSize))
    }
    Write-Host ""
    Write-Host "Fix: extract the update bundle again into this folder, choosing" -ForegroundColor Yellow
    Write-Host "'Replace the files in the destination'. Then run this script again." -ForegroundColor Yellow
    exit 1
}

if ($Changed.Count -gt 0) {
    Write-Host "These files exist but differ from the bundle:" -ForegroundColor Yellow
    $List = if ($ShowMissing) { $Changed } else { $Changed | Select-Object -First $SampleSize }
    $List | ForEach-Object { Write-Host ("  CHANGED  {0}" -f $_) }
    Write-Host ""
    Write-Host "This is normal for files you have edited yourself, and for reports you have" -ForegroundColor Yellow
    Write-Host "regenerated (for example samples\EXPECTED_RESULTS.md after running" -ForegroundColor Yellow
    Write-Host "build_sample_manifest.ps1). It is only a problem if you did not expect it."
}

Write-Host ""
Write-Host "Nothing is missing: the update was applied." -ForegroundColor Green
exit 0
