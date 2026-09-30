# Generates the held-out test set (if it is not there yet) and scores the analyzer and the
# ML layer against it.
#
# The test set is captures the model never trained on, covering situations the training
# captures did not have: IMAP STARTTLS, POP3 STLS, SMTP with no STARTTLS offered, and
# capture files that mix protocols and port families.
#
# Run:
#   .\scripts\run_testset.ps1                 # score what is there; generate it first if missing
#   .\scripts\run_testset.ps1 -Regenerate     # capture it again from scratch
#   .\scripts\run_testset.ps1 -Rounds 120     # a bigger large file (~3,100 sessions)
#   .\scripts\run_testset.ps1 -SkipLarge      # small files only, faster
#   .\scripts\run_testset.ps1 -Limit 4        # score the first four files only (quick check)

param(
    [switch]$Regenerate,
    [switch]$SkipLarge,
    [int]$Rounds = 40,
    [int]$Limit = 0
)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Python = "python"
if (Test-Path ".\.venv\Scripts\python.exe") { $Python = ".\.venv\Scripts\python.exe" }

# Generation needs Wireshark's tshark on PATH. Scoring does not, but generation does, and
# on Windows none of the ports involved need administrator rights.
if ($Regenerate -or -not (Test-Path ".\testset\ground_truth.json")) {
    Write-Host "Generating the test set (this takes about a minute) ..." -ForegroundColor Cyan
    $args = @("tools\lab_capture_toolkit.py", "testset", "--rounds", "$Rounds")
    if ($SkipLarge) { $args += "--skip-large" }
    & $Python @args
    if ($LASTEXITCODE -ne 0) { throw "Test set generation failed (exit $LASTEXITCODE)" }
}

Write-Host ""
Write-Host "Scoring against the declared expectations ..." -ForegroundColor Cyan
$scoreArgs = @("tools\score_testset.py", "--dir", "testset", "--json", "testset\results.json")
if ($Limit -gt 0) { $scoreArgs += @("--limit", "$Limit") }
& $Python @scoreArgs
$exit = $LASTEXITCODE

Write-Host ""
Write-Host "Full detail: testset\RESULTS.md" -ForegroundColor Green
Write-Host "Expectations: testset\EXPECTED.md   (declared before the captures were analysed)"
Write-Host ""
Write-Host "Exit code 0 means every declared expectation was met. Anything else is listed in"
Write-Host "RESULTS.md with the situation, the check that failed and what was reported instead."

exit $exit
