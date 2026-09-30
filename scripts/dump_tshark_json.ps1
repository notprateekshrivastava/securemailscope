# Diagnostic helper: run exactly the TShark command the backend uses and save
# the raw JSON, so a parsing problem can be debugged without guessing.
#
# Usage:
#   .\scripts\dump_tshark_json.ps1 -Capture ".\samples\imap-ssl.pcapng"
#   .\scripts\dump_tshark_json.ps1 -Capture ".\samples\The-Ultimate-PCAP.pcapng" -MaxPackets 3000

param(
    [Parameter(Mandatory = $true)][string]$Capture,
    [int]$MaxPackets = 0,
    [string]$OutDir = ".\data\tshark-dumps"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Capture)) { throw "Capture not found: $Capture" }

$Tshark = "tshark"
if (-not (Get-Command $Tshark -ErrorAction SilentlyContinue)) {
    foreach ($Candidate in @(
            "C:\Program Files\Wireshark\tshark.exe",
            "C:\Program Files (x86)\Wireshark\tshark.exe")) {
        if (Test-Path $Candidate) { $Tshark = $Candidate; break }
    }
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$BaseName = [System.IO.Path]::GetFileNameWithoutExtension($Capture)

# Same filter and preferences as app/analysis/tshark.py
$Filter = "tcp.port in {25,110,143,465,587,993,995} || smtp || imap || pop || tls || ssl"

$TsharkArgs = @("-n", "-r", $Capture, "-Y", $Filter, "-T", "json",
    "-o", "tcp.desegment_tcp_streams:TRUE",
    "-o", "tls.desegment_ssl_records:TRUE")
if ($MaxPackets -gt 0) { $TsharkArgs += @("-c", "$MaxPackets") }

$JsonPath = Join-Path $OutDir "$BaseName.json"
$FieldPath = Join-Path $OutDir "$BaseName.fields.txt"

Write-Host "[1/3] Running: $Tshark $($TsharkArgs -join ' ')"
$Timer = [System.Diagnostics.Stopwatch]::StartNew()
$Json = & $Tshark @TsharkArgs
$Timer.Stop()
$Json | Out-File -FilePath $JsonPath -Encoding utf8
Write-Host ("[2/3] Saved {0:N1} MB of JSON to {1} in {2:N1}s" -f `
    ((Get-Item $JsonPath).Length / 1MB), $JsonPath, $Timer.Elapsed.TotalSeconds)

Write-Host "[3/3] Email/TLS field names produced by your Wireshark version:"
$Content = Get-Content $JsonPath -Raw
[regex]::Matches($Content, '"([a-z0-9_]*(?:smtp|imap|pop|tls|ssl)[a-z0-9_.]*)"') |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique |
    Tee-Object -FilePath $FieldPath
Write-Host "`nField list also saved to $FieldPath"
Write-Host "Send that file if a sample is parsed incorrectly."
