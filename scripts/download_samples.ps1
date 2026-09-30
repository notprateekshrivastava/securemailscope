$ErrorActionPreference = "Stop"

$Samples = Join-Path (Get-Location) "samples"
New-Item -ItemType Directory -Force $Samples | Out-Null

$Files = @(
    @{
        Name = "smtp-ssl.pcapng"
        Url = "https://raw.githubusercontent.com/Lekensteyn/wireshark-notes/master/tls/smtp-ssl.pcapng"
    },
    @{
        Name = "imap-ssl.pcapng"
        Url = "https://raw.githubusercontent.com/Lekensteyn/wireshark-notes/master/tls/imap-ssl.pcapng"
    },
    @{
        Name = "pop-ssl.pcapng"
        Url = "https://raw.githubusercontent.com/Lekensteyn/wireshark-notes/master/tls/pop-ssl.pcapng"
    },
    @{
        Name = "The-Ultimate-PCAP.pcapng.gz"
        Url = "https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz"
    }
)

foreach ($File in $Files) {
    $Destination = Join-Path $Samples $File.Name
    Write-Host "Downloading $($File.Name)..."
    Invoke-WebRequest -Uri $File.Url -OutFile $Destination
}

$Compressed = Join-Path $Samples "The-Ultimate-PCAP.pcapng.gz"
$Extracted = Join-Path $Samples "The-Ultimate-PCAP.pcapng"
if (Test-Path $Compressed) {
    Write-Host "Extracting The-Ultimate-PCAP.pcapng.gz..."
    tar -xzf $Compressed -C $Samples
}

Write-Host "`nDownloaded files:`n"
Get-ChildItem $Samples -File | Where-Object { $_.Extension -in ".pcap", ".pcapng", ".cap", ".gz" } | Format-Table Name, Length
Write-Host "`nNow test:"
Write-Host 'tshark -r ".\samples\The-Ultimate-PCAP.pcapng" -c 10'
