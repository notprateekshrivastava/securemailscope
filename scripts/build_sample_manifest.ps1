# Builds .\samples\EXPECTED_RESULTS.md from the JSON files produced by
# .\scripts\test_all_samples.ps1. Run that script first.
#
# The generated document is the evidence page for the submission: it lists, per
# capture, what the analysis engine actually observed (protocol, port, TLS
# version and where that value came from, negotiated cipher, upgrade outcome,
# cleartext authentication, risk, posture, evidence completeness) and then the
# findings with their severity. Nothing in it is estimated.

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$ResultsDir = Join-Path $Root "data\sample-results"
$OutFile = Join-Path $Root "samples\EXPECTED_RESULTS.md"

if (-not (Test-Path $ResultsDir)) {
    Write-Host "No results found. Run .\scripts\test_all_samples.ps1 first." -ForegroundColor Red
    exit 1
}

$ResultFiles = Get-ChildItem $ResultsDir -Filter *.json -File
if ($ResultFiles.Count -eq 0) {
    Write-Host "No analysis results found in $ResultsDir" -ForegroundColor Red
    exit 1
}

$Table = @()
$Captures = @()
$Sections = @()
$MaxRowsPerCapture = 8

foreach ($ResultFile in $ResultFiles | Sort-Object Name) {
    try {
        $Result = Get-Content $ResultFile.FullName -Raw | ConvertFrom-Json
    } catch {
        continue
    }
    if ($Result.detail) { continue }

    $Sessions = @($Result.sessions)
    $Index = 0
    # Worst risk class across the capture, using the same ordering as the API
    # summary (LOW < MEDIUM < HIGH < CRITICAL), so this table and the JSON report
    # always agree.
    $ClassOrder = @{ "LOW" = 0; "MEDIUM" = 1; "HIGH" = 2; "CRITICAL" = 3 }
    $WorstClass = "LOW"
    foreach ($Session in $Sessions) {
        $Current = [string]$Session.policy_risk_class
        if ($ClassOrder.ContainsKey($Current) -and $ClassOrder[$Current] -gt $ClassOrder[$WorstClass]) {
            $WorstClass = $Current
        }
    }
    $Protocols = @($Sessions | ForEach-Object { $_.protocol } | Sort-Object -Unique) -join "/"
    if ($Protocols -eq "") { $Protocols = "-" }
    $Agreements = @($Sessions | Where-Object { $_.ml.risk_class -eq $_.policy_risk_class })
    $AgreementText = "{0}/{1}" -f $Agreements.Count, $Sessions.Count

    $Captures += [pscustomobject]@{
        Capture    = $Result.source_filename
        Protocols  = $Protocols
        Sessions   = $Result.summary.total_sessions
        Tls        = $Result.summary.tls_sessions
        Plaintext  = $Result.summary.plaintext_sessions
        StartTLS   = $Result.summary.starttls_sessions
        Upgraded   = $Result.summary.successful_upgrades
        Findings   = $Result.summary.total_findings
        WorstRisk  = $(if ($Sessions.Count -gt 0) { $WorstClass } else { "-" })
        Posture    = $Result.summary.overall_posture_score
        Evidence   = $Result.summary.evidence_completeness
        MlAgree    = $AgreementText
    }

    foreach ($Session in $Sessions) {
        $Index++
        if ($Index -gt $MaxRowsPerCapture) { continue }
        $StartTls = "-"
        if ($Session.starttls.implicit_tls) { $StartTls = "implicit TLS" }
        elseif ($Session.starttls.rejected) { $StartTls = "REJECTED" }
        elseif ($Session.starttls.upgrade_successful) { $StartTls = "upgraded" }
        elseif ($Session.starttls.command_seen) { $StartTls = "requested, unconfirmed" }
        elseif ($Session.starttls.advertised) { $StartTls = "advertised only" }

        $Version = "-"
        if ($Session.tls.tls_version) {
            $Version = "{0} ({1})" -f $Session.tls.tls_version, $Session.tls.version_source
        } elseif ($Session.tls.detected) {
            $Version = "UNKNOWN ({0})" -f $Session.tls.version_source
        }

        $Cipher = "-"
        if ($Session.tls.cipher_suite) { $Cipher = $Session.tls.cipher_suite }
        elseif ($Session.tls.cipher_source -eq "CLIENT_OFFER") { $Cipher = "UNKNOWN (client offer only)" }

        $Certificate = "-"
        if ($Session.certificate.present) {
            $Certificate = "CN={0}, {1} {2}" -f $Session.certificate.common_name,
                $Session.certificate.public_key_algorithm, $Session.certificate.public_key_bits
        }

        $Cleartext = "no"
        if ($Session.starttls.plaintext_authentication_seen) { $Cleartext = "YES" }
        if (-not $Session.tls.detected) { $Cleartext = "session without TLS" }

        $TlsValue = "no"
        if ($Session.tls.detected) { $TlsValue = "yes" }

        $Agreement = "agree"
        if ($Session.ml.risk_class -ne $Session.policy_risk_class) { $Agreement = "DISAGREE" }

        $Table += [pscustomobject]@{
            Capture     = $Result.source_filename
            Session     = $Session.session_id
            Protocol    = ("{0}:{1}" -f $Session.protocol, $Session.server_port)
            Tls         = $TlsValue
            Version     = $Version
            Cipher      = $Cipher
            StartTLS    = $StartTls
            Cleartext   = $Cleartext
            Certificate = $Certificate
            Posture     = $Session.posture_score
            Risk        = $Session.policy_risk_class
            ML          = $Session.ml.risk_class
            Agreement   = $Agreement
            Evidence    = $Session.evidence_completeness
        }
    }

    if ($Sessions.Count -gt $MaxRowsPerCapture) {
        $Table += [pscustomobject]@{
            Capture = ("... {0} more session(s)" -f ($Sessions.Count - $MaxRowsPerCapture)); Session = ""
            Protocol = ""; Tls = ""; Version = ""; Cipher = ""; StartTLS = ""; Cleartext = ""
            Certificate = ""; Posture = ""; Risk = ""; ML = ""; Agreement = ""; Evidence = ""
        }
    }

    $SectionLines = @()
    $SectionLines += ("### {0}" -f $Result.source_filename)
    $SectionLines += ""
    $SectionLines += ("{0} session(s), overall posture {1}/100 ({2}), evidence completeness {3}." -f `
            $Result.summary.total_sessions, $Result.summary.overall_posture_score,
            $Result.summary.overall_risk_class, $Result.summary.evidence_completeness)
    $SectionLines += ""
    if ($Sessions.Count -eq 0) {
        $SectionLines += "No mail session was parsed from this capture."
        $SectionLines += ""
    }
    foreach ($Finding in $Result.findings) {
        $SectionLines += ("- ``{0}`` [{1}] {2}" -f $Finding.code, $Finding.severity, $Finding.title)
        $SectionLines += ("  - evidence: {0}" -f (($Finding.evidence) -join "; "))
        $SectionLines += ("  - fix: {0}" -f $Finding.recommendation)
    }
    $SectionLines += ""
    $Sections += ($SectionLines -join "`n")
}

$Lines = @()
$Lines += "# Observed results for every sample capture"
$Lines += ""
$Lines += ("Generated by ``scripts\build_sample_manifest.ps1`` on {0}." -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
$Lines += ""
$Lines += "Every value below comes from SecureMailScope analysing the capture with TShark."
$Lines += "Nothing is estimated: a value that could not be observed is reported as"
$Lines += "``UNKNOWN`` together with the reason, and is never treated as a weakness by itself."
$Lines += ""
$Lines += "## Capture summary"
$Lines += ""
$Lines += "| Capture | Protocol | Sessions | TLS | Cleartext | STARTTLS | Upgraded | Findings | Worst risk | Posture | Evidence | ML agrees |"
$Lines += "|---|---|---|---|---|---|---|---|---|---|---|---|"
foreach ($Row in $Captures) {
    $Lines += ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} |" -f `
            $Row.Capture, $Row.Protocols, $Row.Sessions, $Row.Tls, $Row.Plaintext, $Row.StartTLS,
        $Row.Upgraded, $Row.Findings, $Row.WorstRisk, $Row.Posture, $Row.Evidence, $Row.MlAgree)
}
$Lines += ""
$Lines += ("``ML agrees`` compares the machine-learning risk class with the rule findings per")
$Lines += "session. It is reported openly because the rule findings are the evidence-based"
$Lines += "result and the model must not be allowed to contradict them silently."
$Lines += ""
$Lines += ("## Session detail (first {0} sessions per capture)" -f $MaxRowsPerCapture)
$Lines += ""
$Lines += "| Capture | Session | Protocol:port | TLS | Version (source) | Cipher | Upgrade | Cleartext auth | Certificate | Posture | Risk | ML | Evidence |"
$Lines += "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
foreach ($Row in $Table) {
    $Lines += ("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} | {12} |" -f `
            $Row.Capture, $Row.Session, $Row.Protocol, $Row.Tls, $Row.Version, $Row.Cipher,
        $Row.StartTLS, $Row.Cleartext, $Row.Certificate, $Row.Posture, $Row.Risk, $Row.ML, $Row.Evidence)
}
$Lines += ""
$Lines += "Version source ``SERVER_HELLO`` means the value was read from the server's own"
$Lines += "handshake message. ``CLIENT_OFFER`` means only the client's proposal was visible,"
$Lines += "so no negotiated value is claimed."
$Lines += ""
$Lines += "## Findings per capture"
$Lines += ""
$Lines += ($Sections -join "`n")
$Lines += "## How to read this"
$Lines += ""
$Lines += "- ``posture`` is 100 minus the weighted severity of the findings (0-100)."
$Lines += "- ``evidence completeness`` is the fraction of the five evidence items that were"
$Lines += "  observable (protocol, traffic, TLS version, cipher suite, certificate)."
$Lines += "- A capture with a low completeness is not a weak capture; it is a capture that"
$Lines += "  shows less. The report states which questions it cannot answer."
$Lines += ""

$Lines | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "Wrote $OutFile"
Write-Host ("Sessions documented: {0} across {1} capture(s)." -f $Table.Count, $ResultFiles.Count)
