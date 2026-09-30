# Sample PCAP files for SecureMailScope

These files are for parser/integration testing. They are not the final labelled ML dataset.

## Included in the shared workspace

| File | Purpose | Source |
|---|---|---|
| `The-Ultimate-PCAP.pcapng` | Broad protocol capture; includes SMTP, IMAP and POP3 cleartext, STARTTLS and implicit-TLS variants | [Project page](https://weberblog.net/the-ultimate-pcap/) |
| `smtp-ssl.pcapng` | SMTPS/TLS sample | [Public capture repository](https://github.com/Lekensteyn/wireshark-notes/tree/master/tls) |
| `imap-ssl.pcapng` | IMAPS/TLS sample | [Public capture repository](https://github.com/Lekensteyn/wireshark-notes/tree/master/tls) |
| `pop-ssl.pcapng` | POP3S/TLS sample | [Public capture repository](https://github.com/Lekensteyn/wireshark-notes/tree/master/tls) |

The compressed `The-Ultimate-PCAP.pcapng.gz` is also present. Upload the extracted `.pcapng` file to the API, not the compressed archive.

## Windows test commands

From the project root:

```powershell
tshark -r ".\samples\The-Ultimate-PCAP.pcapng" -c 10
```

Email-port filter:

```powershell
tshark -r ".\samples\The-Ultimate-PCAP.pcapng" `
  -Y "tcp.port == 25 || tcp.port == 465 || tcp.port == 587 || tcp.port == 110 || tcp.port == 995 || tcp.port == 143 || tcp.port == 993" `
  -c 30
```

Test one encrypted sample:

```powershell
tshark -r ".\samples\imap-ssl.pcapng" -c 10
```

## Upload through the API

Use Swagger at `http://localhost:8000/docs` and select `POST /api/v1/analyses/upload`.

Or use PowerShell 7:

```powershell
$form = @{
  file = Get-Item ".\samples\imap-ssl.pcapng"
  uploaded_by = "team"
}
Invoke-RestMethod -Method POST -Uri "http://localhost:8000/api/v1/analyses/upload" -Form $form
```

## Run every sample automatically

Start the API first, then:

```powershell
.\scripts\test_all_samples.ps1
```

The script uploads each capture, prints duration, session/TLS/plaintext counts,
severity breakdown and the highest-severity findings, and saves the full JSON
answers to `data\sample-results\`.

Build the evidence manifest for your submission with:

```powershell
.\scripts\build_sample_manifest.ps1
```

That writes `samples\EXPECTED_RESULTS.md`, a table of what each capture really
contains (protocol, port, TLS version and its source, cipher, STARTTLS outcome,
cleartext authentication, posture, evidence completeness, top findings).

## What each sample can and cannot prove

| Sample | Proves | Cannot prove |
|---|---|---|
| `imap-ssl.pcapng` | IMAPS parsing, TLS detection, STARTTLS negotiation, evidence qualification | certificate checks - the certificate is encrypted in TLS 1.3 and the capture is loopback |
| `pop-ssl.pcapng` | POP3S parsing, implicit-TLS port handling | weak-cipher detection |
| `smtp-ssl.pcapng` | SMTPS parsing, TLS handshake metadata | STARTTLS behaviour |
| `The-Ultimate-PCAP.pcapng` | cleartext, STARTTLS and implicit-TLS mail sessions side by side, plus non-mail traffic that must be ignored | certificate/weak-configuration coverage - the file does not contain every weak case |

## If a sample parses incorrectly

```powershell
.\scripts\dump_tshark_json.ps1 -Capture ".\samples\imap-ssl.pcapng"
```

It runs the exact command the backend uses, saves the raw JSON to
`data\tshark-dumps\` and lists the field names your installed Wireshark produced.

## Lab captures (weak and healthy configurations)

`samples\lab\` contains nine captures generated on this machine by
`tools\lab_capture_toolkit.py`, covering the cases the public files do not have:
cleartext authentication, a rejected STARTTLS upgrade, TLS 1.0, a NULL cipher, an
expired weak certificate, TLS 1.3 with the certificate hidden, and a CBC cipher.

```powershell
python tools\lab_capture_toolkit.py verify
```

That command analyses every lab capture and compares the result with what the
scenario is supposed to produce (currently 9/9). The evidence table is written to
`samples\lab\EXPECTED_RESULTS.md`. See `docs\LAB_CAPTURES.md` for the demo script.

## Important

These public files are useful for proving that parsing works. They may not contain every weak configuration required for the final demo. After the parser is verified, we will generate controlled lab captures for TLS 1.0/1.1, weak ciphers, expired certificates and plaintext authentication. See `docs\ANALYSIS_FIXES.md` section 7 for the current status of that work.
