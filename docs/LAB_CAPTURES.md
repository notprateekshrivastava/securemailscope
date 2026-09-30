# Lab captures: how to prove risk escalation with your own traffic

This document explains the fifteen lab captures in `samples\lab\`, how they were
produced, and how to use them in the demo.

The public Wireshark samples prove that the parser works, but they do not contain
the weak configurations the project has to detect. The lab set fills exactly that
gap, using the option the official dataset note allows: generating SMTP / IMAPS /
POP3S traffic and capturing it locally.

---

## 1. What is in `samples\lab\`

| Capture | Scenario | Expected findings |
|---|---|---|
| `smtp-starttls-secure.pcapng` | SMTP 587, successful STARTTLS, modern TLS 1.2, healthy certificate | *(none - baseline)* |
| `smtp-starttls-rejected.pcapng` | Server answers `454` to STARTTLS, client authenticates unencrypted | `STARTTLS_REJECTED`, `PLAINTEXT_AUTHENTICATION`, `PLAINTEXT_EMAIL_SESSION` |
| `imap-cleartext-login.pcapng` | IMAP `LOGIN` sent before STARTTLS, then a successful upgrade | `PLAINTEXT_AUTHENTICATION` |
| `pop3-cleartext.pcapng` | POP3 with no encryption at all (`USER`/`PASS` in the clear) | `PLAINTEXT_EMAIL_SESSION`, `PLAINTEXT_AUTHENTICATION` |
| `imaps-tls10-legacy.pcapng` | IMAPS 993 negotiating TLS 1.0 with CBC and static RSA | `DEPRECATED_TLS_VERSION`, `NO_FORWARD_SECRECY`, `LEGACY_CBC_CIPHER` |
| `imaps-null-cipher.pcapng` | IMAPS negotiating a NULL (encryption-free) cipher suite | `INSECURE_CIPHER` |
| `smtps-weak-certificate.pcapng` | SMTPS with an expired 1024-bit certificate issued for the wrong hostname | `CERTIFICATE_EXPIRED`, `WEAK_CERTIFICATE_KEY`, `CERTIFICATE_HOSTNAME_MISMATCH` |
| `imaps-tls13-cert-hidden.pcapng` | Modern TLS 1.3, where the certificate is encrypted on the wire | `CERTIFICATE_NOT_OBSERVED` (INFO only) |
| `imaps-cbc-cipher.pcapng` | TLS 1.2 with ECDHE but a CBC cipher suite | `LEGACY_CBC_CIPHER` |
| `pop3s-tls10-legacy.pcapng` | POP3S 995 negotiating TLS 1.0 with static RSA | `DEPRECATED_TLS_VERSION`, `NO_FORWARD_SECRECY` |
| `pop3s-weak-certificate.pcapng` | POP3S with an expired 1024-bit certificate for the wrong hostname | `CERTIFICATE_EXPIRED`, `WEAK_CERTIFICATE_KEY`, `CERTIFICATE_HOSTNAME_MISMATCH` |
| `pop3s-cbc-cipher.pcapng` | POP3S with a CBC cipher suite | `LEGACY_CBC_CIPHER` |
| `smtps-cbc-cipher.pcapng` | SMTPS 465 with a CBC cipher suite | `LEGACY_CBC_CIPHER` |
| `smtps-tls13-modern.pcapng` | SMTPS over TLS 1.3, certificate not observable | `CERTIFICATE_NOT_OBSERVED` (INFO only) |
| `imaps-weak-certificate.pcapng` | IMAPS with an expired 1024-bit certificate for the wrong hostname | `CERTIFICATE_EXPIRED`, `WEAK_CERTIFICATE_KEY`, `CERTIFICATE_HOSTNAME_MISMATCH` |

The last six were added after measuring what improves the model: more *diverse* captures,
not more training rows (four times the synthetic rows changed nothing). Until then POP3 had
no encrypted scenario at all, which left POP3S - named in the problem statement - covered
only in cleartext. Each new scenario reuses an existing mock-server mode and TLS profile,
so nothing about the first nine captures changed, and the set verifies **15/15**.

`samples\lab\EXPECTED_RESULTS.md` is generated from the real analysis output and
shows, per capture, the observed protocol, TLS version and its source, cipher and
its source, certificate facts, risk score, risk class, posture score, evidence
completeness and the findings that fired. `samples\lab\capture_log.json` records
what the mock server and the client actually did.

---

## 2. How the captures were produced

`tools\lab_capture_toolkit.py` does four things on this machine only:

1. **Certificates** - builds a private lab CA (root -> intermediate -> leaf) with
   `cryptography`, plus a deliberately bad leaf: 1024-bit RSA, expired, and a
   name that does not match the server name the client requests. A SHA-1
   signature is attempted first and falls back to SHA-256 when the local
   `cryptography` build refuses SHA-1; `certificate_facts.json` records which was
   used.
2. **Mock mail server** - a minimal SMTP / IMAP / POP3 server that speaks the real
   dialogues and behaves exactly as the scenario requires (advertise STARTTLS,
   accept it, reject it with `454`, or start TLS immediately).
3. **Client** - performs the client half: `EHLO`/`AUTH` for SMTP,
   `CAPABILITY`/`LOGIN` for IMAP, `USER`/`PASS` for POP3, with the weak TLS
   profile where the scenario needs one.
4. **Capture** - runs TShark on the loopback interface, filtered to the scenario's
   port, while the two talk. Nothing leaves `127.0.0.1`.

No email content is generated or stored: the mock server answers protocol commands
only, and the one `RETR` reply is a fixed placeholder line. The analysis engine
never reads message bodies either - that is enforced in the parser, which skips
`*.data` fields.

Weak profiles are requested deliberately, with `@SECLEVEL=0`, because modern
OpenSSL refuses to negotiate them by default. The toolkit records in
`capture_log.json` what was actually negotiated, so nothing is claimed that the
packets do not show.

---

## 3. Run it yourself (Windows)

```powershell
cd "D:\CryptoPost SIH\securemailscope"

python tools\lab_capture_toolkit.py list      # what can be generated
python tools\lab_capture_toolkit.py certs     # regenerate the lab CA and leaves
python tools\lab_capture_toolkit.py capture   # needs Administrator + Npcap loopback
python tools\lab_capture_toolkit.py verify    # analyse and compare with expectations
```

`verify` needs neither Administrator rights nor a live capture, and it prints one
line per capture:

```text
OK      imaps-tls10-legacy
        IMAP:993 TLS 1.0 TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) risk=81 class=CRITICAL posture=19 ml=CRITICAL
        findings: ['DEPRECATED_TLS_VERSION:CRITICAL', 'LEGACY_CBC_CIPHER:MEDIUM', 'NO_FORWARD_SECRECY:MEDIUM']
```

Current status of the shipped set: **9/9 captures behave as expected**.

On Linux the capture step needs elevated rights (`sudo -E python ...`) because
binding 25/110/143 and capturing the loopback interface require them.

If a scenario cannot be created on your machine - for example an OpenSSL build
without the NULL cipher - the toolkit falls back to the next closest weak profile
and writes the substitution into `capture_log.json`. It never silently produces a
capture that does not match its label.

---

## 4. Demo script for the judges (about 4 minutes)

1. **Health and scope** - `GET /api/v1/health` shows `tshark_available: true`,
   `ml_model_available: true`. Say the scope out loud: *"SMTP, IMAP and POP3
   traffic only; we never decrypt or read mail content."*
2. **Upload the healthy baseline** - `samples\lab\smtp-starttls-secure.pcapng`.
   Show: STARTTLS advertised, command seen, accepted, upgrade successful, TLS 1.2
   from `SERVER_HELLO`, ECDHE with forward secrecy, certificate valid and matching,
   **risk 0, posture 100, no findings**.
3. **Upload the plaintext login** - `samples\lab\imap-cleartext-login.pcapng`.
   Show the CRITICAL `PLAINTEXT_AUTHENTICATION` finding and the recommendation.
   Point out the session *also* upgraded successfully - the exposure still counts.
4. **Upload the rejected upgrade** - `samples\lab\smtp-starttls-rejected.pcapng`.
   Show `STARTTLS_REJECTED` (HIGH) plus `PLAINTEXT_AUTHENTICATION` (CRITICAL).
5. **Upload the legacy IMAPS capture** - `samples\lab\imaps-tls10-legacy.pcapng`.
   Show `DEPRECATED_TLS_VERSION`, `NO_FORWARD_SECRECY`, `LEGACY_CBC_CIPHER`,
   posture 19/100.
6. **Upload the weak certificate capture** - `samples\lab\smtps-weak-certificate.pcapng`.
   Show the certificate panel: CN, issuer, RSA 1024, expired, hostname mismatch. This is the capture that proves certificate analysis works, because
   in TLS 1.3 the certificate is encrypted and therefore invisible.
7. **Upload the TLS 1.3 capture** - `samples\lab\imaps-tls13-cert-hidden.pcapng`.
   Show that the certificate section reports `UNKNOWN` with an INFO finding, and
   say: *"missing evidence is never reported as insecure."* Judges remember this.
8. **Upload the NTRO-style aggregate** - `samples\The-Ultimate-PCAP.pcapng`.
   The summary appears in about 3.5 seconds: 51 mail sessions, 13 TLS,
   38 cleartext, 8 STARTTLS requests, 13 successful upgrades, mixed risk classes.
9. **Reports** - download the JSON, HTML and PDF report for one weak capture.
10. **ML** - open the `ml` block of a session: risk class, confidence, anomaly
    score, and the explanation list. Say: *"the rule engine is auditable, the ML
    layer adds pattern-based risk; both are shown, and the report states which one
    is evidence-based."*

---

## 5. Honest limits of this lab set

Say these out loud if a judge probes:

- The captures are **lab traffic between two local processes**, not production
  mail traffic. They prove the detection logic, not field accuracy.
- The weak configurations are **requested by the toolkit** (`@SECLEVEL=0`). A real
  2015-era server would negotiate them for other reasons.
- The private CA means **trust-anchor validation is out of scope** for a passive
  capture; the tool reports chain completeness and identity, not trust.
- **SHA-1 signatures** could not be produced with the `cryptography` build used here, so the
  weak leaf is signed with SHA-256 and the toolkit reports that in
  `samples\lab\certificate_facts.json`. `WEAK_CERTIFICATE_SIGNATURE` therefore does not fire in this
  set; everything else about the certificate scenario (1024-bit key, expiry, hostname mismatch) does.
- Two conditions could not be produced with the OpenSSL build used here: **3DES**
  and **RC4** suites are unavailable even with the legacy provider. The NULL
  cipher, TLS 1.0, CBC and static RSA scenarios cover the same code paths, and the
  cipher table already contains the 3DES/RC4/EXPORT entries so those captures can
  be added later on a build that supports them.
- The ML model must be retrained after this update (`python -m app.ml.train`). Until
  then the API reports `ml_model_status: stale` in `/api/v1/health`, does **not**
  load the old model, and uses the rule result so the report cannot contradict
  itself. `python scripts\self_check.py` prints
  `ML classification agrees with the rule engine - 69/69 sessions` once retrained.
- **No MITM or downgrade claim is made anywhere.** A passive capture cannot prove
  one. `imaps-tls10-legacy` shows a weak configuration that would make a downgrade
  attractive, which is a different statement.
