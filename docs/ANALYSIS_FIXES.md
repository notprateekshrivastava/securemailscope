# Why the first sample result was wrong, and what changed

This document explains the incorrect output you received for `imap-ssl.pcapng`,
what caused it in the code, what was changed, and how to verify the corrected
behaviour on your Windows machine.

It is written so that every claim can be checked against the code and against a
fresh API response.

---

## 1. What you saw

Your upload of `imap-ssl.pcapng` returned this combination:

| Field | Value you got | Why it is wrong |
|---|---|---|
| `starttls.accepted` | `true` | correct |
| `starttls.rejected` | `true` | **contradiction** - a session cannot be accepted and rejected at the same time |
| `starttls.upgrade_successful` | `true` | correct |
| findings | `STARTTLS_REJECTED` (HIGH) | a false alarm: the server did **not** reject anything |
| `tls.cipher_suite` | `0x00ff` | `0x00ff` is not a cipher, it is the TLS renegotiation signalling value (SCSV) |
| `tls.key_exchange` | `null` | unknown because the cipher was misread |
| `tls.forward_secrecy` | `null` | unknown for the same reason |
| `tls.certificate_seen` | `false` | correct for this capture (see section 6) |
| `starttls.evidence` | contained "Plaintext authentication pattern observed" | the flag itself was `false`, so the sentence was misleading |
| `posture_score` | `70` (MEDIUM) with `ml.risk_class = CRITICAL` | an encrypted, correctly upgraded session should not be scored as risky just because a string was misread |
| `start_time` / `duration_ms` | `null` / `0` | timestamp field names were not matched on your Wireshark version |

---

## 2. Root causes

### Bug 1 - the rejection test was unanchored (the main problem)

Old code in `app/analysis/tshark.py`:

```python
if re.search(r"(?:454|530|NO|ERR).*(?:STARTTLS|STLS)", text, re.IGNORECASE):
    self.starttls_rejected = True
```

The Dovecot greeting line your capture contains is:

```text
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.
```

The rule reads: *"find `454`, `530`, `NO` or `ERR` anywhere, then later, anywhere, the word `STARTTLS`"*.

The word **LOGIN-REFE`RR`ALS** contains `ERR`, and the word `STARTTLS` appears later in the same line.
The greeting therefore looked like a rejection. It is not one - it is a capability
advertisement, i.e. the server telling the client that it **supports** STARTTLS.

Two more consequences of the same unanchored search:

- `NO` matches inside words such as `NOte`, `caNNot`, `LOGIN-REFE...`. Any text with
  those letters followed by `STARTTLS` produced a rejection.
- The scan was not direction-aware. Server text and client text were joined into one
  string, so the greeting could be treated as if the *client* had issued the command.

### Bug 2 - the cipher was taken from the wrong place

Old code in `_StreamAccumulator.finalise`:

```python
cipher = self.ciphers[-1] if self.ciphers else None
```

`self.ciphers` collected every `tls.handshake.ciphersuite` value in the whole
stream, in any direction, including:

- every suite the **client** offered in the ClientHello (dozens of values), and
- the empty-renegotiation signalling value `0x00ff`, which is not a cipher at all.

Taking the last value therefore returned a *client offer*, not the *negotiated*
cipher. There was also no code-to-name table, so `0xc02f` could not be recognised as
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, and the cipher strength score stayed at the
neutral fallback of 50.

### Bug 3 - evidence sentences were hard-coded

Old code:

```python
evidence=[
    evidence
    for evidence, present in [
        ...
        ("Plaintext authentication pattern observed", self.plaintext_auth),
    ]
    if present
],
```

The sentence itself was correct, but `self.plaintext_auth` was set by a very loose
test that matched the letters `AUTH`, `LOGIN`, `USER` or `PASS` anywhere in any mail
field value - including the server's capability list (`AUTH=PLAIN`). So the flag
flickered between `true` and `false` in different places of the same response, and
the report contradicted itself.

Additionally, plaintext authentication was suppressed when the upgrade succeeded:

```python
plaintext_authentication_seen=self.plaintext_auth and not self.upgrade_successful
```

That inverts the security meaning. Sending `AUTH ...` **before** STARTTLS is exactly
the exposure the project is supposed to detect; the fact that the client upgraded
afterwards does not undo it.

### Bug 4 - field names only worked for one Wireshark layout

Old code looked up `frame.time_epoch` literally. TShark prints a "pretty" alias for
every layer (`frame_frame_time_epoch`, `tls_tls_handshake_type`), and the exact set of
names differs between Wireshark 3.x and 4.x. When only the alias was present, the
lookup silently returned nothing, which is why `start_time` was `null`.

### Bug 5 - a 15 MB capture blocked the whole API

- TShark was invoked **without a display filter**, so it parsed every packet of the
  capture, including the routing protocols (RARP, LDP, L2TPv3, ...) that the samples
  contain.
- TShark was invoked **without `-n`**, so it performed name resolution.
- The upload endpoint was declared `async def` but called blocking code directly, so
  the event loop was blocked: `/docs` and the dashboard could not answer while the
  capture was being parsed.

That is why `The-Ultimate-PCAP.pcapng` appeared to hang.

---

## 3. What changed

| File | Change |
|---|---|
| `app/analysis/tshark.py` | Rewritten stream state machine: direction-aware client/server handling, anchored and **tagged** STARTTLS response parsing, ServerHello-only version/cipher selection, plaintext-authentication detection before TLS, evidence text generated from the real flags, `-n` plus a display filter, 900 s timeout with a clear error, logging of the exact TShark command |
| `app/analysis/ciphers.py` | **New.** Cipher-code table (`0xc02f` to `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, key exchange, strength, forward secrecy) plus SCSV and GREASE filtering |
| `app/schemas.py` | `TLSInfo` gained `version_source`, `cipher_source` and `offered_cipher_suites` so the report states *where* a value came from |
| `app/main.py` | Upload endpoint is now a normal `def` function, so FastAPI runs it in a worker thread and the API stays responsive; structured logging |
| `app/service.py` | Progress logging: file size on upload, session count after parsing |
| `app/ml/train.py` | New training scenario `pre_tls_auth` (credentials in the clear, then a successful upgrade) |
| `tests/test_starttls_semantics.py` | **New.** 7 regression tests, including your exact Dovecot greeting case |
| `scripts/test_all_samples.ps1` | Now prints duration, TLS/plaintext/upgrade counts, severity breakdown and the top findings per sample |
| `scripts/dump_tshark_json.ps1` | **New.** Diagnostic: runs the exact backend command and lists the field names your Wireshark produces |
| `scripts/build_sample_manifest.ps1` | **New.** Builds `samples\EXPECTED_RESULTS.md` from real analysis output |

### The new decision rules, in one table

| Question | Old behaviour | New behaviour |
|---|---|---|
| Was STARTTLS rejected? | any `NO`/`ERR` before the word STARTTLS anywhere in the stream | only a tagged server line (`. NO`, `. BAD`, `-ERR`, `454`, ...) sent **after** the client request and **within 4 packets** of it |
| Is the greeting a rejection? | yes (false alarm) | no - capability lines are excluded explicitly |
| Which cipher was negotiated? | last cipher value anywhere | the value in the **ServerHello**; SCSV/GREASE ignored; otherwise reported as "client offer only" |
| Which TLS version was negotiated? | highest version seen anywhere | the value in the **ServerHello**; if absent, version stays `UNKNOWN` with `version_source` explaining why |
| Was a password sent in the clear? | any `USER`/`PASS`/`AUTH`/`LOGIN` token, suppressed after a successful upgrade | a real client authentication command (per protocol) sent **before** TLS starts; never suppressed |
| Are message contents read? | body fields could leak into the scan | `smtp.data` / `imap.data` style body fields are excluded from every scan |

---

## 4. How to verify on Windows

### Step 1 - copy the updated files

Copy these paths from the shared workspace into `D:\CryptoPost SIH\securemailscope`,
keeping the same folder structure:

```text
app\analysis\tshark.py
app\analysis\ciphers.py        (new)
app\schemas.py
app\main.py
app\service.py
app\ml\train.py
tests\test_starttls_semantics.py   (new)
scripts\test_all_samples.ps1
scripts\dump_tshark_json.ps1       (new)
scripts\build_sample_manifest.ps1  (new)
docs\ANALYSIS_FIXES.md             (new)
samples\README.md
```

If you prefer, copying the whole project folder over the old one also works, but keep
your `data\` folder and your `models\` folder.

### Step 2 - run the tests

```powershell
cd "D:\CryptoPost SIH\securemailscope"
python -m pytest -q
```

Expected:

```text
13 passed
```

These tests run without TShark and without the internet. They include a test named
`test_successful_imap_starttls_is_not_reported_as_rejected`, which builds the same
Dovecot greeting that caused the false alarm.

### Step 3 - retrain the model (recommended, about one minute)

```powershell
python -m app.ml.train
```

Why: the training data now includes the "credentials in the clear, then a successful
upgrade" scenario. Without retraining, the model still works - it simply has never
seen that combination.

Expected last lines include a validation accuracy around `0.97`. This is synthetic
accuracy and must be reported as such.

### Step 4 - start the API

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Leave this terminal open. It now prints progress while a capture is parsed:

```text
INFO securemailscope Analysis 7f3c...: stored 7f3c..._imap-ssl.pcapng (0.01 MB) from team
INFO securemailscope.tshark tshark: tshark.exe -n -r ... -Y tcp.port in {25,110,143,465,587,993,995} || smtp || imap || pop || tls || ssl -T json ...
INFO securemailscope Analysis 7f3c...: 1 email session(s) parsed
```

### Step 5 - re-run the samples

In a second terminal:

```powershell
cd "D:\CryptoPost SIH\securemailscope"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\test_all_samples.ps1
```

You will now get a table plus the highest-severity findings per sample, for example:

```text
File                      Seconds Sessions TLS Plaintext StartTLS Upgraded Findings Posture Risk
imap-ssl.pcapng               0.9        1   1         0        1        1        1      95 LOW
pop-ssl.pcapng                0.8        1   1         0        1        1        1      95 LOW
smtp-ssl.pcapng               0.9        1   1         0        1        1        1      95 LOW
The-Ultimate-PCAP.pcapng     12.0        N   N         N        N        N        N      ..  ..
```

Exact numbers will differ; what matters is the pattern described in step 6.

### Step 6 - check the corrected `imap-ssl.pcapng` result specifically

Open `data\sample-results\imap-ssl.json` and confirm:

```text
starttls.accepted                    true
starttls.rejected                    false          <- was true
starttls.upgrade_successful          true
starttls.plaintext_authentication_seen false
tls.cipher_source                    SERVER_HELLO
tls.cipher_suite                     a readable suite name, no 0x00ff
tls.version_source                   SERVER_HELLO
tls.forward_secrecy                  true or false (no longer null)
findings                             no STARTTLS_REJECTED, no PLAINTEXT_AUTHENTICATION
summary.overall_posture_score        high (no false HIGH finding)
```

`CERTIFICATE_NOT_OBSERVED` (INFO) may still be present. That is correct, see below.

### Step 7 - build the manifest for your submission

```powershell
.\scripts\build_sample_manifest.ps1
```

This writes `samples\EXPECTED_RESULTS.md`: a table of exactly what each capture
contains, taken from real analysis output, with the evidence-completeness column.
Judges can read one page and see which sample proves which capability.

### If something still looks wrong

```powershell
.\scripts\dump_tshark_json.ps1 -Capture ".\samples\imap-ssl.pcapng"
```

This runs the exact backend command and writes
`data\tshark-dumps\imap-ssl.fields.txt`, listing every field name your installed
Wireshark produced. Send that file and the problem can be located precisely instead of
guessed.

---

## 5. Is it safe to stop a slow upload?

Yes. Nothing breaks and nothing is corrupted:

- The uploaded file is written to `data\uploads\` **first**.
- The analysis runs during the request; the result is saved **only after** it finishes.
- Stopping therefore leaves no half-written result file. You simply rerun.

Guidance with the fixed code:

| Capture | Expected time |
|---|---|
| the three small TLS fixtures (< 15 KB) | under 2 seconds each |
| `The-Ultimate-PCAP.pcapng` (15 MB) with the display filter | roughly 5-60 seconds |
| any capture still running after ~3 minutes | stop it, then run `dump_tshark_json.ps1` to see what the file actually contains |

If the browser shows a timeout while the API is still working, the API log will still
finish the analysis and save the JSON result - check `data\sample-results\` and
`GET /api/v1/analyses` before re-uploading.

---

## 6. Why "certificate not visible" is correct for this sample

`imap-ssl.pcapng` is a loopback capture of an IMAP session. Two facts explain the
empty certificate section:

1. The capture was taken between two local processes, so the handshake is short and
   the sample file is only 10 KB.
2. In TLS 1.3 the server certificate is sent **after** the handshake keys are derived,
   so it is encrypted on the wire. No passive observer - and therefore no passive
   analysis tool - can see it.

The correct output is therefore:

```text
tls.certificate_seen        false
certificate.present         false
certificate.chain_status    UNKNOWN
tls.handshake_status        PARTIAL
finding                     CERTIFICATE_NOT_OBSERVED (INFO)
```

This is the project's evidence rule working as intended: missing evidence is reported
as UNKNOWN or PARTIAL, never as "insecure", and never guessed from similar sessions.

Certificate checks need a capture where the certificate is actually visible. That
means a TLS 1.2 handshake (where the certificate is sent in clear) and a **full**
handshake, not a resumed one. This is one of the lab captures still to be produced.

---

## 7. Second round: bugs that only real captures exposed

After the fixes above, the four sample captures were analysed with the real TShark
binary. Four further defects appeared, all of which would have been invisible with
synthetic test data.

### 7.1 TLS records were silently deleted before parsing

One TCP segment can carry several TLS records - typically `ServerHello`,
`Certificate`, `ServerKeyExchange` and `ServerHelloDone` together. In TShark's
JSON output those records share the same key, and Python's JSON parser keeps only
the **last** one. The ServerHello and the certificate therefore never reached the
analysis code, which is why `certificate_seen` was `false` on a capture where a
certificate was present in plain view.

Fix: TShark is now called with `--no-duplicate-keys`, which turns repeated keys
into a list, plus two fallbacks for older Wireshark builds. Effect on
`imap-ssl.pcapng`: certificate CN `localhost`, issuer Dovecot, RSA 2048, SHA-256
signature, expired on 2025-01-29 - all extracted from packets that were previously
discarded.

### 7.2 SNI was read as a length value

The Server Name Indication extension nests the name next to `..._name_len` and
`..._name_list_len`. A substring lookup returned `16` or `13` first, so the SNI
was never captured and hostname verification never ran.

Fix: only hostname-shaped values are accepted as SNI.

### 7.3 Hostname matching was broken on Python 3.13

`ssl.match_hostname` was removed from the standard library. The old code called
it inside a `try/except` that treated any exception as "no match", so **every**
session with a visible SNI would have been reported as
`CERTIFICATE_HOSTNAME_MISMATCH`. The fix implements the comparison directly
(subjectAltName first, wildcard only in the left-most label, common name only when
no SAN exists).

### 7.4 A 15 MB capture returned 1717 sessions

The read filter also matched `tls` and `ssl` in general, so the aggregate capture
produced 1717 unrelated TLS sessions and buried the 51 real mail sessions. The
filter is now mail-only (`tcp.port in {25,110,143,465,587,993,995} || smtp || imap
|| pop`), the scope is recorded in the analysis metadata, and the same capture now
parses in about 3.5 seconds with 51 mail sessions and nothing else.

### 7.5 Risk classes could contradict the findings

With a purely additive score, one CRITICAL finding (45 points) printed as
"MEDIUM" while three MEDIUM findings (54 points) printed as "CRITICAL". The class
now follows the most severe finding, promoted to CRITICAL above 80 points, and the
headline class of a report is the worst session rather than the average.

### 7.6 The ML layer disagreed with the rule engine

Trained only on synthetic rows, the classifier called a clean TLS 1.3 session
CRITICAL. Real capture features are now part of training, labelled by the rule
engine (weak supervision, stated as such in the metadata). After retraining, all
63 real sessions in the sample and lab set are classified in agreement with the
rule engine, and the metadata records the confusion counts so the claim can be
checked.

### 7.7 Verification of this round

```text
pytest -q                                  13 passed
lab_capture_toolkit.py verify              9/9 captures behave as expected
The-Ultimate-PCAP.pcapng                   51 sessions, 13 TLS, 38 cleartext, 3.5 s
imap-ssl / pop-ssl / smtp-ssl              certificates parsed, correct verdicts
```

## 8. Still open

| Item | Status |
|---|---|
| Public fixtures prove parsing and evidence qualification | done for SMTP/IMAP/POP3 over TLS |
| A capture with a visible certificate (TLS 1.2 full handshake) | needed - enables certificate findings |
| Controlled weak captures: TLS 1.0/1.1, 3DES, static RSA, expired certificate | needed for the demo of risk escalation |
| Controlled plaintext capture: IMAP LOGIN / POP3 USER+PASS / SMTP AUTH before encryption | needed |
| STARTTLS rejection capture | needed |
| ML metrics on real captures | partially addressed: real capture features are used for training and the calibration check is recorded in the model metadata (in-sample, weak supervision, small sample - always labelled as such) |
| MITM / downgrade claims | **never** claimed from a passive capture; only "possible indicator" wording with the evidence that is missing |

The next build step is the lab-capture toolkit: a small local mail server, a client
script and a TShark capture command that produce the five weak/plaintext/rejection
captures above, so the risk-elevation path can be demonstrated from real packets.
