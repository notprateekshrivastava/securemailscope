# Files changed - copy this list

## Latest update: 2026-09-28a - the interface: dashboard redesign + PDF/HTML report rebuild

**Use `securemailscope_update_2026-09-28a.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, replace, restart the API, hard-refresh the browser
(Ctrl+F5 - the page is cached).

| File | What changed |
|---|---|
| `app\reports.py` | **Rewritten.** The PDF overlap is fixed at the root: every table cell is now a wrapping `Paragraph` and column widths are derived from the page frame, so text can no longer run over the next column and the table can never be wider than the paper. The document is now a report: metric strip, severity distribution with a plain-English line per band, capture facts, prioritised findings, sessions highest-risk-first, numbered actions, and a closing statement of what it does not claim. The HTML report shares the same palette and structure. Both share one palette constant with the dashboard |
| `app\dashboard.py` | **Redesigned, same features.** Verdict band with a posture ring, four tabs (Overview / Findings / Sessions / Actions), one filter box that narrows both findings and sessions, session rows expand in place, ML disagreement marked instead of hidden, and a "no mail sessions" state that is distinct from "low risk". Still one file, inline CSS and vanilla JS, nothing from the internet |
| `tests\test_dashboard.py` | 12 tests (was 9). **New: the inline JavaScript is parsed** - a syntax error in it still returns HTTP 200 and still passes every string test, which is how one reached a screenshot. Also: the script really calls each documented endpoint, and the ML disagreement marker exists |
| `docs\screenshots\` | **New.** Six dashboard screenshots, two sample PDFs, a sample HTML report, and `dashboard_offline_snapshot.html` - the whole dashboard in one file with the analyses embedded, for the slide deck |
| `docs\DESIGN.md` | **New.** The design decisions, the two PDF bugs and their fixes, the honesty rules, and the shared colour tokens |
| `requirements-dev.txt` | `esprima` added - it is the test-only parser for the dashboard JavaScript |
| `README.md` | Points at the design notes and the screenshots directory |

**Verified:** 49 tests passed (was 46), `self_check` 33/0, lab verify 15/15, and the reports were
rendered and inspected page by page - `docs\screenshots\report_pdf_ultimate.pdf` is the one to
look at first.

---

# Files changed - earlier rounds

## Latest update: 2026-09-27h - why two machines showed different ML numbers

**Use `securemailscope_update_2026-09-27h.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, then **run `python -m app.ml.train` before scoring** -
that command is the whole point of this update.

| File | What changed |
|---|---|
| `tools\score_testset.py` | **New MODEL WARNING.** Before scoring, it checks whether any capture the model should have learned from is newer than the model file. If it is, it prints a warning, repeats it at the top of `RESULTS.md` with the numbers both ways, and marks the console figure as coming from an out-of-date model |
| `docs\SCALE_AND_ML.md` | New section in 3.4: the same test set scored with two models, side by side |
| `docs\TRAINING_PLAYBOOK.md` | The rule this taught us, with the measured table, right where a reader looks for traps |
| `docs\SUBMISSION_CHECKLIST.md`, `README.md` | A judge-facing answer for "why is your ML agreement different on my machine?" |

**What happened.** The same held-out test set was scored on two machines and gave different
ML agreement - 987/1116 (88.4%) and 1073/1116 (96.1%). Reproduced here exactly, and the cause
is one thing: the model on the first machine was trained **before `samples\sweep` existed**
(69 capture rows instead of 90). Every rule-based check was 100% on both machines - only the
triage layer differed.

| Disagreement | Out-of-date model | Current model |
|---|---|---|
| `imap_cleartext_login` (rules CRITICAL, ML HIGH) | 43 sessions | 43 sessions |
| static-RSA sessions (rules MEDIUM, ML CRITICAL) | **86 sessions** | **0 sessions** |

The older model had never seen a static-RSA session and over-warned on 86 of them. This is
the clearest measured justification for the coverage sweep in the project: on held-out
captures it removed a systematic false alarm across 86 sessions and cost nothing.

**Action on the Windows machine** (one command, then re-score):

```powershell
python -m app.ml.train
python tools\score_testset.py --dir testset
```

If `samples\sweep` is missing, get it from the bundle, or regenerate it - no administrator
rights needed on Windows:

```powershell
python tools\lab_capture_toolkit.py sweep
```

**Verified:** pytest 46 passed, `self_check` 33/0, lab verify 15/15, test set 1,116/1,116 on
every rule-based check with ML agreement 1,073/1,116 (96.1%).

---

# Files changed - earlier rounds

## Latest update: 2026-09-27g - a held-out test set, and the two bugs it found

**Use `securemailscope_update_2026-09-27g.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, replace, then `python -m app.ml.train` once.
The test set is measurements, not training data: do not add `testset\` to `CAPTURE_DIRS`.

| File | What changed |
|---|---|
| `testset\` | **New: 27 captures, 1,116 sessions, 50 distinct (protocol, port, mode, profile) situations, plus `ground_truth.json` (expectations declared before capture), `EXPECTED.md`, `README.md` and `RESULTS.md` (the measurement). Covers IMAP STARTTLS upgraded/refused, POP3 STLS upgraded/refused, SMTP with no STARTTLS offered, mixed-port and mixed-protocol files, and a 6.4 MB / 1,040-session file for scale |
| `tools\lab_capture_toolkit.py` | **New `testset` subcommand.** New protocol modes that did not exist: `imap_starttls`, `imap_reject_starttls`, `pop3_stls`, `pop3_reject_stls`, `pop3_plaintext`, `smtp_no_starttls`. Implicit-TLS captures now exchange a real mail session inside the tunnel instead of only the handshake. STARTTLS/STLS upgrades now send SNI, so certificate hostname matching is evaluable on the upgrade path as it is under implicit TLS. Refused STLS is now actually refused. Writes a folder README |
| `tools\score_testset.py` | **New.** Scores the analyzer and the ML layer against the declared expectations: session reconstruction, declared findings, findings that must NOT appear, TLS facts, risk class against the declared policy band, and ML-vs-rules agreement. Writes `RESULTS.md` with a per-situation observed table and every failure named |
| `app\analysis\tshark.py` | **Two defects fixed, both found by the test set.** (1) The vocabulary fallback now always runs and merges with the port-convention pass, so a capture mixing standard and unusual ports keeps both - before, 21 of 26 sessions in one file were silently dropped. (2) `discover_mail_ports` now returns every protocol that greeted from an unusual port, not only the first |
| `scripts\run_testset.ps1` | **New.** Generates the test set if missing, scores it, prints where the detail is. Windows, no administrator rights needed |
| `tests\test_testset_isolation.py` | **New, 4 tests.** The test set cannot become a training folder, the scanner must not return its captures, every declared session must carry an expectation, and every TLS profile must declare both what it must show and what it must forbid |
| `tests\test_unknown_ports.py` | Two tests: a mixed-port capture keeps both port families, and discovery returns both greeting ports. The old test that asserted the (wrong) single-pass behaviour was replaced |
| `scripts\self_check.py`, `tests\test_starttls_semantics.py`, `tests\test_tshark_parser.py` | Stubs updated for the new pass signature (TShark is stubbed in tests, so nothing here needs Wireshark) |
| `docs\SCALE_AND_ML.md` | New section 3.4: the test set, the two defects and their fixes, the measured result table, and what it does not prove |
| `docs\TRAINING_PLAYBOOK.md`, `docs\SUBMISSION_CHECKLIST.md`, `README.md` | How to run the test set, the rule that it is never training data, and a judge-facing row with the numbers |

**Measured result** (`python tools\score_testset.py --dir testset`): 1,116/1,116 sessions
reconstructed; every declared finding reported; **no finding invented** anywhere in 1,116
sessions; TLS version, cipher, certificate visibility and forward secrecy all as configured;
risk class inside the declared band in every case; ML agreeing with the rules 1,073/1,116 =
**96.1%**, with all 43 disagreements in one situation (`imap_cleartext_login`: rules
CRITICAL, ML HIGH).

**Verified:** pytest 46 passed, `self_check` 33/0, lab verify 15/15.

---

# Files changed - earlier rounds

## Latest update: 2026-09-27f - systematic sweep, and the honest accuracy answer

**Use `securemailscope_update_2026-09-27f.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, replace, then `python -m app.ml.train` once.

Driven by the rubric line about sample size ("publish the in-sample and holdout scores").
Both were already published; this round makes the sample bigger.

| File | What changed |
|---|---|
| `tools\lab_capture_toolkit.py` | **New `sweep` subcommand:** captures the full protocol x port-family x TLS-profile matrix (3 x 2 x 7 = **42 captures**), with the expected findings per profile declared up front so a profile that stops producing its weakness is caught instead of trained on. Skips privileged ports with an explicit message instead of writing empty captures |
| `samples\sweep\` | **New.** 42 captures + `capture_log.json` + `SWEEP_RESULTS.md` (verified: 21 behave exactly as expected, 21 UNCLASSIFIED on high ports, by design) |
| `app\ml\train.py` | `CAPTURE_DIRS` includes `samples\sweep` when it exists, so a checkout without it trains exactly as before |
| `models\model_metadata.json` | Retrained: **90 rows, 40 captures with sessions**; calibration 90/90, holdout **82/90**, transfer **78/90** |
| `docs\SCALE_AND_ML.md` | Rewritten accuracy section: in-sample vs holdout side by side, majority-class baseline (**48.9%**), both confidence intervals, the honest decomposition of the 91.1%, the **"why not 95%"** analysis, and the single error that under-warns. New Idea C documenting the sweep |
| `docs\SUBMISSION_CHECKLIST.md`, `docs\TRAINING_PLAYBOOK.md`, `README.md` | Every figure refreshed to 91.1% holdout / 86.7% transfer / 48.9% baseline, with the "±6 points, so 95% is inside the interval" wording |

**Answer to "should we train with more data?" - measured, not guessed.** More *rows* changed
nothing (5,000 -> 20,000 synthetic left the holdout at 53/63). 42 more *captures* moved the
reported holdout from 87.0% to 91.1%, of which the honest portion is the curated set going
61/69 (up one row); the rest is a near-twin measurement effect, disclosed rather than hidden.
The sweep also improved class balance and fixed one real error.

**Verified:** pytest 41 passed, `self_check` 33/0, lab verify 15/15, unseen-capture test
6/11 + 5 unclassified + 0 crashes.

---

# Files changed - earlier rounds

## Latest update: 2026-09-27e - scale files, and two defects found by measuring them

**Use `securemailscope_update_2026-09-27e.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, replace, then `python -m app.ml.train` once.

| File | What changed |
|---|---|
| `tools\make_stress_capture.py` | **New.** Builds large captures from the lab set (`--repeat N`), using `editcap`/`mergecap` from Wireshark, with time-shifted repetitions so the file reads as one long recording. Refuses to write into `samples\lab` and states that stress captures are **not training data** |
| `samples\stress\medium.pcapng` | **New.** 1.49 MB, 300 sessions, 560 findings - parsed in 11 s |
| `samples\stress\large.pcapng` | **New.** 14.72 MB, 3,000 sessions, 5,600 findings - parsed in 105 s |
| `app\main.py` | `GET /api/v1/analyses` gains **`?summary_only=true`**: the full list returned **16.6 MB** for eight stored captures, the light one **0.01 MB** and keeps every summary field |
| `app\dashboard.py` | Uses `summary_only`; caps the session table at the 200 highest-risk sessions with a visible note; shown in the same commit as the unclassified/no-session states |
| `app\reports.py` | The PDF lists the 40 most severe findings and now **says so** (`Showing the 40 most severe of 5,600 finding(s)`), pointing at the HTML/JSON reports for the full set. A silent cap looks like lost evidence |
| `FRONTEND_API.md` | Rewritten for integration: `summary_only`, the measured upload durations (24 s and 236 s - so the frontend must allow long timeouts), the failure-response table, and the two fields that must be displayed instead of a green score |
| `docs\INTEGRATION_PLAN.md` | **New.** Verdict, the two frontend paths, the five calls, five non-negotiable frontend rules, the four-minute demo script with fallbacks, the integration checklist, and the honest assessment of the live-agent idea |
| `docs\SCALE_AND_ML.md` | New measured table for the stress captures, including what the measurement changed |
| `tests\test_unknown_ports.py`, `tests\test_dashboard.py` | Three new tests: `summary_only` keeps summaries and drops the heavy parts, the table cap is present and explained, and the PDF states its truncation |

**Measured live through the running API:** medium 300 sessions in **24 s**; large 3,000
sessions in **236 s**; reports for the large capture JSON 17.9 MB / HTML 1.4 MB / PDF 7 KB,
all under a second; throughput about **28 sessions per second** on two cores.

**Verified:** pytest **41 passed**, `self_check` 33/0, lab verify **15/15**, unseen-capture
test 6/11 + 5 unclassified + 0 crashes.

---

# Files changed - earlier rounds

## Latest update: 2026-09-27d - prototype hardening from a live end-to-end test

**Use `securemailscope_update_2026-09-27d.zip`.** Extract into
`D:\CryptoPost SIH\securemailscope`, replace, then `python -m app.ml.train` once.

I started the real server and drove the whole upload path. It works, and it exposed three
things a reviewer would have seen before we did:

| File | What changed |
|---|---|
| `app\service.py` | Fixed the same false all-clear that was fixed in the CLI, but in the layer the dashboard reads: an unclassifiable capture used to return `0 sessions, posture 100, LOW`. It now carries `unclassified_streams` + `unclassified_note`. Empty uploads are refused (`422 The uploaded file is empty`), and a file with no readable packets is refused instead of being scored |
| `app\schemas.py` | `AnalysisResult` gains `unclassified_streams` and `unclassified_note` |
| `app\dashboard.py` | Three distinct states instead of one misleading one: scored sessions show class + posture; encrypted-but-unidentifiable shows an **UNCLASSIFIED** badge with a banner listing each stream (port, TLS version and its source, SNI, certificate visibility); nothing to score shows a neutral **NO MAIL SESSIONS** badge and `posture n/a` instead of a green `LOW 100/100` |
| `app\analysis\unclassified.py` | New `count_readable_packets()` so an empty/truncated file is distinguishable from a capture that simply holds no mail |
| `tests\test_unknown_ports.py`, `tests\test_dashboard.py` | Four new tests: the API carries unclassified streams, a normal capture is untouched by the diagnostic, and the dashboard never promises a score for a capture it could not score |
| `docs\RUN_BACKEND.md` (new section I table), `docs\SUBMISSION_CHECKLIST.md` (2 new judge answers) | The three upload outcomes and the measured end-to-end timings |

**Measured live, through the running API** (2 CPU cores, sandbox TShark 4.4.18): health 0.4 s;
lab capture upload+analyse 0.4 s; 15 MB / 51-session capture 5.3 s; JSON report instant;
HTML instant; PDF 0.12 s and starts with `%PDF`; two concurrent uploads 0.44 s; 404/400/422
paths all return clear messages; the dashboard loads **no external resources** so it works
on an air-gapped machine.

**Verified after the change:** pytest **38 passed**, `self_check` **33 passed / 0 failed**,
lab verify **15/15**, unseen-capture test **6/11 + 5 unclassified + 0 crashes**.

---

# Files changed - earlier rounds

## Latest update: 2026-09-27c - POP3S coverage, and the training measurements

**Use `securemailscope_update_2026-09-27c.zip`.** Extract it into
`D:\CryptoPost SIH\securemailscope`, replace existing files, then run
`python -m app.ml.train` once. What changed and why:

| File | What changed |
|---|---|
| `tools\lab_capture_toolkit.py` | **Six new scenarios** (9 -> 15): `pop3s-tls10-legacy`, `pop3s-weak-certificate`, `pop3s-cbc-cipher`, `smtps-cbc-cipher`, `smtps-tls13-modern`, `imaps-weak-certificate`. Every one is a (protocol, port, profile) combination that did not exist before, so no existing capture changed. POP3 previously had no encrypted scenario at all |
| `samples\lab\` | **Six new captures**, 15 in total, plus a refreshed `capture_log.json` and `EXPECTED_RESULTS.md`. Verified **15/15 behave as expected** |
| `docs\TRAINING_PLAYBOOK.md` | **New.** The training method, the measured answer to "what makes the model better", the five-level test ladder, the Kaggle rules (what to publish, what never to train on), and the day-by-day plan to the deadline |
| `docs\SCALE_AND_ML.md` | New section 5 with the row-count experiment: 5,000 -> 20,000 synthetic rows left the holdout at **53/63**, unchanged. Updated to the current figures: 19 captures, 69 rows, holdout and transfer **60/69 (87.0%)** |
| `docs\LAB_CAPTURES.md` | The six new scenarios documented, with the reason each was added |
| `docs\SUBMISSION_CHECKLIST.md`, `docs\RUN_BACKEND.md`, `README.md` | All figures refreshed to 15 captures / 69 rows / 60-of-69. Stale numbers in a submission pack are worse than no numbers |
| `models\model_metadata.json` | Regenerated by training: `capture_holdout` and `synthetic_transfer` are now 60/69 on 19 captures |

Measured after the change: pytest **34 passed**, `self_check` **33 passed / 0 failed**, lab
verify **15/15**, unseen-capture test **6/11 with every expected finding, 5 unclassified,
0 crashes, rules vs ML 6/6**. The two remaining holdout misses are recorded honestly in the
playbook: `imap-cleartext-login` (CRITICAL predicted HIGH) and `smtp-starttls-secure`
(LOW predicted CRITICAL).

---

# Files changed - earlier round

## Latest update: 2026-09-27b - captures on unfamiliar ports

**Use `securemailscope_update_2026-09-27b.zip` (about 315 KB, 107 files).** The exact size and sha256
are printed by the build command and quoted in the message that accompanies the update.
Extract it into
`D:\CryptoPost SIH\securemailscope`, replacing existing files, then run
`python -m app.ml.train` once (the bundle never contains the trained model).

What this round changed, and why:

| File | What changed |
|---|---|
| `app\analysis\tshark.py` | **Mail traffic is now identified from the protocols' own vocabulary, not only from the port number.** A second pass searches for `EHLO`, `* OK`, `+OK`, `STLS` and similar words, then tells TShark to dissect those ports. Before this, a mail service on 8143, 2525 or 8110 produced an empty report. Also: the standard-port table is no longer a module-level constant used in five places - the per-capture port map is threaded through the stream state machine |
| `app\analysis\unclassified.py` | **New.** Reports encrypted streams that could not be attributed to a mail protocol, with port, negotiated TLS version (taken from the server's hello), SNI and certificate visibility - and states that the protocol inside cannot be proven. Implicit TLS on an unknown port has no vocabulary to read, so guessing would be inventing evidence |
| `app\cli.py` | `check` prints the unclassified-stream report when a capture yields no session, instead of the old silent "no sessions" |
| `app\analysis\batch.py` | A capture with no session but with encrypted streams is recorded as UNCLASSIFIED in the batch output, and no longer prints a perfect posture score next to an empty result |
| `tools\lab_capture_toolkit.py` | The harness now fails loudly instead of writing an empty capture: it checks the socket error **and counts packets carrying payload**, deleting the file when the conversation never happened. `variants` only captures each scenario on ports that are semantically valid for it (STARTTLS/STLS on 25, 587, 143, 110, 2525, 8143, 8110; implicit TLS on 465, 993, 995, 9465, 9993, 9995), skips privileged ports with an explicit message, and is privilege-aware per platform |
| `tools\capability_test.py` | **New.** Measures the analyzer on captures the model has never seen: expected findings, rules-vs-ML agreement, training-range verdict, and crashes. Writes `docs\CAPABILITY_TEST.md` and exits non-zero if any capture fails |
| `tests\test_unknown_ports.py` | **New.** 12 hermetic tests: vocabulary identification, that TLS ciphertext never looks like vocabulary, greeting-direction port naming, the second-pass behaviour, and that an out-of-range session is flagged |
| `tests\test_starttls_semantics.py`, `tests\test_tshark_parser.py`, `scripts\self_check.py` | Test stand-ins updated for the new optional port-map argument on the TShark runner |
| `samples\variants\` | **New.** 11 captures on ports absent from the training set, plus `capture_log.json` |
| `docs\CAPABILITY_TEST.md` | **New.** The generated result table, including what the training-range column means and when it may be quoted |
| `docs\SCALE_AND_ML.md` | New section 3.3: the false start (12 "successful" captures that were two-packet refusals), the real defect, the fix, the measured before/after, and the limit that remains |
| `docs\RUN_BACKEND.md`, `docs\SUBMISSION_CHECKLIST.md`, `README.md` | New `check` walkthrough, the unseen-capture procedure, four judge answers and a fifth known limit |
| `build_update_bundle.py` | Includes `samples\variants`; writes the `-b` archive |

Verified after the change: **34 pytest tests pass**, `scripts\self_check.py` **27 passed /
0 failed**, the nine lab captures still verify **9/9**, all 13 original captures keep exactly
their previous postures and session counts, and the unseen set measures **6 captures with
every expected finding, 5 honestly unclassified, 0 crashes, rules vs ML 6/6**.

---

# Files changed - earlier round

Everything below was changed in the shared workspace while fixing the incorrect
`imap-ssl.pcapng` result and hardening the engine against real captures.

## Easiest way to apply everything

Download `securemailscope_update_2026-09-27.zip` (164 KB, 69 files) and extract it
**into** `D:\CryptoPost SIH\securemailscope`, choosing "Replace the files in the
destination folder". Then follow "After copying" below.

The archive contains the complete project as it should be - all changed and new
files, the full folder structure, the docs, the scripts, the lab captures and the
regression tests. It deliberately does **not** contain:

| Not included | Why | What to do instead |
|---|---|---|
| `models\*.joblib` | generated from your own training run, so the metadata matches your machine | run `python -m app.ml.train` |
| `samples\The-Ultimate-PCAP.pcapng(.gz)` | 15 MB / 6 MB, already on your machine | keep your existing copies |
| `samples\lab\certs\*.key.pem` | disposable lab private keys | regenerate with `python tools\lab_capture_toolkit.py certs` if you recapture |

Everything else is in the archive, so nothing has to be copied file by file.

### The exact file list (if you prefer to copy by hand)

Copy these paths into `D:\CryptoPost SIH\securemailscope`, keeping the same
structure. Nothing requires editing an existing file by hand.

---

## Copy these files

### Changed application code (15)

| File | What changed | Why it matters |
|---|---|---|
| `app\analysis\tshark.py` | Rewritten TCP-stream state machine: direction-aware client/server handling, tagged STARTTLS answers, ServerHello-only version/cipher, cleartext-authentication detection before TLS, evidence text generated from the real flags, `--no-duplicate-keys`, mail-only read filter, `-n`, 900 s timeout, graceful fallbacks, logging | Fixes the false `STARTTLS_REJECTED`, the wrong `0x00ff` cipher, the lost ServerHello/certificate, the missing timestamps and the hanging 15 MB upload |
| `app\analysis\certificates.py` | Own RFC 6125 hostname matcher (Python 3.13 removed `ssl.match_hostname`), tolerant chain building, self-signed chain handling, no deprecation warnings | Hostname mismatch is now correct instead of always "mismatch", and certificate chains no longer come back as UNKNOWN |
| `app\analysis\constants.py` | `RISK_CLASS_BANDS`, `risk_class_from_score()`, `risk_class_from_findings()` | One shared definition of LOW/MEDIUM/HIGH/CRITICAL for the rule engine, the anomaly fallback and the training labels |
| `app\analysis\assessment.py` | Session class comes from the worst finding (promoted to CRITICAL above 80 points); report headline class is the worst session, not the average | A session with a CRITICAL finding can no longer be printed as "MEDIUM" |
| `app\analysis\rules.py` | New `CIPHER_NOT_RECOGNISED` INFO finding | An unknown cipher code is reported as unassessable instead of silently looking harmless |
| `app\schemas.py` | `TLSInfo` gained `version_source`, `cipher_source`, `offered_cipher_suites` | The report now states *where* every value came from (ServerHello, record layer, or client offer only) |
| `app\main.py` | Upload endpoint is a normal `def` (runs in a worker thread); structured logging | `/docs` and the dashboard stay responsive during a long analysis |
| `app\service.py` | Progress logging, and upload metadata now records the display filter and the analysis scope | You can see what the backend is doing and prove what scope was analysed |
| `app\ml\train.py` | Real-capture training rows labelled by the rule engine (weak supervision), per-capture caps, calibration summary in the metadata, schema fingerprint | The classifier now agrees with the rule engine on real captures instead of contradicting it |
| `app\service.py` | Every new result is stamped with `ANALYZER_VERSION` from `app\version.py` | A stored result now says which build produced it, so `clear_analyses.ps1` can find results made by an older build instead of exporting them next to correct ones |
| `app\reports.py` | The HTML and PDF headers now carry the analyzer version, the capture SHA-256 and the analysis time | A printed report is traceable to the exact bytes that produced it |
| `app\ml\train.py` | **The synthetic labeller no longer scores unobserved evidence as weakness**, and the two missing real-world scenarios (TLS with the certificate not on the wire, cleartext with no authentication seen) were added. `capture_repeat` default is now **2**, not 60, because 60 was measured to destroy generalisation. Leave-one-capture-out and synthetic-to-real transfer are now computed and stored on every training run | These three changes are what took honest generalisation from **14.3% to 85.7%**; the measurements are in `docs\SCALE_AND_ML.md` |
| `app\ml\model.py` | `MODEL_VERSION` is now `synthetic-v2` (the decision boundary changed, so a v1 model is refused as stale) | An old model cannot silently contradict the new code |
| `app\analysis\tshark.py` | **New `tshark_version()`** | The TShark version is recorded and shown by `doctor`; it is also the honest explanation for why one machine reports more "evidence not visible" INFO notes than another |
| `app\main.py` | **New route `GET /dashboard`** serving the interactive dashboard, and `/` now advertises it | The dashboard requirement is met by the backend itself: nothing to build, nothing to install, nothing loaded from the internet |
| `app\config.py` | `settings.version` comes from `app\version.py` | The API version, the report version and the stored version can never drift apart |
| `app\ml\model.py` | Schema fingerprint guard: a model trained with a different feature set or risk bands is **not loaded**; the rule result is reported instead, with the reason and the fix in the explanation | A stale model can never silently contradict the evidence in the same report |

### New application code (5)

| File | Purpose |
|---|---|
| `app\analysis\ciphers.py` | Cipher-suite knowledge base: code to name, key exchange, forward secrecy, strength, plus SCSV/GREASE filtering. Without it `0xc02f` is an unreadable number and `0x00ff` looks like a cipher |
| `app\version.py` | **New.** `ANALYZER_VERSION` (currently `1.0.0`) and its note. Bump it whenever a change alters analysis output |
| `app\analysis\batch.py` | **New.** Parallel directory-level analysis: one process per capture, results written as JSON Lines the instant each capture finishes, a flat CSV summary, a session feature table, `--resume`, per-file failure records, and bounded memory. This is the throughput path and the label factory |
| `app\cli.py` | **New.** `python -m app.cli batch\|export\|doctor\|verify` - batch analysis, feature-table inspection, an environment check, and a run summary |
| `app\dashboard.py` | **New.** The interactive dashboard: one self-contained HTML page with inline CSS and vanilla JavaScript. Upload with a source selector (user / ntro / team), analysis history, posture and severity panels, a session table where every row expands into the full TLS, certificate, STARTTLS and ML evidence, and JSON/HTML/PDF download buttons. Works with no network at all |

### Changed configuration / docs (4)

| File | What changed |
|---|---|
| `requirements-dev.txt` | New: `pip install -r requirements-dev.txt` installs pytest. It was never in `requirements.txt`, which is why `python -m pytest` reported "No module named pytest" |
| `.gitignore` | Also ignores `data/sample-results/`, lab private keys and generated capture logs |
| `samples\README.md` | Added the sample-run workflow, what each sample can and cannot prove, and the manifest command |
| `docs\ANALYSIS_FIXES.md` | Root-cause documentation for both rounds of fixes, with verification steps |
| `docs\RUN_BACKEND.md` | **New.** The run-book: one-time setup, the single command that starts the backend and analyses every capture, opening the dashboard and Swagger, running by hand, uploads from PowerShell, stopping it, Docker, housekeeping, and a troubleshooting table |
| `docs\SUBMISSION_CHECKLIST.md` | **New.** Final checklist for the 30 September submission: verification commands, deliverable-to-file mapping, the numbers to put in the presentation, and answers to likely judge questions |

### New tests (4) plus repository files

| File | Purpose |
|---|---|
| `tests\test_starttls_semantics.py` | 7 regression tests, including the exact Dovecot greeting line from your capture that caused the false rejection |
| `tests\test_ml.py` | Extended with a test that the API still answers before any model has been trained (this used to raise `NameError` on a fresh clone) and a test that a stale model is refused instead of contradicting the findings |
| `tests\test_traceability.py` | **New.** A stored analysis must record the current `ANALYZER_VERSION`, and the API version, the stored version and the report version must be one number |
| `LICENSE` | MIT, so the repository can be public |
| `.gitattributes` | Captures marked binary, `*.ps1` kept CRLF, text normalised to LF |
| `.github\workflows\tests.yml` | **New CI.** Installs TShark, trains the model, runs `doctor`, the self check, pytest, a batch analysis, and asserts the dashboard loads nothing remotely - on Python 3.11 and 3.12 |
| `docs\GITHUB.md` | **New.** What to commit, what must never be committed, first push, badges, release tag, Kaggle upload |
| `docs\SCALE_AND_ML.md` | **New.** The scale story and every ML number with the commands that produced them |
| `tests\test_dashboard.py` | **New.** The dashboard is served, loads nothing from the internet, uses the documented endpoints, and states its evidence limits |

### New / updated scripts (8) and tools (3 new)

| File | Purpose |
|---|---|
| `scripts\test_all_samples.ps1` | Updated: now includes `samples\lab\`, checks the API and the ML model before uploading, prints a fixed-width summary table (columns are no longer dropped on a narrow console), shows severity breakdown and top findings per capture, and flags any session where the ML class disagrees with the rule findings. **Bug fixed:** `$ErrorActionPreference` was set before `param()`, which PowerShell parses as a command named "param" instead of a parameter block - the script would not run at all |
| `scripts\build_sample_manifest.ps1` | Rewritten: produces `samples\EXPECTED_RESULTS.md` with a capture summary table (sessions, TLS, cleartext, upgrades, findings, worst risk, posture, evidence, ML agreement) plus per-session detail and per-capture findings. Previously the findings text was interleaved between table rows, which broke the markdown table |
| `scripts\dump_tshark_json.ps1` | New: runs the exact backend TShark command, saves the raw JSON and lists the field names your Wireshark build produces |
| `scripts\build_sample_manifest.ps1` | New: builds `samples\EXPECTED_RESULTS.md` from real analysis output |
| `scripts\self_check.py` | New: dependency-free verification - no pytest needed. Runs 10 synthetic regression checks and, if TShark is installed, analyses every capture and prints what was found |
| `scripts\restart_and_test.ps1` | **stops the API, starts it with the current code, waits until it answers, then runs the sample test.** Use this every time you change a Python file - a running API keeps the old code in memory. The wait is now `-StartupTimeout` seconds (default 180) and prints progress: the first start after extracting a bundle imports scikit-learn, reportlab and FastAPI from disk and can take over a minute, and the old 40-second limit gave up on it |
| `scripts\export_reports.ps1` | Exports JSON, HTML and PDF for every analysis into `reports\`, with `REPORT_MANIFEST.csv` (including each capture's SHA-256) and a `README.md` for the submission pack. Now exports **the newest analysis of each capture only** (`-All` for everything), refuses results whose analyzer version differs from the running one, and warns above `-MaxSizeMB`. **Bug fixed while testing:** a Python-style triple-backtick line inside a PowerShell string escaped the closing quote and broke the whole script |
| `scripts\check_files.ps1` | New: verifies every file in the update bundle is present and unchanged, using the `bundle_manifest.txt` that ships inside the zip. Run it right after extracting an update, before blaming the code. Exits 1 when files are missing |
| `scripts\clear_analyses.ps1` | New: lists every stored analysis (capture, analyzer version, sessions, size, stale yes/no) and deletes the ones you choose - `-StaleOnly`, `-Keep <n>` or `-All`, each requiring `-Force`. Deletes nothing without it |
| `tools\make_dataset_release.py` | New: builds a publishable dataset (our generated captures, the filtered feature table, a README and a datasheet). Excludes third-party captures automatically |
| `tools\build_dashboard_snapshot.py` | New: writes `reports\dashboard_snapshot.html`, one file containing the whole dashboard with the stored results embedded. For screenshots, for the slide deck, or for a judge's laptop with no server running |

### New lab toolkit and captures (2 paths)

| Path | Purpose |
|---|---|
| `tools\lab_capture_toolkit.py` | New: generates a mock SMTP/IMAP/POP3 server, weak and healthy TLS profiles, a private CA chain, a client per scenario, and captures all of it with TShark |
| `samples\lab\` | New: 9 real captures plus `EXPECTED_RESULTS.md`, produced and verified by the toolkit |

### Generated model files (regenerate locally - do not copy)

| Path | Note |
|---|---|
| `models\risk_model.joblib`, `models\anomaly_model.joblib`, `models\model_metadata.json`, `models\training_dataset.csv` | These are **generated**. Do not copy them; run `python -m app.ml.train` on your machine so the metadata matches your environment and you can see the training output yourself |

---

## If pytest still says "No module named pytest"

Run exactly this, inside the project folder, with the virtual environment active:

```powershell
python -m pip install -r requirements-dev.txt
```

`pytest` is a development tool, so it is not in `requirements.txt` (which is what
`pip install -r requirements.txt` installs). You do not need it to use the system -
`python scripts\self_check.py` covers the same ground with zero extra installs.

## After copying

**Important:** stop the running API first. If uvicorn was started without
`--reload`, Python keeps the old modules in memory and every new upload keeps
producing the old result - which is exactly what your last two runs show.

```powershell
cd "D:\CryptoPost SIH\securemailscope"

# 0. install pytest (it was never in requirements.txt)
pip install -r requirements-dev.txt

# 1. prove the fixes are in place - no pytest required
python scripts\self_check.py

# 2. same thing through the test suite
python -m pytest -q

# 3. regenerate the model so the ML layer matches the new features and labels
python -m app.ml.train
```

Expected:

```text
self_check.py    27 passed, 0 failed        (10 synthetic checks + every capture + ML agreement)
pytest -q        15 passed
```

Then start the API and re-run your samples:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

```powershell
.\scripts\test_all_samples.ps1
```

The script now prints a table with duration, TLS/plaintext/STARTTLS counts,
severity breakdown and the top findings per capture, so a wrong detection is
visible immediately.

---

## What should change in your results

| Result | Before | After |
|---|---|---|
| `imap-ssl.pcapng` STARTTLS | `rejected: true`, `STARTTLS_REJECTED` (HIGH) | `rejected: false`, `accepted: true`, no rejection finding |
| Cipher | `0x00ff` (a signalling value, not a cipher) | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)` + `cipher_source: SERVER_HELLO` |
| Certificate | `present: false` (ServerHello and Certificate were silently dropped) | parsed: CN, issuer, RSA 2048, SHA-256 signature, validity, expiry verdict |
| `start_time` / `duration_ms` | `null` / `0` | real values, with a guard against captures whose timestamps jump |
| `The-Ultimate-PCAP.pcapng` | appeared to hang | about 3.5 s, 51 mail sessions, 0 unrelated streams |
| Risk class | a session with one CRITICAL finding could print as MEDIUM | class follows the worst finding; report headline is the worst session |
| ML class | could say CRITICAL for a clean TLS 1.3 session | trained on real capture features too: agrees with the rule engine on all 63 real sessions |

---

## Optional: rebuild the lab captures on Windows

The nine lab captures are already in `samples\lab\`. To reproduce them locally
(the talking point "we generated this traffic ourselves" is stronger when you can
show the tool):

```powershell
python tools\lab_capture_toolkit.py list
python tools\lab_capture_toolkit.py capture
python tools\lab_capture_toolkit.py verify
```

`capture` needs Administrator rights and Wireshark installed with Npcap loopback
support on Windows. `verify` needs neither.

Details, including the judge demo script: `docs\LAB_CAPTURES.md`.
