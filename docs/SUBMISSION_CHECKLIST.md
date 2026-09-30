# Submission checklist (SIH, deadline 30 September)

Everything below was verified on this machine against real TShark output. Copy the
commands in order; each one prints its own pass/fail.

---

## 1. Final verification (about 3 minutes)

```powershell
cd "D:\CryptoPost SIH\securemailscope"

.\scripts\check_files.ps1           # expect: 0 missing - confirms the update was applied
.\scripts\clear_analyses.ps1        # list stored analyses; add -StaleOnly -Force to purge old ones
python scripts\self_check.py        # expect: 33 passed, 0 failed, ML agrees 69/69
python -m pytest -q                 # expect: 15 passed
.\scripts\restart_and_test.ps1      # restart the API and analyse all the sample captures
.\scripts\build_sample_manifest.ps1 # rebuild samples\EXPECTED_RESULTS.md
.\scripts\export_reports.ps1        # JSON + HTML + PDF for every analysis
```

Keep the four outputs visible for the submission:

| Evidence file | What it proves |
|---|---|
| `samples\EXPECTED_RESULTS.md` | Every capture, every session, what was observed, what was found, and that the ML agrees with the rules |
| `reports\REPORT_MANIFEST.csv` | Each report is tied to the capture's SHA-256, which is the provenance requirement |
| `reports\*.json / *.html / *.pdf` | The three required export formats, from one analysis result |
| `models\model_metadata.json` | Training composition, synthetic validation accuracy, capture calibration and the schema fingerprint, all labelled honestly |

---

## 2. Deliverable mapping (problem statement to file)

Every report also carries the **analyzer version and the capture SHA-256** in its
HTML and PDF header, so a printed page can be tied back to the exact build and the
exact bytes that produced it.

| Requirement | Where it is implemented | How to show it |
|---|---|---|
| PCAP upload by a user or by the NTRO organisation, with provenance, no hand-written JSON | `POST /api/v1/analyses/upload` (`uploaded_by=user\|ntro\|team`), `app/storage.py` | Swagger upload, then show `source_filename`, `source_sha256`, `uploaded_by` in the JSON report |
| SMTP / IMAP / POP3 analysis | `app/analysis/tshark.py`, mail-only read filter | `The-Ultimate-PCAP.pcapng`: 51 sessions, protocols SMTP/IMAP/POP3 |
| TCP stream and session reconstruction | stream aggregation in `tshark.py` | session list with client/server, ports, frames, duration, packet and byte counts |
| STARTTLS / STLS detection, success and failure | tagged-response state machine | `smtp-starttls-secure` (upgraded) vs `smtp-starttls-rejected` (`454`) |
| Plaintext authentication before encryption | `_credentials_were_sent_in_clear` | `imap-cleartext-login`, `pop3-cleartext`, `smtp-starttls-rejected` |
| TLS handshake metadata, versions, ciphers, key exchange, SNI, alerts | TLS evidence collection, `version_source` / `cipher_source` | any lab capture: value plus where it came from |
| Forward secrecy | cipher knowledge base `app/analysis/ciphers.py` | `imaps-tls10-legacy`: static RSA, `NO_FORWARD_SECRECY` |
| X.509 extraction and evaluation (validity, SAN/CN, issuer, key size, signature, hostname, chain) | `app/analysis/certificates.py` | `smtps-weak-certificate`: expired, RSA 1024, hostname mismatch |
| Deprecated TLS, weak ciphers, weak keys, static RSA, certificate problems | `app/analysis/rules.py` | the lab table below |
| Session feature vectors | `app/analysis/features.py`, 26 numeric features | `sessions[].features` in the JSON |
| Explainable ML risk classification and anomaly detection | `app/ml/` (RandomForest + IsolationForest) | `sessions[].ml` with class, confidence, anomaly score, explanation |
| Posture score, prioritisation, findings, recommendations | `app/analysis/assessment.py`, `rules.py`, `recommendations.py` | report body |
| JSON, HTML, PDF reports | `app/reports.py` | `reports\` folder after `export_reports.ps1` |
| Interactive dashboard | `app\dashboard.py`, served at `GET /dashboard`; contract in `FRONTEND_API.md` | open `http://localhost:8000/dashboard`, upload a capture, click a session row |

---

**Before you export, clear the old results.** Every upload is stored in
`data\analyses\` and never expires, so after a few test runs the folder holds several
copies of each capture. Worse, results made **before the mail-only traffic filter was
added** are still there - one of them reports 37,776 sessions for a 14 MB capture and
writes a 141 MB JSON. `export_reports.ps1` refuses those and only takes the newest copy
of each capture, but the clean way is:

```powershell
.\scripts\clear_analyses.ps1                  # look first - lists version, sessions, size, stale
.\scripts\clear_analyses.ps1 -All -Force      # purge everything
.\scripts\restart_and_test.ps1                # regenerate 13 clean analyses
.\scripts\export_reports.ps1                  # exactly 13 analyses x 3 formats
```

Nothing is deleted without `-Force`.

---

## 3. The numbers you can state in the presentation

From your own machine's run (61 captures scanned, 40 with mail sessions, 90 sessions):

| Capture | Sessions | TLS | Cleartext | Upgrades | Findings | Posture | Risk |
|---|---|---|---|---|---|---|---|
| `smtp-starttls-secure.pcapng` | 1 | 1 | 0 | 1 | 0 | 100 | LOW |
| `smtps-weak-certificate.pcapng` | 1 | 1 | 0 | 1 | 3 | 10 | CRITICAL |
| `imaps-tls10-legacy.pcapng` | 1 | 1 | 0 | 1 | 3 | 19 | CRITICAL |
| `imaps-null-cipher.pcapng` | 1 | 1 | 0 | 1 | 2 | 37 | CRITICAL |
| `imaps-cbc-cipher.pcapng` | 1 | 1 | 0 | 1 | 1 | 82 | MEDIUM |
| `imap-cleartext-login.pcapng` | 1 | 1 | 0 | 1 | 1 | 55 | CRITICAL |
| `pop3-cleartext.pcapng` | 1 | 0 | 1 | 0 | 2 | 25 | CRITICAL |
| `smtp-starttls-rejected.pcapng` | 1 | 0 | 1 | 0 | 3 | 0 | CRITICAL |
| `imaps-tls13-cert-hidden.pcapng` | 1 | 1 | 0 | 1 | 1 (INFO) | 100 | LOW |
| `The-Ultimate-PCAP.pcapng` | 51 | 13 | 38 | 13 | 60 | 82 | CRITICAL |
| `imap-ssl.pcapng`, `pop-ssl.pcapng`, `smtp-ssl.pcapng` | 1 each | 1 | 0 | 1 | 2, 2, 3 | 52, 52, 34 | HIGH |

Say this out loud: **the same engine gives 100/100 to a correctly configured
session and 0-19/100 to a session that rejects encryption or negotiates TLS 1.0.**

---

## 3b. The ML numbers, and which one to quote

| Number | What it is | Quote it? |
|---|---|---|
| 0.983 | Held-out 20% of **synthetic** rows | Only as a sanity check on training |
| 90/90 | Rule agreement on real captures **used in training** | No. Say "consistency check" if asked |
| **82/90 = 91.1%** (curated set only: 61/69 = 88.4%) | **Leave-one-capture-out**: a whole capture is held out | **Yes. This is the generalisation figure** |
| **78/90 = 86.7%** | Trained on synthetic rows only, tested on real captures | Yes, as the strongest transfer evidence |

`python -m app.ml.train` prints all four, and `python scripts\self_check.py` now prints
the holdout and transfer figures directly under the model status, so nobody has to
remember them. The full evidence, including the two defects found while measuring, is in
**`docs\SCALE_AND_ML.md`**.

---

## 4. What to say when a judge pushes back

| Judge says | Your answer |
|---|---|
| "Show me this detects a real weak configuration." | Open `samples\lab\`: fifteen captures we generated ourselves with a mock mail server and TShark, each with its expected finding recorded in `samples\lab\EXPECTED_RESULTS.md` (`9/9` verified). |
| "Where did your weak traffic come from?" | Generated locally under the dataset note that allows participants to produce SMTP/IMAPS/POP3S traffic. Nothing downloaded, nothing private, loopback only. |
| "Do you decrypt email?" | No. The parser skips `*.data` body fields explicitly. Only protocol commands and TLS handshake metadata are read. |
| "Is this a MITM detection tool?" | No, and we never claim it. A passive capture cannot prove a MITM. We report the weak configuration that would make one attractive, and we mark missing evidence as UNKNOWN. |
| "Why is the certificate missing in some sessions?" | In TLS 1.3 the certificate is encrypted on the wire. `imaps-tls13-cert-hidden.pcapng` demonstrates the tool reporting `CERTIFICATE_NOT_OBSERVED` (INFO) instead of inventing a verdict. |
| "Why is your ML agreement 88% on my colleague's machine and 96% here?" | Because it depends on which captures the loaded model was trained on, and the scorer now says so out loud. Measured on the held-out set: **1,073/1,116 (96.1%)** with the current model, **987/1,116 (88.4%)** with the model from before the coverage sweep - the missing 86 sessions are all static-RSA, where the older model over-warned CRITICAL because no training capture had ever used that profile. Every rule-based check was 100% under both models: findings do not depend on the model. If any capture is newer than the model file the scorer prints a MODEL WARNING and repeats it in `RESULTS.md`. Fix is one command: `python -m app.ml.train`. |
| "How do you know the analyzer works on captures built after the model?" | We generate a **held-out test set** - 27 captures, 1,116 sessions, 50 distinct situations, including IMAP STARTTLS, POP3 STLS and SMTP with no STARTTLS offered, none of which any training capture had. Expectations are declared before the capture runs and stored in `testset\ground_truth.json`. Result: 1,116/1,116 sessions reconstructed, every declared finding reported, **no finding invented** for evidence that was absent, every TLS fact as configured, and the ML layer agreeing with the rules on 1,073/1,116 (96.1%). The first run of this set found two real defects in the analyzer, both recorded in `docs\SCALE_AND_ML.md` section 3.4. `python tools\score_testset.py --dir testset` reproduces it in two minutes. |
| "Is the ML accuracy real?" | Four numbers are recorded in `model_metadata.json` and printed by `train`. In-sample calibration is **90/90** - a consistency check, because those rows trained the model. The honest figures are **leave-one-capture-out 82/90 (91.1%)** and **synthetic-only transfer 78/90 (86.7%)**. On the curated set alone it is 61/69 (88.4%): 21 of the 90 rows are systematic sweep captures whose siblings stay in training, so we publish both and say which is which. We lead with the holdout. |
| "How do you know the model does not just copy your rules?" | It is trained on rule labels, so it does imitate them - that is the point of weak supervision, and the datasheet says so. The useful measurement is whether it imitates them on a capture it has never seen, which is the 91.1% holdout. |
| "Did you find anything wrong while testing?" | Yes, two real defects in the training data, both of the same kind: **evidence that was not observed was being scored as weakness**. A plaintext session (no cipher at all) tripped the weak-cipher penalty, and an unobserved certificate tripped the weak-certificate penalties. On one real capture the model got 3 of 51 sessions right before the fix and 44 of 51 after. The second defect was a training parameter that memorised our sessions instead of learning from them; correcting it took honest accuracy from 31.7% to 87.3% in the parameter sweep. Both are documented in `docs\SCALE_AND_ML.md`. |
| "Can it handle heavy data?" | `python -m app.cli batch <folder> --workers 8` analyses a whole directory tree in parallel, writing results as each capture finishes. 24 captures and 69 sessions take about 9 seconds on two cores. A generated 14.72 MB / 3,000-session capture is parsed in 105 s, and the 14.88 MB mixed-protocol capture in a few seconds. The batch path also emits the session feature table, which is the training set. |
| "Why do your numbers differ from your teammate's machine?" | Only INFO-level "evidence not visible" counts differ, because Windows and Linux TShark dissect some TLS streams slightly differently. The security verdicts (CRITICAL/HIGH/MEDIUM findings) are identical on both. That is what an evidence-qualified tool should look like. |
| "Your report says posture 82/100 but risk class CRITICAL - which is it?" | Deliberate, and both are printed from the same result. Posture is the mean of the session scores, so it describes the estate; the headline class is the **worst** single session, so a real problem can never be hidden behind healthy traffic. A 51-session capture with three plaintext-authentication sessions is mostly healthy and still CRITICAL. |
| "What about scale?" | `The-Ultimate-PCAP.pcapng` (14.88 MB) is parsed in about 13 seconds on a laptop, with the filter keeping only mail traffic. |
| "How would you make the model more accurate?" | We tested the two obvious answers. Four times the synthetic training rows (5,000 to 20,000) left the held-out result **exactly unchanged at 53/63** - the synthetic accuracy rose from 0.983 to 0.9965, which only means the model memorised its generator better. Adding **six more diverse captures** took the held-out result from 54/63 to **60/69 (87.0%)**, and the systematic 42-capture sweep took it to **82/90 (91.1%)** while also fixing one error. So the lever is capture diversity, and that is where the remaining time goes. Measured commands and numbers: `docs\TRAINING_PLAYBOOK.md` section 1. |
| "Is POP3 covered, or only IMAP and SMTP?" | All three protocols, in cleartext and encrypted. POP3S had no encrypted scenario until we measured what improves the model: there are now three POP3S captures (TLS 1.0 with static RSA, a 1024-bit expired certificate for the wrong hostname, and a CBC cipher) plus the cleartext POP3 capture. The lab set is **15 captures, verified 15/15** against the analyzer's own output. |
| "What if I upload an empty or broken file?" | It is refused with a reason, not scored. An empty file returns `422 The uploaded file is empty. Nothing was analysed.`; a file that is not a capture returns `422` with TShark's own explanation; a wrong extension returns `400 Upload a PCAP/PCAPNG/CAP file`. A capture that parses but holds no mail session is accepted, and the dashboard shows a neutral **NO MAIL SESSIONS - nothing to score** badge instead of a green `LOW 100/100`. We fixed that after testing: a perfect score for a file that was never assessed is the most misleading thing this tool could show. |
| "What is the end-to-end time in a live demo?" | Measured on this machine through the running API: health `0.4 s`, a lab capture uploaded and analysed `0.4 s`, the 15 MB mixed capture `5.3 s` (51 sessions), JSON report `instant`, HTML `instant`, PDF `0.12 s`. Two captures uploaded concurrently both complete in `0.44 s`. TShark is the cost, not our code. |
| "What if NTRO hands you a capture from a server on a non-standard port?" | Handled, and it is worth demonstrating: `python tools\capability_test.py` re-captures the nine lab scenarios on ports the training set never used. Six of eleven are on unusual cleartext/STARTTLS ports (25, 2525, 8110, 8143) and every expected finding is found on all six, with rules and ML agreeing 6/6. Identification falls back to the protocols' own vocabulary (`EHLO`, `* OK`, `+OK`, `STLS`) instead of the port number. That was a defect we found and fixed: before it, a mail service on 8143 produced an empty report. |
| "And if it is encrypted end to end on a port you do not know?" | Then the tool says so rather than guessing. Implicit TLS on an unrecognised port has no protocol vocabulary anywhere in the file, so `check` reports the encrypted stream with its port, negotiated TLS version, SNI and certificate visibility, and states that the protocol inside cannot be proven from the capture. Five of the eleven unseen captures exercise exactly that path. Reporting nothing, or naming a protocol from a port number, would both be wrong. |

---

## 5. Dashboard (built - open it, do not describe it)

The dashboard is **served by the backend itself** at:

```
http://localhost:8000/dashboard
```

Start the API first (`restart_and_test.ps1 -SkipTests`), then open that URL.
There is no frontend to build, nothing to install, and **nothing is loaded from
the internet**, so it works air-gapped - which matters when captures come from an
organisation.

What it shows, and what to point at while demonstrating:

| Area | What the judge sees |
|---|---|
| Upload panel | Drop a PCAP or choose a file, pick the source of the capture - **user** (ordinary upload), **ntro** (provided by the organisation) or **team**. This is the same upload workflow with recorded provenance |
| Analyses list | Every stored analysis with its risk class, posture, session count, finding count, uploader and analyzer version |
| Posture metrics | Posture, risk class (worst session), sessions split into TLS and cleartext, STARTTLS upgrades, findings, ML anomalies, evidence completeness |
| Finding severity chart | How the findings are distributed by severity |
| Capture facts | Protocols, TLS versions, cipher suites, overall risk score |
| Recommended actions | The ordered fix list from the recommendation engine |
| Sessions table | One row per email session: server/client, TLS version **and where that value came from**, cipher **and its source**, whether it was upgraded, rule class, ML class, risk score |
| Session drill-down | Click any row to expand the full evidence: TLS handshake detail, the X.509 certificate (subject, issuer, SAN, validity, key size, signature, chain), STARTTLS/STLS state, the ML result with its explanation, and that session's findings |
| Download buttons | JSON / HTML / PDF for the selected analysis |

Two ways to show it without a server, if a machine is locked down:

```powershell
python tools\build_dashboard_snapshot.py     # writes reports\dashboard_snapshot.html
```

That is one file containing the whole dashboard with the stored results embedded.
It opens from a USB stick with no network and no Python running. Verified in a real
browser: the offline file renders the same panels, expands session rows, and shows an
"offline snapshot" banner.

`FRONTEND_API.md` remains the contract, so a separate React/Vue dashboard can replace
this page later without touching the backend.

---

## 6. Two numbers that look contradictory and are not

`The-Ultimate-PCAP.pcapng` reports **posture 82/100** and **risk class CRITICAL**, and
`self_check.py` prints a **worst session score** next to a **capture posture**. This is
intentional and consistent:

| Number | Meaning | Where it comes from |
|---|---|---|
| Session score (for example 78) | How risky that one session is | the rules that fired in that session |
| Capture posture (for example 82) | 100 minus the **average** of all session scores | the summary in every report |
| Capture risk class (CRITICAL) | The **worst** single session's class | never an average, so one bad session cannot be averaged away |

A capture can be mostly healthy and still CRITICAL. Say that sentence before a judge
asks.

---

### Is the number good? The baseline, and why not 95%

| Measure | Value | How it is computed |
|---|---|---|
| **In-sample (calibration)** | **90/90** | the rows that trained the model - a consistency check, **not** evidence |
| **Holdout (leave-one-capture-out)** | **82/90 = 91.1%** | whole capture held out; no session from it helped training |
| Holdout on the curated set only | 61/69 = 88.4% | same 19 hand-written/third-party captures as before the sweep existed |
| Transfer (synthetic -> real) | 78/90 = 86.7% | trained on synthetic rows only, tested on real captures |
| **Majority-class baseline** | 44/90 = **48.9%** | always predict MEDIUM; what a useless model scores |

**+42.2 points over the trivial baseline.** The confidence intervals do not overlap:
ours is [85.2%, 97.0%], the baseline's is [38.6%, 59.2%].

**Why not 95%?** Because 90 rows cannot tell the difference. One row is worth 1.1 points; a
95% claim would allow at most 4 misses and we have 8; and 95% sits *inside* our confidence
interval, so "we measured 91% ± 6 points" is the honest sentence. Reaching ±3 points of
certainty needs about 350 rows. Tuning until the number reads 95% on 90 rows would be
fitting the test set, and the next capture would expose it.

**The one error to disclose first:** `imap-cleartext-login` is predicted HIGH where the rules
say CRITICAL - the only understatement in nine errors. The other eight all over-warn (seven
are the same LOW/MEDIUM boundary on one capture). Full breakdown: `docs\SCALE_AND_ML.md`.

---

## 7. Known limits to state before you are asked

1. **3DES, RC4 and SHA-1 signing could not be generated** with the OpenSSL and
   `cryptography` builds used here. The cipher table already contains those suites
   and the rules exist; the lab set covers the same code paths with TLS 1.0, CBC,
   NULL cipher, static RSA and a 1024-bit certificate.
2. **Trust-anchor validation is out of scope** for a passive capture: we report
   chain completeness and identity, not whether a public CA would accept it.
3. **The ML model is small and trained on synthetic rows plus 69 real sessions.**
   It is presented as a supporting layer; the findings are the evidence.
4. **Live monitoring was not built**, by design: it would need authorisation and a
   traffic vantage point. The system is passive, offline and privacy-preserving.
5. **A mail protocol inside implicit TLS on an unrecognised port cannot be named from
   the capture.** The stream is reported and described, but the protocol is left
   UNKNOWN. This is a limit of passive analysis, not an implementation gap: the first
   byte on the wire is a TLS ClientHello, and a port number is a convention, not
   evidence.

---

## 8. If you get extra time before the deadline

In priority order:

1. **Screenshots** of the dashboard and of one HTML report for the slide deck.
2. **A second weak-certificate capture** on a machine whose OpenSSL still allows
   SHA-1 signing, to switch on `WEAK_CERTIFICATE_SIGNATURE`.
3. **A 3DES capture** if a build with the legacy provider enabled can negotiate it.
4. **Re-run `export_reports.ps1` with `-Match`** to build a smaller report pack
   containing only the six showcase captures.
