# SecureMailScope Backend + AI/ML

SecureMailScope is an evidence-driven cryptographic security posture assessment framework for SMTP, IMAP and POP3 traffic captured in PCAP files.

This repository is the backend and AI/ML track. The frontend can consume the REST API documented in `FRONTEND_API.md`.

## What this system does

```text
PCAP
  -> TCP/session reconstruction
  -> SMTP/IMAP/POP3 identification
  -> STARTTLS/STLS transition analysis
  -> TLS handshake and cipher extraction
  -> X.509 certificate analysis
  -> deterministic cryptographic findings
  -> ML risk classification and anomaly scoring
  -> posture scoring and prioritisation
  -> recommendations and JSON/HTML/PDF reports
```

This is intentionally a hybrid system:

- TShark/Wireshark and `cryptography` provide verifiable protocol evidence.
- The rule engine identifies definite weaknesses and maps them to remediation.
- The ML layer classifies session risk and detects unusual combinations.
- Missing evidence is represented as `UNKNOWN`/`PARTIAL`, not guessed.

## Start here

| Document | Use it for |
|---|---|
| `START_HERE.md` | Beginner walkthrough: file layout, training, running the API, uploading a PCAP |
| `docs\FILES_CHANGED.md` | The update bundle, the exact file list, and what changed in the results |
| `scripts\self_check.py` | One-command verification: `python scripts\self_check.py` (no pytest needed) |
| `scripts\restart_and_test.ps1` | Restart the API with the current code and re-run every sample: `.\scripts\restart_and_test.ps1` |
| `GET /api/v1/health` | `ml_model_status` and `ml_model_note` tell you whether a trained model is actually in use |
| `docs\ANALYSIS_FIXES.md` | Why the first result was wrong, root causes, and how to verify every fix |
| `docs\LAB_CAPTURES.md` | The nine generated lab captures, the judge demo script, and the honest limits |
| `docs\SUBMISSION_CHECKLIST.md` | Final verification commands, deliverable-to-file mapping, presentation numbers, and answers to likely judge questions |
| `scripts\check_files.ps1` | Run this first: confirms every file from the update bundle is present and unchanged |
| `scripts\clear_analyses.ps1` | Lists stored analyses and removes old or duplicate ones (`-StaleOnly`, `-Keep <n>`, `-All`, all needing `-Force`) |
| `tools\build_dashboard_snapshot.py` | Writes `reports\dashboard_snapshot.html`: the whole dashboard in one file with the stored results embedded, for screenshots or a machine with no server |
| `samples\EXPECTED_RESULTS.md` | What each sample really contains, from real analysis output |
| `FRONTEND_API.md` | Endpoint contract for the frontend team |

## Lab captures

`samples\lab\` contains nine PCAPNG files generated locally by
`tools\lab_capture_toolkit.py` (mock mail server + client + TShark loopback
capture): a healthy baseline, a rejected STARTTLS upgrade, cleartext IMAP/POP3
authentication, TLS 1.0 with static RSA, a NULL cipher, an expired 1024-bit
certificate issued for the wrong hostname, a TLS 1.3 session where the certificate
is encrypted, and a CBC cipher suite.

```powershell
python tools\lab_capture_toolkit.py list
python tools\lab_capture_toolkit.py verify     # prints 9/9 when the engine behaves as expected
```

## Official problem-statement coverage

| Requirement | Implementation area |
|---|---|
| SMTP/IMAP/POP3 identification | `app/analysis/tshark.py` |
| STARTTLS/STLS detection | `app/analysis/tshark.py` |
| TCP stream/session reconstruction | TShark stream aggregation |
| TLS handshake reconstruction | TShark TLS field aggregation |
| TLS version/cipher/key exchange | `app/analysis/tshark.py` |
| X.509 extraction and validation | `app/analysis/certificates.py` |
| Weakness detection | `app/analysis/rules.py` |
| Feature extraction | `app/analysis/features.py` |
| Risk classification/anomaly detection | `app/ml/model.py` |
| Posture scoring/prioritisation | `app/analysis/assessment.py` |
| Recommendations | `app/analysis/recommendations.py` |
| JSON/HTML/PDF reports | `app/reports.py` |
| Interactive dashboard backend | FastAPI endpoints |

* **Integrating a frontend / rehearsing the demo**: endpoints, timeout and payload rules,
  the four-minute script and the fallbacks - **`docs\INTEGRATION_PLAN.md`**.
* **Training and testing, start to finish**: the method, what actually improves the
  model (measured), the five-level test ladder and the Kaggle rules - **`docs\TRAINING_PLAYBOOK.md`**.

## Scale and the ML numbers

* **Heavy data processing**: `python -m app.cli batch <folder> --workers 8` analyses a
  whole directory tree in parallel. 19 captures and 69 sessions take about 4 seconds on
  2 cores, and every session lands in a feature table you can train on.
* **Honest ML figures**: 91.1% agreement with the rule engine on captures it has never seen
  (leave-one-capture-out, 82/90 - the curated set alone is 61/69), and 86.7% when trained on
  synthetic rows only and tested on real captures. The in-sample 90/90 is a consistency
  check, not evidence. The confidence interval is about six points wide, so the honest
  sentence is "91%, plus or minus six", never 95%. Full evidence, the baseline and the
  defects found while measuring: **`docs\SCALE_AND_ML.md`**.
* **Retrain after every update that adds captures.** Measured on the held-out set: identical
  code scored **88.4%** ML agreement with the pre-sweep model and **96.1%** with the current
  one, and the analyzer's rule checks were 100% in both runs. Adding captures without running
  `python -m app.ml.train` therefore makes the ML column look worse for no visible reason -
  so the scorer now prints a MODEL WARNING when any capture is newer than the model file.
* **Interface**: the dashboard is one self-contained HTML page (verdict band, four tabs,
  one filter, sessions expand in place) and the reports are JSON, HTML and PDF from the same
  data. Why it looks like it does, and the two PDF layout bugs that were fixed:
  **`docs\DESIGN.md`**. Screenshots and sample reports: **`docs\screenshots\`**.
* **Held-out test set**: `testset/` is 27 captures and 1,116 sessions generated *after*
  training, on situations the training captures never had (IMAP STARTTLS, POP3 STLS, SMTP with
  no STARTTLS offered, mixed-port files). Score it with `python tools\score_testset.py --dir
  testset`. Its first run found two real defects in the analyzer, both now fixed -
  `docs\SCALE_AND_ML.md` section 3.4.
* **Publishing**: `python tools\make_dataset_release.py` builds a dataset with a
  datasheet. **`docs\GITHUB.md`** covers the repository.
* **Not just the ports we trained on**: mail traffic is identified from the protocols'
  own vocabulary as well as the port, so a server on 8143, 2525 or 8110 is analysed like
  one on 143, 587 or 110. `python tools\capability_test.py` measures this on captures the
  model has never seen; if a stream is encrypted end to end on an unknown port, the tool
  reports what it saw instead of naming a protocol it cannot prove. Evidence and the
  measurements: **`docs\CAPABILITY_TEST.md`**.

## Running the backend

Every command, in order, from first install to the demo, with a troubleshooting
table: **`docs\RUN_BACKEND.md`**.

## Running locally

### 1. Install system dependency

The real PCAP analyser uses TShark. Install Wireshark/TShark on the host, or use Docker.

### 2. Install Python dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Train the demo models

```bash
python -m app.ml.train
```

The model is trained on controlled synthetic session features. It is a competition MVP model, not a claim of production accuracy.

### 4. Start API

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/docs` for Swagger API documentation.

### 5. Generate a demo analysis

```bash
curl -X POST http://localhost:8000/api/v1/demo/analysis
```

The demo endpoint is useful while the frontend and PCAP capture environment are being prepared.

### 6. Analyze a PCAP

```bash
curl -X POST http://localhost:8000/api/v1/analyses/upload \
  -F "file=@samples/mail.pcap"
```

## Important limitations

- Passive analysis cannot decrypt email content without appropriate session secrets.
- A certificate chain may be incomplete in a PCAP. The API reports this explicitly.
- A missing handshake is not automatically classified as insecure; evidence completeness is returned.
- A passive laptop does not automatically see every Wi-Fi client's unicast traffic. Use a local interface, an authorized gateway/TAP/SPAN point, or PCAP replay for the live demo.
- Do not use the project to monitor networks without authorization.
