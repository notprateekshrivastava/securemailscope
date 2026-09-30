# SecureMailScope: beginner start guide

This guide is for a teammate who is new to backend and AI/ML. Follow the steps in order. Do not create random files outside the project folder.

## Document index

| Document | Read it when |
|---|---|
| `docs\FILES_CHANGED.md` | You need the update bundle and the exact file list |
| `docs\TRAINING_PLAYBOOK.md` | You want to train, test or improve the model - the method, the measurements behind each recommendation, and the plan to the deadline |
| `docs\INTEGRATION_PLAN.md` | You are wiring the frontend or rehearsing the live demo - endpoints, timeouts, the demo script, and the differentiator options |
| `docs\ANALYSIS_FIXES.md` | You want to know why the first `imap-ssl.pcapng` result was wrong and how each fix is verified |
| `docs\LAB_CAPTURES.md` | You want the weak test captures and the demo script for the judges |
| `docs\SUBMISSION_CHECKLIST.md` | You are preparing the final submission: verification commands, evidence files, presentation numbers, judge questions |
| `docs\SCALE_AND_ML.md` | You want the scale story and every ML number, with the commands that produced them |
| `docs\GITHUB.md` | You are putting the project on GitHub or Kaggle - including what must never be committed |
| `docs\RUN_BACKEND.md` | You want to run the backend: every command from install to demo, plus a troubleshooting table |
| `scripts\check_files.ps1` | You are not sure whether an update was copied correctly - it lists exactly what is missing |
| `scripts\clear_analyses.ps1` | Your reports folder has duplicates or odd old results - it shows what is stored and removes what you choose |
| `http://localhost:8000/dashboard` | You want to see and demonstrate the system: upload a capture, click a session, expand its evidence |
| `tools\build_dashboard_snapshot.py` | You need the dashboard as one offline file for screenshots or a laptop with no server |
| `samples\EXPECTED_RESULTS.md` | You want proof of what each sample actually contains |
| `FRONTEND_API.md` | You are connecting the frontend |

## Quick check after updating the code

```powershell
python scripts\self_check.py
```

No extra package needed. It replays the regression cases that used to fail and
then analyses every capture in `samples\` and `samples\lab\`, printing what was
found. Expect `26 passed, 0 failed`. If it reports only capture failures, the code
is fine and the capture is the problem; if the synthetic checks fail, the updated
`app\analysis` files are not in place.

## 0. The one idea to remember

You are not training AI on the whole PCAP directly.

```text
PCAP file
  -> TShark extracts sessions and TLS/certificate facts
  -> Python converts facts into features
  -> rules identify definite weaknesses
  -> ML classifies risk and finds unusual sessions
  -> recommendations explain what the administrator should fix
```

The ML model is only one part of SecureMailScope.

## 1. Where every file belongs

The project folder is:

```text
securemailscope/
```

Do not put Python files in random locations. Use this structure:

```text
securemailscope/
├── app/
│   ├── main.py                 FastAPI HTTP endpoints
│   ├── service.py              Upload -> analysis -> ML -> result pipeline
│   ├── schemas.py              API data shapes
│   ├── storage.py              Saves uploads/results
│   ├── reports.py              JSON/HTML/PDF reports
│   ├── analysis/
│   │   ├── tshark.py           PCAP, TCP, SMTP/IMAP/POP3 and TLS extraction
│   │   ├── certificates.py     X.509 parsing and certificate checks
│   │   ├── rules.py             Finds weaknesses and creates findings
│   │   ├── assessment.py        Risk/posture aggregation
│   │   ├── recommendations.py   Remediation advice
│   │   └── features.py         Stable ML feature boundary
│   └── ml/
│       ├── train.py            Generates training data and trains models
│       └── model.py            Loads models and predicts risk/anomalies
├── data/
│   ├── uploads/                Uploaded PCAP files are stored here temporarily
│   └── analyses/               JSON analysis results are stored here
├── samples/                    Your controlled test PCAPs go here
├── models/                     Trained .joblib models go here
├── tests/                      Automated tests
├── requirements.txt            Python dependencies
├── Dockerfile                  Backend + TShark deployment image
├── docker-compose.yml          One-command local deployment
├── FRONTEND_API.md             Contract for Prateek's frontend
└── PS_TRACEABILITY.md          Official problem statement mapping
```

## 2. Install prerequisites

### Windows

Install:

1. Python 3.11 or 3.12 from python.org.
2. Wireshark. Select the TShark component during installation.
3. Git, if the project is in Git.
4. Docker Desktop, if possible.

Open PowerShell and verify:

```powershell
python --version
tshark --version
```

If PowerShell says that `tshark` exists in the current location but does not load it, run:

```powershell
.\\tshark.exe --version
```

If TShark is installed by Wireshark in the standard folder, run:

```powershell
& "C:\\Program Files\\Wireshark\\tshark.exe" --version
```

For the backend, the easiest permanent fix is to add `C:\\Program Files\\Wireshark` to your Windows user PATH and open a new PowerShell window. The backend also checks this standard location automatically. You can explicitly configure another location with:

```powershell
$env:SECUREMAILSCOPE_TSHARK_PATH = "C:\\Path\\To\\tshark.exe"
```

If TShark is not installed, add the TShark component while installing Wireshark or use Docker.

### Ubuntu/Debian

```bash
sudo apt update
sudo apt install python3 python3-venv tshark
python3 --version
tshark --version
```

### Docker option

If installing TShark is difficult, Docker is the easiest team-wide solution:

```bash
docker compose up --build
```

The Dockerfile installs TShark inside the container.

## 3. Create the Python environment

From inside `securemailscope`:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run PowerShell as your user and execute:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate again.

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Train the initial models

Run:

```bash
python -m app.ml.train
```

This creates:

```text
models/risk_model.joblib
models/anomaly_model.joblib
models/model_metadata.json
```

Do not manually edit `.joblib` files.

### What this command does

`app/ml/train.py`:

1. Creates controlled synthetic session feature rows.
2. Creates scenarios such as secure TLS, deprecated TLS, weak certificates and plaintext authentication.
3. Assigns labels: LOW, MEDIUM, HIGH and CRITICAL.
4. Trains a Random Forest risk classifier.
5. Trains an Isolation Forest anomaly detector.
6. Saves the trained models.

This is enough for the hackathon MVP. In the presentation, say that the first model is trained on controlled synthetic/lab-generated features and can be retrained using labelled organisational data.

## 5. Start the backend

The one command that always works after a code change:

```powershell
.\scripts\restart_and_test.ps1
```

It stops the previous API, starts it with the current code, waits for it to answer,
prints the health status including whether a trained model is in use, and then runs
every sample capture. Detailed manual steps follow.

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000/docs
```

This is the automatic Swagger API page. It lets you test every endpoint without building a frontend first.

Health check:

```text
GET http://localhost:8000/api/v1/health
```

Expected result:

```json
{
  "status": "ok",
  "tshark_available": true,
  "ml_model_available": true,
  "version": "1.0.0"
}
```

## 6. Test without a PCAP

Use the controlled demo fixture:

```bash
curl -X POST http://localhost:8000/api/v1/demo/analysis
```

It contains:

- Secure SMTP STARTTLS/TLS 1.3
- Weak IMAP STARTTLS/TLS 1.0
- Plaintext POP3 authentication

This is only for frontend development and testing. It is not a replacement for testing real PCAP files.

## 7. Upload a PCAP from a user or NTRO

The real endpoint is:

```text
POST /api/v1/analyses/upload
```

The frontend sends a multipart form:

```text
file: capture.pcap
uploaded_by: user
```

For an NTRO-provided capture:

```text
file: ntro_capture.pcap
uploaded_by: ntro
```

Using curl:

```bash
curl -X POST http://localhost:8000/api/v1/analyses/upload \
  -F "file=@samples/ntro_capture.pcap" \
  -F "uploaded_by=ntro"
```

The backend then:

1. Receives the file.
2. Checks the extension and size.
3. Stores it under `data/uploads/`.
4. Calculates its SHA-256 hash.
5. Runs TShark.
6. Reconstructs email sessions.
7. Extracts TLS/certificate features.
8. Runs rules.
9. Runs the ML models.
10. Generates recommendations.
11. Saves the result under `data/analyses/`.
12. Returns the complete `AnalysisResult` JSON to the frontend.

The user or NTRO does not need to create JSON manually. They upload a PCAP.

## 8. What Prateek's frontend must do

The frontend should have a file picker and submit:

```javascript
const body = new FormData();
body.append("file", selectedFile);
body.append("uploaded_by", "user");

const response = await fetch(
  `${API_URL}/api/v1/analyses/upload`,
  { method: "POST", body }
);

const analysis = await response.json();
```

For an NTRO capture, use:

```javascript
body.append("uploaded_by", "ntro");
```

Then render these fields:

```text
analysis.summary
analysis.sessions
analysis.findings
analysis.recommendations
```

Full field guidance is in `FRONTEND_API.md`.

## 9. How the AI/ML part works in simple language

### Feature

A feature is a measurable fact about a session:

```text
TLS version = TLS 1.0
Certificate expired = true
Forward secrecy = false
Cipher strength = 20
```

### Label

A label is the expected risk category:

```text
TLS 1.0 + expired certificate = CRITICAL
```

### Training

Training means showing the model many feature rows with labels so it learns common relationships.

### Prediction

When a new PCAP is uploaded:

```text
New session features -> model -> HIGH risk
```

### Anomaly detection

The anomaly model learns what normal secure sessions look like. It flags unusual sessions even if a specific attack label was not available.

### Rule engine versus ML

Rules are used for facts that should be deterministic:

```text
TLS 1.0 detected
Certificate expired
RSA key is 1024 bits
```

ML is used for:

```text
Risk classification
Unusual combinations
Deviation from a baseline
```

## 10. The complete result for one weak session

The final result should look conceptually like this:

```text
Evidence:
  Protocol: SMTP
  TLS: 1.0
  Cipher: 3DES
  Key exchange: RSA
  Certificate: expired
  Forward secrecy: no

Assessment:
  Risk: CRITICAL
  Policy score: 95/100
  ML class: CRITICAL
  Anomaly: yes

Why:
  Deprecated TLS
  Legacy cipher
  No forward secrecy
  Expired certificate

Actions:
  Disable TLS 1.0
  Enforce TLS 1.2/1.3
  Replace the certificate
  Prefer ECDHE
  Reject plaintext authentication
```

That is the difference between “analysis” and “security posture assessment”.

## 11. Team working order

### Backend/AI/ML team

1. Make the API run.
2. Train the model.
3. Test the demo fixture.
4. Obtain three real controlled PCAPs.
5. Test TShark extraction.
6. Fix field mappings for the installed Wireshark version.
7. Send Prateek one real API response.
8. Add server-level posture and baseline comparison only after P0 works.

### Frontend team

1. Connect to `/api/v1/demo/analysis`.
2. Build dashboard using the demo response.
3. Connect file upload to `/api/v1/analyses/upload`.
4. Display loading state while analysis runs.
5. Add session detail and findings pages.
6. Add JSON/HTML/PDF download buttons.

## 12. Lab captures: weak traffic you generate yourself

The public sample captures cannot show weak encryption, and you cannot invent
packets. Instead, one script creates the traffic locally and records it:

```powershell
python tools\lab_capture_toolkit.py list      # 9 scenarios and their expected findings
python tools\lab_capture_toolkit.py capture   # Administrator + Npcap loopback on Windows
python tools\lab_capture_toolkit.py verify    # analyse and compare, no special rights
```

What it does: a small mock SMTP/IMAP/POP3 server and a client talk only to
`127.0.0.1` while TShark records the loopback interface. Result: nine real capture
files in `samples\lab\`, including cleartext `LOGIN`, a rejected STARTTLS upgrade,
TLS 1.0 with static RSA, a NULL cipher, an expired 1024-bit certificate for the
wrong hostname, and TLS 1.3 where the certificate is encrypted and therefore
invisible.

`verify` prints one line per capture and ends with `9/9 captures behave as
expected`, and rewrites `samples\lab\EXPECTED_RESULTS.md` with the observed
values. That file is the honest answer to "how do you know the weak-encryption
detection works?".

Full details, including what each capture proves and the four-minute demo script:
`docs\LAB_CAPTURES.md`.

## 13. Common mistakes to avoid

- Do not train a neural network just to say the project uses AI.
- Do not manually create fake output after upload.
- Do not claim that missing certificate evidence means the certificate is invalid.
- Do not claim that a laptop can observe every Wi-Fi device automatically.
- Do not upload confidential NTRO data to external AI APIs.
- Do not expose the upload API publicly without limits and authorization.
- Do not call a synthetic validation accuracy production accuracy.
- Do not build the chatbot before the analyzer, assessment and recommendations work.
