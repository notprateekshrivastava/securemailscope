# How to run the backend - every command, in order

Written for Windows PowerShell, in the project folder:

```powershell
cd "D:\CryptoPost SIH\securemailscope"
```

If the prompt shows `(.venv)` you are already inside the virtual environment. If it
does not, run this first:

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass) ; (& ".\.venv\Scripts\Activate.ps1")
```

---

## A. One-time setup (do this once, ever)

```powershell
# 1. Create the virtual environment (skip if .venv already exists)
python -m venv .venv
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass) ; (& ".\.venv\Scripts\Activate.ps1")

# 2. Install the libraries
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

# 3. Confirm Wireshark/TShark is installed
tshark -v

# 4. Train the ML model (creates models\risk_model.joblib and friends)
python -m app.ml.train

# 5. Prove everything works before you rely on it
python scripts\self_check.py
python -m pytest -q
```

Expected results: `self_check` ends with **27 passed, 0 failed** including
`ML classification agrees with the rule engine - 69/69 sessions`, and pytest ends with
**22 passed**.

If `tshark -v` fails, install Wireshark with the TShark component, then tell the app
where it is:

```powershell
$env:SECUREMAILSCOPE_TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
```

---

## B. Start the backend and analyse everything (the one command you need)

```powershell
.\scripts\restart_and_test.ps1
```

That single command does all of this:

1. stops any API already running on port 8000 (so you never analyse with old code),
2. starts the backend with the current code,
3. waits until it answers and prints its status, TShark availability and ML model,
4. uploads and analyses every capture in `samples\` and `samples\lab\`,
5. prints the summary table and checks that the ML agrees with the rules.

Variations:

```powershell
.\scripts\restart_and_test.ps1 -SkipTests          # only restart the backend
.\scripts\restart_and_test.ps1 -Port 8080          # use a different port
.\scripts\restart_and_test.ps1 -UploadedBy ntro    # record a different uploader
.\scripts\restart_and_test.ps1 -StartupTimeout 300 # slow machine
```

---

## C. Open the interfaces

| What | Address | Use it for |
|---|---|---|
| **Dashboard** | http://localhost:8000/dashboard | Upload a PCAP, see results, click a session for the full evidence, download reports |
| **Swagger UI** | http://localhost:8000/docs | Test any endpoint by hand, no code needed |
| **Health check** | http://localhost:8000/api/v1/health | Confirm the API, TShark and ML model are ready |
| **Analysis list** | http://localhost:8000/api/v1/analyses | All stored results as JSON |

Open the first one in a browser:

```powershell
start http://localhost:8000/dashboard
```

---

## D. Run it by hand instead of with the script

Useful when you want to watch the log live or change the port.

```powershell
# Stop whatever is on port 8000
Get-NetTCPConnection -LocalPort 8000 -State Listen |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }

# Start the backend in the foreground (Ctrl+C stops it)
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Keep that window open. Open a **second** PowerShell window for anything else:

```powershell
cd "D:\CryptoPost SIH\securemailscope"
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass) ; (& ".\.venv\Scripts\Activate.ps1")
```

Useful options:

```powershell
uvicorn app.main:app --port 8000 --reload     # auto-reload when you edit code (development only)
uvicorn app.main:app --host 127.0.0.1 --port 8000   # only this machine can reach it (safer)
uvicorn app.main:app --port 8080              # different port if 8000 is taken
```

> **Always restart after changing a Python file.** A running API keeps the old code in
> memory, so without a restart your uploads still produce the old result. That is the
> whole reason `restart_and_test.ps1` exists.

---

## E. Upload a PCAP without the dashboard

**PowerShell:**

```powershell
$api = "http://localhost:8000"
curl.exe -s -X POST "$api/api/v1/analyses/upload" `
  -F "file=@D:\path\to\capture.pcapng" `
  -F "uploaded_by=ntro" | ConvertFrom-Json | Select-Object analysis_id, source_filename, source_sha256
```

`uploaded_by` accepts `user`, `ntro`, `team` or `demo` - this is the provenance record,
so no JSON file is ever written by hand.

**Then fetch a report for that analysis:**

```powershell
$id = "paste-the-analysis-id-here"
curl.exe -s -o report.json "$api/api/v1/analyses/$id/reports/json"
curl.exe -s -o report.html "$api/api/v1/analyses/$id/reports/html"
curl.exe -s -o report.pdf  "$api/api/v1/analyses/$id/reports/pdf"
```

**Or analyse a capture for every session at once and export everything:**

```powershell
.\scripts\test_all_samples.ps1     # uploads all samples, prints the summary table
.\scripts\build_sample_manifest.ps1 # refreshes samples\EXPECTED_RESULTS.md
.\scripts\export_reports.ps1        # writes reports\ with JSON + HTML + PDF for each capture
```

---

## F. Stop the backend

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

Find out what is running on the port, without killing it:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

---

## F2. Batch analysis from the command line (the high-throughput path)

The API analyses one upload at a time. For a folder of captures, use the CLI:

```powershell
# Environment check first - it tells you if TShark or the model is missing
python -m app.cli doctor

# Analyse every capture under a folder, in parallel
python -m app.cli batch "D:\captures" --out data\batch --workers 8

# Other options
python -m app.cli batch samples --out data\batch --workers 4 --resume    # skip what is done
python -m app.cli batch samples --out data\batch --limit 50              # stop after 50
python -m app.cli batch samples --out data\batch --no-features           # summary only

# Inspect the results
python -m app.cli export data\batch\session_features.csv --stats
python -m app.cli verify data\batch\captures.jsonl
```

### Analysing one capture you were given

```powershell
python -m app.cli check "D:\captures\from-ntro.pcapng"
```

Use this for a capture that did not come from the lab. It prints a per-session table
(`session / proto:port / TLS / rules / ML / agree`), the finding count, the capture
posture, whether the rule engine and the model agree, and - most importantly - whether the
session sits inside the range the model was trained on. If it does not, the ML class is
explicitly **not validated** for that capture and you should rely on the rule findings.

If a capture yields no session at all, `check` says what it did see. Encrypted streams on a
port TShark does not recognise are listed with their TLS version, SNI and certificate
visibility, and the protocol inside is left unnamed rather than guessed from a port number.

### Proving it works on captures the model has never seen

```powershell
python tools\lab_capture_toolkit.py variants --outdir samples\variants
python tools\capability_test.py
```

The first command re-captures the nine lab scenarios on ports that the training set does
not contain; the second measures the analyzer against them and writes
`docs\CAPABILITY_TEST.md`. Both are also useful as a live demonstration: the captures are
generated in front of the judge in about thirty seconds.

On Windows every port can be used. On Linux or macOS, ports below 1024 (25, 110, 143, 465,
587, 993, 995) need `sudo`; the toolkit prints `SKIPPED` for them instead of writing an
empty capture, and the high-port variants (2525, 8110, 8143) need no elevation.

Outputs, all in the `--out` folder:

| File | Contents |
|---|---|
| `captures.jsonl` | One complete record per capture, written as each one finishes |
| `captures.csv` | One row per capture: sessions, findings by severity, posture, risk class |
| `session_features.csv` | One row per session: 26 features plus the rule label, ML label and finding codes |
| `failures.jsonl` | Only captures that failed, with the reason - one bad file never stops the batch |

A 14.88 MB mixed-protocol capture is parsed in a few seconds, and the whole 13-capture
sample set takes about 4 seconds on two cores.

---

## G. Run it in Docker (optional)

The API, TShark and model training are all handled by the image.

```powershell
docker compose up --build          # starts on http://localhost:8000
docker compose down                # stop it
```

The dashboard is at http://localhost:8000/dashboard. `data\` and `models\` are mounted
from your machine, so results and the trained model survive a rebuild.

---

## H. Housekeeping, when the folders fill up

Every upload is stored forever in `data\analyses\`, so after several runs the folder
holds several copies of each capture.

```powershell
.\scripts\clear_analyses.ps1                  # list only: version, sessions, size, stale yes/no
.\scripts\clear_analyses.ps1 -All -Force      # delete every stored analysis
.\scripts\clear_analyses.ps1 -Keep 13 -Force  # keep the 13 newest, delete the rest
.\scripts\clear_analyses.ps1 -StaleOnly -Force # delete only results from older builds
```

Nothing is ever deleted without `-Force`. `export_reports.ps1` already takes only the
newest analysis of each capture, so a full folder does not break your reports - it just
uses disk space.

---

## I. If something goes wrong

Three upload results that are answers, not failures:

| What you see | What it means | What to do |
|---|---|---|
| `422 The uploaded file is empty. Nothing was analysed.` | The file has zero bytes | Re-export the capture; the upload was refused so no empty result is stored |
| `422 tshark: The file ... isn't a capture file in a format TShark understands.` | Not a capture, or a corrupt one | Check you exported PCAP/PCAPNG and not, for example, a CSV or a text log |
| Dashboard shows **NO MAIL SESSIONS - nothing to score** | It parsed, but held no SMTP/IMAP/POP3 traffic | Correct behaviour. The tool only reads mail traffic, so it deliberately does not score other protocols. Use a capture that contains mail |
| Dashboard shows **UNCLASSIFIED - encrypted traffic found, protocol not provable** | Implicit TLS on a port TShark does not recognise, so there is no protocol vocabulary to read | Not a bug. The stream is described (port, TLS version from the server's hello, SNI, certificate visibility). Ask for the server configuration or a capture with the connection setup |


| Symptom | Cause | Fix |
|---|---|---|
| `The term '.\scripts\...ps1' is not recognized` | The file is not on this machine - the bundle was not extracted | Extract the update bundle with *Replace the files in the destination*, then run `.\scripts\check_files.ps1` (`Missing: 0` means you are up to date) |
| `A parameter cannot be found that matches parameter name ...` | Running an old copy of a script | Same fix: extract the bundle again |
| API did not answer / keeps starting | First start imports scikit-learn, reportlab and FastAPI from disk; antivirus makes this slow | Wait, or `.\scripts\restart_and_test.ps1 -StartupTimeout 300` |
| `ML model: rule-fallback (stale)` or `not_loaded` | The model was trained before the code changed, or never trained | `python -m app.ml.train`, then restart |
| `TShark available: False` | Wireshark/TShark not installed or not on PATH | Install it, or set `$env:SECUREMAILSCOPE_TSHARK_PATH` |
| Upload returns 400 | File extension not accepted | Allowed: `.pcap`, `.pcapng`, `.cap`, `.pcap.gz`, `.json` |
| Upload returns 503 | TShark missing | Same as above |
| Upload returns 422 | The capture could not be parsed | Check the file opens in Wireshark |
| Dashboard shows "The API is not answering" | Backend stopped or wrong port | Start it, press Refresh in the page |
| Reports show very old numbers | Old analyses still stored | `.\scripts\clear_analyses.ps1 -StaleOnly -Force`, then re-run |
| `python -m app.cli` prints nothing | The subcommand is missing: use `batch`, `export`, `doctor` or `verify` |
| `No module named uvicorn` / `No module named pytest` | Virtual environment not active, or dependencies missing | Activate `.venv`, then `python -m pip install -r requirements-dev.txt` |

---

## J. The order for your demo

```powershell
cd "D:\CryptoPost SIH\securemailscope"
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass) ; (& ".\.venv\Scripts\Activate.ps1")

.\scripts\restart_and_test.ps1          # backend up, all sample captures, ML agrees
start http://localhost:8000/dashboard   # upload a capture, click a session row
.\scripts\export_reports.ps1            # JSON + HTML + PDF for the submission pack
python tools\build_dashboard_snapshot.py # offline dashboard file for the slide deck
```

Behind the scenes, the backend serves these routes - `GET /dashboard` for the dashboard,
`POST /api/v1/analyses/upload` for uploads, `GET /api/v1/analyses/{id}/reports/{json|html|pdf}`
for reports. Everything is passive: no capture is sent anywhere, nothing is decrypted,
and no email content is read.
