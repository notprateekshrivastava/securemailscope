# Screenshots and sample documents

Everything in this folder is generated from the real system - no mock-ups, no edited images.
The captures analysed are the ones in `samples\` and `testset\`.

## Dashboard

| File | What it shows |
|---|---|
| `01-dashboard-overview.png` | The verdict band, posture ring and severity distribution for a 51-session capture |
| `02-dashboard-sessions.png` | The Sessions tab: one row per session, upgrade state, rule class, ML class and score |
| `03-dashboard-session-detail.png` | A session expanded in place: TLS evidence, certificate, STARTTLS/STLS and the findings for that session |
| `04-dashboard-findings.png` | The Findings tab, highest severity first, with evidence and the recommended fix |
| `05-dashboard-critical-capture.png` | A one-session capture that is CRITICAL: weak certificate on an IMAP STARTTLS upgrade |
| `06-dashboard-empty-state.png` | What the page looks like before anything is analysed |
| `dashboard_offline_snapshot.html` | The whole dashboard as **one file with the analyses embedded** - opens with no server and no network. Use this for the slide deck or a judge's laptop |

## Reports

| File | What it shows |
|---|---|
| `report_pdf_ultimate.pdf` | The PDF report for the 51-session capture: metric strip, severity distribution, findings, sessions, actions, evidence statement |
| `report_html_ultimate.html` | The same capture as the HTML report |
| `report_pdf_weak_certificate.pdf` | The PDF report for a single-session CRITICAL capture - the shortest useful report |

## How to regenerate them

```powershell
# 1. dashboard, live (the interactive version, with upload enabled)
.\scripts\restart_and_test.ps1 -SkipTests
#    then open http://localhost:8000/dashboard

# 2. dashboard, offline single file (for slides)
python tools\build_dashboard_snapshot.py
#    reports\dashboard_snapshot.html

# 3. reports for one capture
curl.exe -F "file=@samples\The-Ultimate-PCAP.pcapng" -F "uploaded_by=user" ^
  http://localhost:8000/api/v1/analyses/upload
#    then the JSON / HTML / PDF buttons in the dashboard header
#    or: .\scripts\export_reports.ps1
```

## Note for the submission document

The screenshots are dark-theme because that is the dashboard. If a screenshot has to sit on a
white page in the SIH write-up, the HTML report (`report_html_ultimate.html`) prints cleanly
on white, and the PDF needs no conversion at all. Both are the same content as the dashboard.
