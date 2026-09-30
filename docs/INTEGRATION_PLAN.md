# Integration plan: frontend + live demo

Written for the situation we are actually in: two days left, the backend is finished and
verified, and the remaining risk is the demo. Everything below is in the order that
protects the mark.

---

## 0. Verdict: yes, start now, in this order

| Order | What | Owner | Why this order |
|---|---|---|---|
| 1 | **Run the backend and prove it works on your machine** (30 min) | you | Every later step depends on this; nothing else can be tested until the API answers |
| 2 | **Decide: bundled dashboard, or your own frontend?** (5 min) | you | Below are two honest paths; do not build both |
| 3 | **Wire the chosen frontend to the five endpoints** (half a day) | frontend | This is the graded deliverable: an interactive dashboard |
| 4 | **Rehearse the demo end to end** (1 hour) | whole team | The demo is what the judges score, not the repo |
| 5 | **Only if time remains: add one differentiator** (see section 5) | you | Never at the cost of steps 1-4 |

---

## 1. Prove the backend first (30 minutes, do this before anything else)

```powershell
cd "D:\CryptoPost SIH\securemailscope"
python -m app.ml.train            # once, after copying the update bundle
python -m app.cli doctor          # TShark, model, sample counts
python scripts\restart_and_test.ps1
```

Then open `http://127.0.0.1:8000/dashboard` and upload three files in this order:

1. `samples\lab\smtp-starttls-rejected.pcapng` - must show `STARTTLS_REJECTED` and
   `PLAINTEXT_AUTHENTICATION`, posture 0, CRITICAL.
2. `samples\lab\imaps-tls10-legacy.pcapng` - must show `DEPRECATED_TLS_VERSION`,
   posture 19, CRITICAL.
3. `samples\variants\imaps-null-cipher-port9993.pcapng` - must show **UNCLASSIFIED**, not a
   green score.

If those three look right, the backend is demo-ready and you can stop testing it.

---

## 2. The frontend decision

### Path A - use the bundled dashboard (recommended for the deadline)

`GET /dashboard` already ships inside the backend. It is self-contained (no CDN, works with
no internet), reads the same endpoints, uploads captures, renders sessions and findings,
and links the JSON/HTML/PDF exports. **Zero integration work.**

When a judge asks "where is the frontend?", you open `/dashboard`, or you use the offline
snapshot (`python tools\build_dashboard_snapshot.py` → one HTML file with the analyses baked
in) which also works on a laptop with nothing installed.

### Path B - build a separate frontend (only if you already have React/Vue work started)

The contract is `FRONTEND_API.md`. Five calls cover the whole application:

| # | Call | Used for |
|---|---|---|
| 1 | `GET /api/v1/health` | header status: TShark, model version |
| 2 | `POST /api/v1/analyses/upload` (multipart) | the upload button |
| 3 | `GET /api/v1/analyses?summary_only=true` | the list of captures |
| 4 | `GET /api/v1/analyses/{id}` | the detail view of the opened capture |
| 5 | `GET /api/v1/analyses/{id}/reports/{json,html,pdf}` | the export buttons |

Non-negotiable frontend rules, each learned from a real failure:

1. **Allow a long timeout on upload.** It is synchronous: 1.5 MB / 300 sessions takes 24 s,
   14.7 MB / 3,000 sessions takes 236 s. Show an "analysing…" state.
2. **Use `summary_only=true` for the list.** The full list was 16.6 MB with eight captures
   stored; the light one is 0.01 MB.
3. **Never render a green risk badge for a capture with no sessions.** `posture=100, LOW` is
   the default for an empty result, so check `unclassified_streams` first, then
   `total_sessions == 0`, and only then show a score.
4. **Show the `detail` string on 400/422/503.** Those are designed answers
   ("The uploaded file is empty. Nothing was analysed."), not crashes.
5. **CORS is already open** (`allow_origins` defaults to `*`), so a frontend on another port
   works without changes. In production, set `SECUREMAILSCOPE_CORS_ORIGINS` to the real origin.

---

## 3. The demo script (rehearse until it is boring)

Total 4 minutes. Narrate the *evidence discipline*, not the features - that is what makes
this different from every other team's tool.

| Time | Action | What you say |
|---|---|---|
| 0:00 | `python -m app.cli doctor` | "TShark present, model version, environment healthy." |
| 0:20 | Upload `smtp-starttls-rejected.pcapng` on `/dashboard` | "A server that refuses STARTTLS and then accepts credentials in the clear: two findings, posture 0." |
| 1:00 | Open the session, show the finding evidence | "Every finding carries the frames and the evidence it was derived from." |
| 1:30 | Upload `imaps-tls13-cert-hidden.pcapng` | "TLS 1.3 hides the certificate, so the tool reports `CERTIFICATE_NOT_OBSERVED` instead of inventing a verdict. Missing evidence is never treated as insecure." |
| 2:00 | Upload `imaps-null-cipher-port9993.pcapng` | "Implicit TLS on a port we do not recognise: we say UNCLASSIFIED and describe the stream, rather than guessing from the port number." |
| 2:30 | Export PDF and HTML for the first capture | "JSON, HTML and PDF, from the same result." |
| 3:00 | Run `python tools\capability_test.py` | "This generates captures on ports the model never trained on, and measures the analyzer against them: 6 with every expected finding, 5 honestly unclassified, 0 crashes." |
| 3:40 | Close | "Rules are the evidence; the model is a triage layer that tells you when it is out of its depth. 60 of 69 held-out sessions agree with the rules." |

**Fallbacks if something fails mid-demo:** the offline snapshot HTML (no server needed), the
`reports\` folder with pre-exported JSON/HTML/PDF, and `python -m app.cli check <capture>`
which prints the whole assessment as text.

---

## 4. What "integrated" means, as a checklist

- [ ] Backend starts with `scripts\restart_and_test.ps1` and `/dashboard` loads
- [ ] All three capture types above render correctly (scored / certificate-unknown / unclassified)
- [ ] Upload from the frontend works, with a visible progress state
- [ ] Session list shows rule class, ML class and the agreement
- [ ] A finding's evidence and recommendation are visible per session
- [ ] JSON, HTML and PDF exports open
- [ ] The offline snapshot works with the server stopped
- [ ] The demo has been run start to finish twice without a fix in between

---

## 5. The differentiator question, answered honestly

You asked for a live agent that sits on the WiFi and warns before mail is opened. Here is
what is true, what is buildable in the time left, and what would damage us.

### What is not possible (and must never be claimed)

* A laptop in monitor mode **cannot** see all traffic on a switched or encrypted WiFi
  network. Most of what other devices send is not visible from one machine.
* We **cannot read mail content**, by design and by promise. We detect the *absence of
  protection*, not the content.
* Passive capture **cannot prevent** anything. It can warn while or immediately after
  credentials cross the wire, not before the user acts.
* Passive capture **cannot prove** a MITM or downgrade. It can show that the configuration
  would allow one.

### What is buildable in a few hours, and is genuinely impressive

A **live watch agent for authorised positions**: `tools/live_watch.py` captures on an
interface the user names, in rotating chunks, runs the existing engine on each chunk, and
raises an alert when it sees a cleartext authentication or a failed STARTTLS/STLS upgrade -
the two things that actually put mail credentials at risk.

Why it is defensible rather than gimmicky:

* it reuses the whole engine, so there is no new unverified code path;
* it runs only on an interface the operator names, with an explicit consent flag, and it
  says in its own output that it sees only the traffic forwarded to that interface;
* it never stores mail content, and the alerts are the same findings the reports show;
* it turns the project from "a PCAP analyser" into "a monitor that tells you when your own
  organisation is leaking credentials" - which matches the national-security framing.

The one-sentence framing for judges: *"Authorised, passive, local. It sees only the segment
it is attached to, it never reads mail, and it tells you within seconds when a session
authenticates in the clear."*

### Cheaper alternatives, ranked by impact per hour of work

| Idea | Effort | Impact | Note |
|---|---|---|---|
| **Live watch agent** (above) | 3-5 h with testing | High - it is the story nobody else will have | Must be scoped and described exactly as above |
| **Exposure summary in the report**: "what an observer on this path could have harvested" - count of cleartext authentications, servers that accept downgrade, ports serving mail in the clear | 1-2 h | High, and it is already 90% computed | Pure presentation of existing findings; no new claims |
| **"Fix list" for a mail administrator**, sorted by effort/impact ("turn off AUTH on 25", "renew the certificate before 2026-10-01") | 1 h | Medium | Turns findings into an action list a judge can picture |
| **Compare two captures** (before/after a config change) | 2-3 h | Medium | Nice for "show me it works", weak as a headline |
| **Hindi/bilingual report output** | 1 h | Low-medium | Only if the panel is regional-language focused |

### My recommendation

Start the integration now (steps 1-4). If, and only if, steps 1-4 are green by tomorrow
evening, build the **live watch agent** as the differentiator - it is the one addition that
changes how the project is perceived, and it is honest if we describe its limits in the same
breath. The exposure summary is the cheap backup: it costs an hour and needs no new claims.

Do **not**: add a deep-learning model, claim MITM detection, claim to read mail, or promise
monitoring of networks we cannot see. Those are the ways a strong project loses marks.
