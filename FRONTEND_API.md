# Frontend integration contract

> **A working dashboard already ships with the backend** at `GET /dashboard`
> (`app\dashboard.py`). It uses exactly the endpoints below. Treat this document as
> the contract if you build a separate frontend, and as the reference for how the
> data is shaped.

The frontend can use the FastAPI service at `http://localhost:8000` during development. The production URL should be configured through an environment variable.

## Endpoints

### Health

```http
GET /api/v1/health
```

Response:

```json
{
  "status": "ok",
  "tshark_available": true,
  "ml_model_available": true,
  "version": "1.0.0"
}
```

### Demo fixture

Useful while the PCAP capture environment is not ready:

```http
POST /api/v1/demo/analysis
```

This returns three controlled sessions:

- Secure SMTP STARTTLS/TLS 1.3
- Weak IMAP STARTTLS/TLS 1.0 with legacy cipher and certificate problems
- Plaintext POP3 authentication

### Upload PCAP

```http
POST /api/v1/analyses/upload
Content-Type: multipart/form-data
file=<capture.pcap>
uploaded_by=user|ntro|team
```

The `uploaded_by` field is optional and defaults to `user`. Use `ntro` when the source is an NTRO-provided capture. The response is an `AnalysisResult` object and includes the upload provenance.

**The upload call is synchronous**, and a large capture takes a while: measured on two
cores, a 1.5 MB / 300-session file takes **24 s** and a 14.7 MB / 3,000-session file takes
**236 s**. Two consequences for the frontend:

* allow a long request timeout - minutes, not seconds;
* show a progress or "analysing…" state, because the browser will otherwise look frozen.

For anything larger than a few hundred sessions, prefer the CLI batch path
(`python -m app.cli batch <folder>`) and show its results, rather than uploading
capture by capture through the browser.

**Failure responses are answers, not bugs.** Show the `detail` string to the user:

| Status | `detail` example | Meaning |
|---|---|---|
| 400 | `Upload a PCAP/PCAPNG/CAP file` | Wrong file extension |
| 422 | `The uploaded file is empty. Nothing was analysed.` | Zero-byte upload, refused rather than stored |
| 422 | `tshark: The file ... isn't a capture file in a format TShark understands.` | Not a capture, or corrupt |
| 503 | `TShark is not installed...` | Server-side dependency missing |

### List analyses

```http
GET /api/v1/analyses                  # full records (kept for compatibility)
GET /api/v1/analyses?summary_only=true # summaries only - use this for a list
```

**Use `summary_only=true` for any list or table.** The full form returns every session and
every finding of every stored capture. Measured with eight stored analyses, one of which
holds 3,000 sessions: **16.6 MB versus 0.01 MB**. The light form keeps the whole `summary`
block (sessions, findings count, posture, class) and sets `sessions`, `findings` and
`recommendations` to empty lists with `metadata.summary_only = true`, so a card can render
without the payload.

Then fetch the one you open:

```http
GET /api/v1/analyses/{analysis_id}     # full record for that capture
```

### Read an analysis

```http
GET /api/v1/analyses/{analysis_id}
```

### Read one session

```http
GET /api/v1/analyses/{analysis_id}/sessions/{session_id}
```

### Download reports

```http
GET /api/v1/analyses/{analysis_id}/reports/json
GET /api/v1/analyses/{analysis_id}/reports/html
GET /api/v1/analyses/{analysis_id}/reports/pdf
```

## Dashboard fields

The frontend should display these main values from `summary`:

```text
summary.overall_risk_score       0 to 100; higher is worse
summary.overall_posture_score    0 to 100; higher is better
summary.overall_risk_class       LOW/MEDIUM/HIGH/CRITICAL
summary.total_sessions
summary.tls_sessions
summary.plaintext_sessions
summary.anomalous_sessions
summary.findings_by_severity
summary.protocols
summary.tls_versions
summary.evidence_completeness
```

For a session row use:

```text
session_id
protocol
client_ip/client_port
server_ip/server_port
tls.tls_version
tls.cipher_suite
tls.key_exchange
tls.forward_secrecy
certificate.expired
certificate.chain_status
policy_risk_score
posture_score
policy_risk_class
ml.risk_class
ml.confidence
ml.anomaly_score
ml.anomalous
evidence_completeness
```

## Two response fields that must be displayed, not ignored

`unclassified_streams` and `unclassified_note` are set when a capture produced **no** email
session but did contain encrypted traffic that could not be attributed to SMTP, IMAP or
POP3 - which happens with implicit TLS on a port TShark does not recognise, because the
client's first byte is a TLS ClientHello and there is no protocol vocabulary to read.

An empty result must not be presented as a clean one. `summary.overall_posture_score` is
`100` and `overall_risk_class` is `LOW` for *any* capture with no sessions, including an
empty or unrecognised one, so those two fields alone must never drive a green badge. When
`sessions` is empty:

* if `unclassified_streams` is non-empty, show **UNCLASSIFIED** and list each stream
  (`stream_id`, `server_port`, `tls_version`, `tls_version_source`, `server_name`,
  `certificate_visible`, and a ready-made `description` string), plus `unclassified_note`;
* otherwise show a neutral **NO MAIL SESSIONS - nothing to score** state with `posture n/a`
  rather than a score.

The bundled dashboard implements exactly this; copy its behaviour.

## Important display rules

- `UNKNOWN` means the PCAP did not contain enough evidence. It does not automatically mean insecure.
- `policy_risk_score` is deterministic and explainable.
- `ml.confidence` is a percentage from 0 to 100 when the trained model is loaded.
- `ml.anomaly_score` is between 0 and 1, where higher means more unusual.
- Render every finding's `evidence`, `confidence`, and `recommendation` in the details view.
- Show frame/stream references so the result remains forensic and explainable.
