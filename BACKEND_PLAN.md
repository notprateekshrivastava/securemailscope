# Backend and AI/ML work split

## Backend responsibility

The backend owns:

1. PCAP upload and validation.
2. TShark invocation and TCP stream aggregation.
3. SMTP/IMAP/POP3 detection.
4. STARTTLS/STLS state detection.
5. TLS and certificate extraction.
6. Normalised session JSON.
7. Rules and findings.
8. ML risk/anomaly inference.
9. Posture and priority aggregation.
10. Recommendations.
11. JSON/HTML/PDF reports.
12. REST contract consumed by Prateek's frontend.

## Frontend responsibility

The frontend can consume the API and render:

- Upload state.
- Summary cards.
- Protocol and TLS charts.
- Session table.
- TLS/certificate detail panels.
- Finding evidence.
- Risk/anomaly views.
- Recommendations.
- Report download buttons.

The exact API contract is in `FRONTEND_API.md`.

## API contract

```text
GET  /api/v1/health
POST /api/v1/analyses/upload
POST /api/v1/demo/analysis
GET  /api/v1/analyses
GET  /api/v1/analyses/{analysis_id}
GET  /api/v1/analyses/{analysis_id}/sessions/{session_id}
GET  /api/v1/analyses/{analysis_id}/reports/json
GET  /api/v1/analyses/{analysis_id}/reports/html
GET  /api/v1/analyses/{analysis_id}/reports/pdf
POST /api/v1/models/reload
```

## Current implementation status

- [x] FastAPI application skeleton.
- [x] PCAP upload endpoint.
- [x] TShark JSON stream aggregation.
- [x] Protocol/port detection.
- [x] STARTTLS/STLS indicators.
- [x] TLS field extraction.
- [x] X.509 parser.
- [x] Deterministic rule engine.
- [x] Recommendations.
- [x] Synthetic Random Forest classifier.
- [x] Isolation Forest anomaly model.
- [x] Demo secure/weak/plaintext fixture.
- [x] JSON/HTML/PDF report generation.
- [x] Frontend integration contract.
- [x] Unit tests.

## Next implementation tasks

1. Install TShark and test against three real controlled PCAPs.
2. Confirm the exact TShark field names for the Wireshark version used by the team.
3. Add server-level aggregation and crypto fingerprints.
4. Add baseline/diff endpoint.
5. Add PCAP replay/WebSocket mode only after upload analysis is stable.
6. Add auth/rate limits before exposing a public deployment.

## ML honesty rule

The shipped model is trained on controlled synthetic session features because the official dataset permits participants to generate captures. The final presentation should say this clearly and show a validation report, without claiming production accuracy.
