# SecureMailScope: exact problem-statement scope

## Product definition

SecureMailScope is **not only a PCAP analyser**. It is a passive forensic security-posture assessment system:

```text
Captured email traffic
  -> reconstruct evidence
  -> identify cryptographic weaknesses
  -> explain where the mail infrastructure is lacking
  -> assess risk and anomalous behaviour
  -> prioritise what to fix first
  -> recommend concrete mitigation
  -> export a forensic report/dashboard
```

The system should not read email content or claim to prove an attack from incomplete evidence.

## Official inputs

- PCAP files containing SMTP, IMAP and POP3 communications.
- Synthetic SMTP/IMAPS/POP3S captures are explicitly acceptable for the competition dataset.

## Official evidence extraction outputs

### 1. Email protocol and session evidence

- Automatic SMTP identification.
- Automatic IMAP identification.
- Automatic POP3 identification.
- Explicit TLS versus implicit TLS.
- Client and server IP/port.
- TCP stream ID.
- Session start/end/duration.
- Packet and byte counts.
- Retransmissions/resets/handshake failures.
- Complete, partial or unknown evidence status.

### 2. Encryption-transition evidence

- SMTP `EHLO`/`STARTTLS`.
- IMAP `CAPABILITY`/`STARTTLS`.
- POP3 `STLS`.
- Upgrade advertised.
- Upgrade command observed.
- Server accepted or rejected the upgrade.
- TLS handshake observed after the upgrade.
- Upgrade success/failure.
- Authentication before encryption.
- Possible downgrade/stripping indicators, stated cautiously.

### 3. TCP and TLS evidence

- Reconstructed TCP sessions/streams.
- Visible ClientHello and ServerHello.
- Handshake completeness.
- Negotiated TLS version.
- Client-offered versions where visible.
- Negotiated cipher suite.
- Key exchange mechanism.
- Supported group/key share where visible.
- Signature algorithm where visible.
- SNI/server name.
- Session resumption.
- TLS alerts and repeated handshakes.
- Handshake duration and failures.

### 4. X.509 certificate evidence

- Leaf and intermediate certificates when captured.
- Subject, CN and SAN.
- Issuer and serial number.
- Valid-from and valid-until dates.
- Days until expiry.
- Expired/not-yet-valid status.
- Self-signed status.
- Hostname/SNI match.
- Public-key algorithm.
- Public-key length/curve.
- Certificate signature and hash algorithm.
- SHA-1/MD5 detection.
- Certificate fingerprint.
- Chain order/linkage.
- Chain complete/incomplete/unknown status.

A passive capture may not contain a root or intermediate certificate. Therefore the product must report `INCOMPLETE` or `UNKNOWN` instead of claiming trust when evidence is absent.

## Official assessment outputs

The assessment layer answers: **where is this communication or mail server lacking, how serious is it, and what should be done?**

### Cryptographic weaknesses

- SSLv3/TLS 1.0/TLS 1.1.
- NULL, EXPORT, RC4, RC2, anonymous and other obsolete ciphers.
- 3DES and legacy CBC configurations.
- Static RSA/no forward secrecy.
- Weak DH/EC parameters when visible.
- RSA keys below 2048 bits.
- Weak certificate signature algorithms.
- Expired/not-yet-valid certificates.
- Self-signed or hostname-mismatched certificates.
- Incomplete certificate chains.
- Plaintext email sessions.
- Plaintext authentication before encryption.
- STARTTLS/STLS rejected or not completed.
- TLS handshake instability and repeated failures.
- Certificate or cryptographic posture changes.

### Findings

Every finding should include:

- Finding code.
- Severity: INFO/LOW/MEDIUM/HIGH/CRITICAL.
- Description.
- Affected session/server.
- Evidence and stream/frame reference where available.
- Confidence/evidence completeness.
- Score impact.
- Concrete remediation.

## Official AI/ML outputs

- Cryptographic risk classification: LOW/MEDIUM/HIGH/CRITICAL.
- ML confidence.
- Suspicious TLS anomaly score.
- Anomalous/not-anomalous indicator.
- Security posture score.
- Session-level risk.
- Mail-server-level risk.
- Overall capture/enterprise risk.
- Threat prioritisation.
- Explainable reason codes.

The ML layer is hybrid:

- Deterministic rules produce cryptographic facts and remediation.
- A supervised tabular model classifies session risk.
- An unsupervised model detects unusual combinations against a baseline.
- Rule score, ML class and anomaly score are displayed separately.

## Official final outputs

- Comprehensive security posture assessment.
- Prioritised security findings.
- Actionable recommendations.
- Interactive dashboard.
- JSON report.
- HTML report.
- PDF report.

## Extra features recommended for this MVP

### P1: Evidence completeness and traceability

Show whether a decision is based on a complete stream/handshake/certificate and link each finding to a TCP stream/frame.

### P1: Cryptographic fingerprint and baseline comparison

Store a server fingerprint and detect:

```text
Previous: TLS 1.3 + ECDHE + valid certificate
Current:  TLS 1.0 + RSA + expired certificate
Result:   Cryptographic posture degraded
```

### P1: PCAP replay/live dashboard

Replay an authorised PCAP at a controlled rate and stream session findings to the dashboard. This demonstrates live monitoring without incorrectly claiming that any laptop can observe every Wi-Fi client.

### P1: What-if policy simulation

Allow an administrator to simulate:

- Require TLS 1.2+.
- Require forward secrecy.
- Reject expired/mismatched certificates.
- Reject plaintext authentication.

Show the expected reduction in risk without actually blocking network traffic.

### P1: Privacy mode

Metadata-only processing, optional IP redaction and no email-content decryption.

## Explicit non-goals for the three-day build

- Actual enterprise-wide Wi-Fi interception from an ordinary laptop.
- Traffic blocking or an email security firewall.
- Reading/decrypting email content.
- Definitive proof of MITM from one incomplete PCAP.
- Full online revocation/trust validation in every environment.
- Generic LLM SOC chatbot.
- Blockchain features unrelated to the cryptographic posture objective.
