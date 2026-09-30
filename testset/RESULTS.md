# Held-out test set - measured results

Analyzer `1.0.0`. Expectations were written before the captures were
analysed (`EXPECTED.md`, `ground_truth.json`); this file is only the measurement.

## Headline

| Question | All sessions | Non-repeated sessions | At scale (repeated file) |
|---|---|---|---|
| Session reconstructed | 1116/1116 (100.0%) | 76/76 (100.0%) | 1040/1040 (100.0%) |
| Declared findings all reported | 1116/1116 (100.0%) | 76/76 (100.0%) | 1040/1040 (100.0%) |
| No forbidden finding invented | 1116/1116 (100.0%) | 76/76 (100.0%) | 1040/1040 (100.0%) |
| TLS facts as configured | 1116/1116 (100.0%) | 76/76 (100.0%) | 1040/1040 (100.0%) |
| Risk class in the expected band | 1116/1116 (100.0%) | 76/76 (100.0%) | 1040/1040 (100.0%) |

**Sessions measured:** 1116 across 27 files. They cover **50 distinct (protocol, port, mode, profile) situations**; the two field files appear as 52 sessions because each situation is captured on both the standard and the alternate port family, and the large file is one of them repeated. 1116 sessions have a shape no training capture had.

**ML agreement with the rule engine:** 1073/1116 (96.1%) overall, 1073/1116 (96.1%) on the unseen situations.

The middle column is every session outside the large file: 24 single-session captures plus the 52 field sessions. The right-hand column is the same 26-session file repeated with shifted timestamps - it measures session reconstruction and throughput at scale, not new diversity, so the middle column is the one to read for correctness.

## Per capture

| Capture | Group | Sessions | Matched | Findings | No false findings | Facts | Class |
|---|---|---|---|---|---|---|---|
| `smtp-587-starttls-modern` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-587-starttls-legacy-tls10` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-587-starttls-weak-cert` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-587-starttls-cbc` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-587-starttls-static-rsa` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-25-starttls-rejected` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtp-2525-no-starttls` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-modern` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-legacy-tls10` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-weak-cert` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-cbc` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-null-cipher` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-143-starttls-rejected` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imap-8143-cleartext-login` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-modern` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-legacy-tls10` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-weak-cert` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-cbc` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-static-rsa` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-110-stls-rejected` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3-8110-plaintext` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `smtps-465-implicit-modern` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `imaps-993-implicit-legacy-tls10` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `pop3s-995-implicit-weak-cert` | singles | 1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| `field-mixed-1` | field | 26 | 26/26 | 26/26 | 26/26 | 26/26 | 26/26 |
| `field-mixed-2` | field | 26 | 26/26 | 26/26 | 26/26 | 26/26 | 26/26 |
| `field-large` | large | 1040 | 1040/1040 | 1040/1040 | 1040/1040 | 1040/1040 | 1040/1040 |

## What was observed, per situation

One row per (protocol, port, mode, profile). `Cert` is what the analyzer actually
saw: a certificate, nothing at all because there was no handshake, or an encrypted
one it declines to call absent. `FS` is forward secrecy (yes/no) where a key exchange
happened.

| Situation | TLS | Cipher | Cert | FS | Findings reported | Rules | ML |
|---|---|---|---|---|---|---|---|
| IMAP:143 imap_cleartext_login/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | PLAINTEXT_AUTHENTICATION | CRITICAL | HIGH |
| IMAP:143 imap_reject_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| IMAP:143 imap_starttls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| IMAP:143 imap_starttls/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| IMAP:143 imap_starttls/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| IMAP:143 imap_starttls/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| IMAP:143 imap_starttls/null-cipher | TLS 1.2 | TLS_RSA_WITH_NULL_SHA (0x0 | yes | NO | INSECURE_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| IMAP:993 implicit_tls/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| IMAP:993 implicit_tls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| IMAP:993 implicit_tls/modern-tls13 | TLS 1.3 | TLS_AES_256_GCM_SHA384 (0x | encrypted, not visible | yes | CERTIFICATE_NOT_OBSERVED | LOW | LOW |
| IMAP:8143 imap_cleartext_login/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | PLAINTEXT_AUTHENTICATION | CRITICAL | HIGH |
| IMAP:8143 imap_reject_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| IMAP:8143 imap_starttls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| IMAP:8143 imap_starttls/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| IMAP:8143 imap_starttls/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| IMAP:8143 imap_starttls/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| IMAP:8143 imap_starttls/null-cipher | TLS 1.2 | TLS_RSA_WITH_NULL_SHA (0x0 | yes | NO | INSECURE_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| POP3:110 pop3_plaintext/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION | CRITICAL | CRITICAL |
| POP3:110 pop3_reject_stls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| POP3:110 pop3_stls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| POP3:110 pop3_stls/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| POP3:110 pop3_stls/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| POP3:110 pop3_stls/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| POP3:110 pop3_stls/static-rsa | TLS 1.2 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | MEDIUM | MEDIUM |
| POP3:995 implicit_tls/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| POP3:995 implicit_tls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| POP3:8110 pop3_plaintext/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION | CRITICAL | CRITICAL |
| POP3:8110 pop3_reject_stls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| POP3:8110 pop3_stls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| POP3:8110 pop3_stls/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| POP3:8110 pop3_stls/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| POP3:8110 pop3_stls/static-rsa | TLS 1.2 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | MEDIUM | MEDIUM |
| POP3:8110 pop3_stls/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| SMTP:25 smtp_reject_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| SMTP:465 implicit_tls/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| SMTP:465 implicit_tls/modern-tls13 | TLS 1.3 | TLS_AES_256_GCM_SHA384 (0x | encrypted, not visible | yes | CERTIFICATE_NOT_OBSERVED | LOW | LOW |
| SMTP:587 smtp_no_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION | CRITICAL | CRITICAL |
| SMTP:587 smtp_reject_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| SMTP:587 smtp_secure/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| SMTP:587 smtp_secure/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| SMTP:587 smtp_secure/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |
| SMTP:587 smtp_secure/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| SMTP:587 smtp_secure/static-rsa | TLS 1.2 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | MEDIUM | MEDIUM |
| SMTP:2525 smtp_no_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION | CRITICAL | CRITICAL |
| SMTP:2525 smtp_reject_starttls/- | cleartext | cleartext | none (no handshake) | n/a | PLAINTEXT_AUTHENTICATION, PLAINTEXT_EMAIL_SESSION, STARTTLS_REJECTED | CRITICAL | CRITICAL |
| SMTP:2525 smtp_secure/modern | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | none | LOW | LOW |
| SMTP:2525 smtp_secure/legacy-tls10 | TLS 1.0 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | DEPRECATED_TLS_VERSION, LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | CRITICAL | CRITICAL |
| SMTP:2525 smtp_secure/cbc-only | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | LEGACY_CBC_CIPHER | MEDIUM | MEDIUM |
| SMTP:2525 smtp_secure/static-rsa | TLS 1.2 | TLS_RSA_WITH_AES_128_CBC_S | yes | NO | LEGACY_CBC_CIPHER, NO_FORWARD_SECRECY | MEDIUM | MEDIUM |
| SMTP:2525 smtp_secure/weak-cert | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_128 | yes | yes | CERTIFICATE_EXPIRED, CERTIFICATE_HOSTNAME_MISMATCH, WEAK_CERTIFICATE_KEY | CRITICAL | CRITICAL |

## Where the ML layer disagreed with the rules

The rules are the evidence. These are the sessions where the triage layer
reached a different class on data it had never seen.

| Situation | Rules | ML | Sessions |
|---|---|---|---|
| IMAP:143 imap_cleartext_login/modern | CRITICAL | HIGH | 41 |
| IMAP:8143 imap_cleartext_login/modern | CRITICAL | HIGH | 2 |

Every session met every declared expectation.

## How to read this

* **Findings** and **facts** are the independent part: they come from the server
  configuration, which the model has no influence over.
* **Class** checks the analyzer against the project's own documented policy bands
  (cleartext credentials are CRITICAL by definition; a deprecated version, weak
  certificate or NULL cipher must land above a healthy session; the exact band in
  between is a policy choice, so it is declared as a band).
* **ML agreement** is agreement with the rule engine, not with human ground truth.
  Where they disagree the finding is the evidence and the ML class is a hint.
* A synthetic set cannot show that the analyzer works on traffic from a network it
  has never seen. Only a capture from the target organisation could.
