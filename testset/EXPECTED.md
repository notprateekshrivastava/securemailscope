# What the test set expects, declared before it was measured

Dataset version 1.0. Every expectation below comes from the server configuration that was used to generate the traffic, and was written before any capture was analysed. The scoring script reads `ground_truth.json`; it never re-derives the answer from the analyzer's output.

## The axis this set covers that training did not

* **IMAP STARTTLS** upgraded and refused, across five TLS profiles.
* **POP3 STLS** upgraded and refused - POP3 had no upgrade capture at all before this.
* **SMTP with no STARTTLS offered**, next to SMTP that offers it and refuses it.
* Multi-session files mixing three protocols, eight profiles and both port families.

## Class expectations: exact where it is not a judgement call

| Situation | Expected | Why exact or band |
|---|---|---|
| Password sent with no tunnel (refused upgrade, no upgrade offered, cleartext login) | **CRITICAL** | The credential was readable. Not a policy choice |
| Modern TLS, automatic upgrade or implicit | **LOW** | Nothing weak was configured |
| TLS 1.3 | **LOW** | The certificate is encrypted; not observed is not a fault |
| Deprecated TLS 1.0, weak certificate, NULL cipher | HIGH..CRITICAL | The exact band is a policy decision, the direction is not |
| Static RSA / no forward secrecy, legacy CBC | MEDIUM..HIGH | Same |

## Unseen situations (no training capture has this shape)

| File | Sessions | Modes | Profiles | Bytes |
|---|---|---|---|---|
| `smtp-587-starttls-modern` | 1 | smtp_secure | modern | 6,700 |
| `smtp-587-starttls-legacy-tls10` | 1 | smtp_secure | legacy-tls10 | 7,316 |
| `smtp-587-starttls-weak-cert` | 1 | smtp_secure | weak-cert | 6,680 |
| `smtp-587-starttls-cbc` | 1 | smtp_secure | cbc-only | 6,880 |
| `smtp-587-starttls-static-rsa` | 1 | smtp_secure | static-rsa | 6,764 |
| `smtp-25-starttls-rejected` | 1 | smtp_reject_starttls | None | 2,328 |
| `smtp-2525-no-starttls` | 1 | smtp_no_starttls | None | 2,060 |
| `imap-143-starttls-modern` | 1 | imap_starttls | modern | 6,972 |
| `imap-143-starttls-legacy-tls10` | 1 | imap_starttls | legacy-tls10 | 8,672 |
| `imap-143-starttls-weak-cert` | 1 | imap_starttls | weak-cert | 6,696 |
| `imap-143-starttls-cbc` | 1 | imap_starttls | cbc-only | 7,204 |
| `imap-143-starttls-null-cipher` | 1 | imap_starttls | null-cipher | 6,832 |
| `imap-143-starttls-rejected` | 1 | imap_reject_starttls | None | 2,292 |
| `imap-8143-cleartext-login` | 1 | imap_cleartext_login | modern | 6,916 |
| `pop3-110-stls-modern` | 1 | pop3_stls | modern | 7,172 |
| `pop3-110-stls-legacy-tls10` | 1 | pop3_stls | legacy-tls10 | 9,588 |
| `pop3-110-stls-weak-cert` | 1 | pop3_stls | weak-cert | 6,896 |
| `pop3-110-stls-cbc` | 1 | pop3_stls | cbc-only | 7,400 |
| `pop3-110-stls-static-rsa` | 1 | pop3_stls | static-rsa | 7,284 |
| `pop3-110-stls-rejected` | 1 | pop3_reject_stls | None | 2,668 |
| `pop3-8110-plaintext` | 1 | pop3_plaintext | None | 2,436 |
| `smtps-465-implicit-modern` | 1 | implicit_tls | modern | 6,724 |
| `imaps-993-implicit-legacy-tls10` | 1 | implicit_tls | legacy-tls10 | 9,408 |
| `pop3s-995-implicit-weak-cert` | 1 | implicit_tls | weak-cert | 6,944 |
| `field-mixed-1` | 26 | imap_cleartext_login, imap_reject_starttls, imap_starttls, implicit_tls, pop3_plaintext, pop3_reject_stls, pop3_stls, smtp_no_starttls, smtp_reject_starttls, smtp_secure | None, cbc-only, legacy-tls10, modern, modern-tls13, null-cipher, static-rsa, weak-cert | 159,736 |
| `field-mixed-2` | 26 | imap_cleartext_login, imap_reject_starttls, imap_starttls, implicit_tls, pop3_plaintext, pop3_reject_stls, pop3_stls, smtp_no_starttls, smtp_reject_starttls, smtp_secure | None, cbc-only, legacy-tls10, modern, modern-tls13, null-cipher, static-rsa, weak-cert | 159,648 |
| `field-large` | 26 | imap_cleartext_login, imap_reject_starttls, imap_starttls, implicit_tls, pop3_plaintext, pop3_reject_stls, pop3_stls, smtp_no_starttls, smtp_reject_starttls, smtp_secure | None, cbc-only, legacy-tls10, modern, modern-tls13, null-cipher, static-rsa, weak-cert | 6,375,100 |

## Also present, for contrast (a training capture has this shape)

| File | Sessions | Modes | Profiles | Bytes |
|---|---|---|---|---|

## What this test does not prove

* It is synthetic and self-generated. It is not human analyst ground truth, and the
  model was trained on rule labels, so agreement with the rules is what is measured.
* It says nothing about real-world attack rates, or about traffic from a network we
  have never seen. A capture from NTRO would be the only thing that could.
* The band expectations are policy statements. Where the analyzer disagrees with a
  band, the honest reading is that the policy and the code need to be reconciled -
  it is not automatically an analyzer bug, and it is reported either way.
