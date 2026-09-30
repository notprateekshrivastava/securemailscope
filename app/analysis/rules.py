from __future__ import annotations

from ..schemas import Finding, ProtocolName, SessionAnalysis, Severity
from .ciphers import is_known_cipher
from .constants import TLS_VERSION_RANK


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 18,
    Severity.HIGH: 30,
    Severity.CRITICAL: 45,
}


def _finding(
    session: SessionAnalysis,
    code: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    evidence: list[str],
    score_impact: int | None = None,
    confidence: str = "HIGH",
) -> Finding:
    return Finding(
        code=code,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        score_impact=SEVERITY_WEIGHT[severity] if score_impact is None else score_impact,
        confidence=confidence,  # type: ignore[arg-type]
        session_id=session.session_id,
    )


def assess_session(session: SessionAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    tls = session.tls
    cert = session.certificate
    starttls = session.starttls
    protocol = session.protocol
    protocol_value = getattr(protocol, "value", protocol)
    version_rank = TLS_VERSION_RANK.get(tls.tls_version or "", 0)
    cipher = (tls.cipher_suite or "").upper()

    if protocol != ProtocolName.UNKNOWN and not tls.detected and not starttls.implicit_tls:
        severity = Severity.HIGH if starttls.plaintext_authentication_seen else Severity.MEDIUM
        findings.append(
            _finding(
                session,
                "PLAINTEXT_EMAIL_SESSION",
                severity,
                "Email session is not protected by TLS",
                "Application-layer email traffic was observed without a visible TLS session.",
                "Require TLS before authentication and prefer implicit TLS or successful STARTTLS/STLS.",
                [f"Protocol: {protocol_value}", f"Server port: {session.server_port}"],
            )
        )

    if starttls.plaintext_authentication_seen:
        findings.append(
            _finding(
                session,
                "PLAINTEXT_AUTHENTICATION",
                Severity.CRITICAL,
                "Authentication pattern observed before encryption",
                "A USER/PASS/LOGIN/AUTH pattern was observed before a successful TLS upgrade.",
                "Reject plaintext authentication and enforce TLS before credentials are accepted.",
                ["Plaintext authentication pattern observed", *starttls.evidence],
                score_impact=45,
            )
        )

    if tls.tls_version in {"SSLv3", "TLS 1.0"}:
        findings.append(
            _finding(
                session,
                "DEPRECATED_TLS_VERSION",
                Severity.CRITICAL,
                f"Deprecated protocol version: {tls.tls_version}",
                "The negotiated TLS version is obsolete and should not be used for enterprise email.",
                "Disable SSLv3/TLS 1.0 and enforce TLS 1.2 or TLS 1.3.",
                [f"Negotiated version: {tls.tls_version}"],
                score_impact=45,
            )
        )
    elif tls.tls_version == "TLS 1.1":
        findings.append(
            _finding(
                session,
                "LEGACY_TLS_VERSION",
                Severity.HIGH,
                "Legacy TLS 1.1 negotiated",
                "TLS 1.1 is deprecated and should be removed from modern mail infrastructure.",
                "Disable TLS 1.1 and enforce TLS 1.2 or TLS 1.3.",
                ["Negotiated version: TLS 1.1"],
            )
        )
    elif tls.detected and not tls.tls_version:
        findings.append(
            _finding(
                session,
                "TLS_VERSION_UNKNOWN",
                Severity.INFO,
                "TLS version could not be confirmed",
                "TLS records were present but the negotiated version was not visible in the captured handshake.",
                "Capture the complete ClientHello and ServerHello for a definitive assessment.",
                ["Handshake evidence is incomplete"],
                score_impact=0,
                confidence="LOW",
            )
        )

    if any(token in cipher for token in ("NULL", "EXPORT", "RC4", "RC2", "ANON")):
        findings.append(
            _finding(
                session,
                "INSECURE_CIPHER",
                Severity.CRITICAL,
                "Insecure cipher suite negotiated",
                "The cipher suite provides obsolete, anonymous or effectively null protection.",
                "Remove NULL, EXPORT, RC4, RC2 and anonymous cipher suites from the mail server policy.",
                [f"Cipher suite: {tls.cipher_suite}"],
                score_impact=45,
            )
        )
    elif "3DES" in cipher or "DES-CBC3" in cipher:
        findings.append(
            _finding(
                session,
                "LEGACY_CIPHER",
                Severity.HIGH,
                "Legacy 3DES cipher suite negotiated",
                "3DES is obsolete and should not be used for modern email transport.",
                "Prefer AES-GCM or ChaCha20-Poly1305 with an ephemeral key exchange.",
                [f"Cipher suite: {tls.cipher_suite}"],
            )
        )
    elif "CBC" in cipher and tls.tls_version in {"TLS 1.0", "TLS 1.1", "TLS 1.2"}:
        findings.append(
            _finding(
                session,
                "LEGACY_CBC_CIPHER",
                Severity.MEDIUM,
                "Legacy CBC cipher suite negotiated",
                "CBC suites are less preferred than authenticated encryption suites such as AES-GCM or ChaCha20-Poly1305.",
                "Prefer AEAD cipher suites and remove CBC suites where compatibility allows.",
                [f"Cipher suite: {tls.cipher_suite}"],
                score_impact=18,
            )
        )

    if tls.detected and tls.cipher_suite and not is_known_cipher(tls.cipher_suite):
        findings.append(
            _finding(
                session,
                "CIPHER_NOT_RECOGNISED",
                Severity.INFO,
                "Cipher suite is not in the known-suite table",
                "The negotiated suite code was captured, but its strength could not be assessed, so no cipher verdict is claimed.",
                "Add this suite to app/analysis/ciphers.py so its strength and key exchange can be scored.",
                [f"Negotiated cipher suite: {tls.cipher_suite}"],
                score_impact=0,
                confidence="LOW",
            )
        )

    if tls.forward_secrecy is False:
        findings.append(
            _finding(
                session,
                "NO_FORWARD_SECRECY",
                Severity.MEDIUM,
                "Forward secrecy is not provided",
                "The observed key exchange does not provide ephemeral forward secrecy.",
                "Use ECDHE/DHE for TLS 1.2 or TLS 1.3 with an ephemeral key share.",
                [f"Key exchange: {tls.key_exchange or 'UNKNOWN'}"],
            )
        )
    elif tls.detected and tls.forward_secrecy is None:
        findings.append(
            _finding(
                session,
                "FORWARD_SECRECY_UNKNOWN",
                Severity.INFO,
                "Forward secrecy could not be confirmed",
                "The required key exchange evidence was not visible in the captured handshake.",
                "Capture the complete handshake, including the key-share or key-exchange fields.",
                ["Forward secrecy: UNKNOWN"],
                score_impact=0,
                confidence="LOW",
            )
        )

    if cert.present:
        if cert.expired:
            findings.append(
                _finding(
                    session,
                    "CERTIFICATE_EXPIRED",
                    Severity.HIGH,
                    "Certificate is expired",
                    "The captured leaf certificate is outside its validity period.",
                    "Replace the certificate and monitor renewal before expiry.",
                    [f"Valid until: {cert.valid_until}"],
                )
            )
        elif cert.not_yet_valid:
            findings.append(
                _finding(
                    session,
                    "CERTIFICATE_NOT_YET_VALID",
                    Severity.HIGH,
                    "Certificate is not yet valid",
                    "The certificate validity period has not started at analysis time.",
                    "Install the correct certificate and verify server/client clock synchronisation.",
                    [f"Valid from: {cert.valid_from}"],
                )
            )
        elif cert.days_remaining is not None and cert.days_remaining <= 30:
            findings.append(
                _finding(
                    session,
                    "CERTIFICATE_EXPIRING_SOON",
                    Severity.LOW,
                    "Certificate expires soon",
                    "The certificate has 30 or fewer days remaining.",
                    "Schedule certificate renewal and confirm automated renewal monitoring.",
                    [f"Days remaining: {cert.days_remaining}"],
                )
            )
        if cert.public_key_algorithm == "RSA" and (cert.public_key_bits or 0) < 2048:
            findings.append(
                _finding(
                    session,
                    "WEAK_CERTIFICATE_KEY",
                    Severity.HIGH,
                    "Certificate public key is too small",
                    "The certificate RSA key is below the commonly accepted 2048-bit minimum.",
                    "Replace the certificate with RSA 2048-bit or stronger, or a suitable modern EC key.",
                    [f"Public key: {cert.public_key_algorithm} {cert.public_key_bits} bits"],
                )
            )
        if cert.weak_signature:
            findings.append(
                _finding(
                    session,
                    "WEAK_CERTIFICATE_SIGNATURE",
                    Severity.HIGH,
                    "Certificate uses a weak signature hash",
                    "The certificate signature uses MD5 or SHA-1.",
                    "Replace the certificate with a SHA-256-or-stronger signature.",
                    [f"Signature: {cert.signature_algorithm}"],
                )
            )
        if cert.self_signed:
            findings.append(
                _finding(
                    session,
                    "SELF_SIGNED_CERTIFICATE",
                    Severity.MEDIUM,
                    "Certificate is self-signed",
                    "The leaf certificate is self-signed and may not be trusted by clients.",
                    "Use a certificate issued by the organisation's approved CA or a trusted public CA.",
                    [f"Subject and issuer: {cert.subject}"],
                )
            )
        if cert.hostname_match is False:
            findings.append(
                _finding(
                    session,
                    "CERTIFICATE_HOSTNAME_MISMATCH",
                    Severity.HIGH,
                    "Certificate hostname does not match SNI",
                    "The certificate identity did not match the observed server name.",
                    "Install a certificate containing the correct mail host in its SAN extension.",
                    [f"SNI: {tls.sni}", f"Certificate CN: {cert.common_name}"],
                )
            )
        if cert.chain_complete is False:
            findings.append(
                _finding(
                    session,
                    "INCOMPLETE_CERTIFICATE_CHAIN",
                    Severity.MEDIUM,
                    "Certificate chain is incomplete or not verifiable from the capture",
                    "The captured certificate chain could not be linked to a complete issuer chain.",
                    "Configure the server to send the required intermediate certificates and validate against the intended trust store.",
                    [f"Chain status: {cert.chain_status}"],
                    confidence="MEDIUM",
                )
            )
    elif tls.detected and tls.handshake_status != "UNKNOWN":
        findings.append(
            _finding(
                session,
                "CERTIFICATE_NOT_OBSERVED",
                Severity.INFO,
                "Certificate was not visible in the capture",
                "The handshake may be resumed, incomplete or missing the server certificate message.",
                "Capture a complete full handshake before concluding certificate security.",
                ["Certificate: UNKNOWN"],
                score_impact=0,
                confidence="LOW",
            )
        )

    if starttls.command_seen and starttls.rejected:
        findings.append(
            _finding(
                session,
                "STARTTLS_REJECTED",
                Severity.HIGH,
                "STARTTLS/STLS negotiation was rejected",
                "The mail server rejected the requested encryption upgrade.",
                "Fix the mail-server TLS configuration and require encryption before authentication.",
                ["STARTTLS/STLS command observed", "Server rejection observed"],
            )
        )
    elif starttls.command_seen and not starttls.upgrade_successful and not tls.detected:
        findings.append(
            _finding(
                session,
                "STARTTLS_UPGRADE_NOT_COMPLETED",
                Severity.HIGH,
                "Encryption upgrade was not completed",
                "An explicit TLS upgrade command was observed without a successful TLS handshake afterward.",
                "Investigate STARTTLS stripping, server configuration and client fallback behaviour.",
                ["STARTTLS/STLS command observed", "TLS handshake not observed"],
                confidence="MEDIUM",
            )
        )

    if tls.alert_seen or tls.handshake_failures:
        findings.append(
            _finding(
                session,
                "TLS_HANDSHAKE_INSTABILITY",
                Severity.MEDIUM,
                "TLS handshake instability observed",
                "The session contains TLS alerts, failures or repeated negotiation attempts.",
                "Review server logs, supported versions and cipher overlap; investigate unexpected repeated handshakes.",
                [f"TLS failures: {tls.handshake_failures}", f"TLS alert observed: {tls.alert_seen}"],
                score_impact=18,
                confidence="MEDIUM",
            )
        )

    return findings
