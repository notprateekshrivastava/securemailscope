from __future__ import annotations

from collections import OrderedDict

from ..schemas import Finding, SessionAnalysis


def build_recommendations(sessions: list[SessionAnalysis]) -> list[str]:
    """Return deduplicated remediation advice ordered by appearance/severity."""
    ordered: OrderedDict[str, None] = OrderedDict()
    for session in sessions:
        for finding in session.findings:
            ordered.setdefault(finding.recommendation, None)

    # Always give the administrator a secure target state when evidence exists.
    if sessions:
        ordered.setdefault("Enforce TLS 1.2 or TLS 1.3 and remove SSLv3/TLS 1.0/TLS 1.1.", None)
        ordered.setdefault("Prefer ECDHE/DHE or TLS 1.3 ephemeral key exchange for forward secrecy.", None)
        ordered.setdefault("Prefer AES-GCM or ChaCha20-Poly1305 and remove obsolete cipher suites.", None)
        ordered.setdefault("Require valid, unexpired certificates with a complete issuer chain and matching SAN.", None)
        ordered.setdefault("Require authentication only after a successful TLS upgrade.", None)
    return list(ordered)
