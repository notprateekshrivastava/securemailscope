from __future__ import annotations

from typing import Final, Iterable

EMAIL_PORT_PROTOCOL: Final[dict[int, str]] = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3",
}

IMPLICIT_TLS_PORTS: Final[set[int]] = {465, 993, 995}

TLS_VERSION_RANK: Final[dict[str, int]] = {
    "SSLv3": 1,
    "TLS 1.0": 2,
    "TLS 1.1": 3,
    "TLS 1.2": 4,
    "TLS 1.3": 5,
}

SEVERITY_ORDER: Final[dict[str, int]] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Score bands used to label synthetic training rows and to give the anomaly
# fallback a class when no trained model is loaded.
RISK_CLASS_BANDS: Final[tuple[tuple[int, str], ...]] = (
    (80, "CRITICAL"),
    (45, "HIGH"),
    (18, "MEDIUM"),
    (0, "LOW"),
)

# A score this high means several independent problems were found, which is
# treated as CRITICAL even when no single finding is CRITICAL on its own.
CRITICAL_SCORE_FLOOR: Final[int] = 80


def risk_class_from_score(score: int) -> str:
    """Classify a raw risk score (0-100) into LOW/MEDIUM/HIGH/CRITICAL."""
    for threshold, label in RISK_CLASS_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def risk_class_from_findings(severities: Iterable[str], score: int) -> str:
    """Classify a session from its findings, promoted by the accumulated score.

    ``INFO`` and ``LOW`` findings never lift a session above LOW on their own:
    unknown or minor evidence must not look like a security failure.
    """
    ranked = [str(severity).upper() for severity in severities]
    worst = "LOW"
    for candidate in ("CRITICAL", "HIGH", "MEDIUM"):
        if candidate in ranked:
            worst = candidate
            break
    if score >= CRITICAL_SCORE_FLOOR:
        return "CRITICAL"
    return worst
