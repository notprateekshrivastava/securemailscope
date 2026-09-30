from __future__ import annotations

from collections import Counter
from statistics import mean

from ..schemas import AnalysisSummary, Finding, SessionAnalysis
from .constants import SEVERITY_ORDER, risk_class_from_findings, risk_class_from_score
from .rules import assess_session


def risk_class(score: int) -> str:
    """Map an accumulated risk score to a class (see RISK_CLASS_BANDS)."""
    return risk_class_from_score(score)


def apply_policy_assessment(session: SessionAnalysis) -> SessionAnalysis:
    protocol_value = getattr(session.protocol, "value", session.protocol)
    evidence_items = [
        protocol_value != "UNKNOWN",
        session.packet_count > 0,
        (not session.tls.detected) or bool(session.tls.tls_version),
        (not session.tls.detected) or bool(session.tls.cipher_suite),
        (not session.tls.detected) or session.certificate.present,
    ]
    session.evidence_completeness = round(sum(evidence_items) / len(evidence_items), 2)
    findings = assess_session(session)
    # A policy score is an explainable risk score. It is intentionally separate
    # from the ML probability so judges can see exactly why the result changed.
    raw_score = min(100, sum(max(0, finding.score_impact) for finding in findings))
    session.findings = findings
    session.policy_risk_score = raw_score
    session.posture_score = max(0, 100 - raw_score)
    session.policy_risk_class = risk_class_from_findings(
        [str(finding.severity) for finding in findings], raw_score
    )
    return session


def flatten_findings(sessions: list[SessionAnalysis]) -> list[Finding]:
    findings: list[Finding] = []
    for session in sessions:
        findings.extend(session.findings)
    findings.sort(
        key=lambda item: (-SEVERITY_ORDER.get(str(item.severity), 0), -item.score_impact, item.title)
    )
    return findings


def build_summary(sessions: list[SessionAnalysis]) -> AnalysisSummary:
    protocols = Counter(getattr(session.protocol, "value", session.protocol) for session in sessions)
    tls_versions = Counter(
        session.tls.tls_version for session in sessions if session.tls.tls_version
    )
    ciphers = Counter(
        session.tls.cipher_suite for session in sessions if session.tls.cipher_suite
    )
    findings = flatten_findings(sessions)
    severity_counts = Counter(str(finding.severity) for finding in findings)
    total = len(sessions)
    tls_sessions = sum(1 for session in sessions if session.tls.detected)
    plaintext = sum(
        1
        for session in sessions
        if not session.tls.detected and getattr(session.protocol, "value", session.protocol) != "UNKNOWN"
    )
    starttls = sum(1 for session in sessions if session.starttls.command_seen or session.starttls.advertised)
    successful = sum(1 for session in sessions if session.starttls.upgrade_successful)
    anomalous = sum(1 for session in sessions if session.ml.anomalous)
    risk_scores = [session.policy_risk_score for session in sessions]
    overall_risk = round(mean(risk_scores)) if risk_scores else 0
    # The headline class of a report must be the worst session class, never the
    # average: averaging hides a single compromised session behind many healthy
    # ones.
    overall_class = "LOW"
    for session in sessions:
        candidate = str(session.policy_risk_class)
        if SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(overall_class, 0):
            overall_class = candidate
    completeness = round(mean(session.evidence_completeness for session in sessions), 2) if sessions else 0.0

    return AnalysisSummary(
        protocols=dict(protocols),
        total_sessions=total,
        tls_sessions=tls_sessions,
        plaintext_sessions=plaintext,
        starttls_sessions=starttls,
        successful_upgrades=successful,
        anomalous_sessions=anomalous,
        total_findings=len(findings),
        findings_by_severity={key: severity_counts.get(key, 0) for key in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")},
        tls_versions=dict(tls_versions),
        ciphers=dict(ciphers),
        overall_risk_score=overall_risk,
        overall_posture_score=max(0, 100 - overall_risk),
        overall_risk_class=overall_class,
        evidence_completeness=completeness,
    )
