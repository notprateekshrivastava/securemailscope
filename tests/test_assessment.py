from app.analysis.assessment import apply_policy_assessment, build_summary
from app.analysis.fixtures import demo_sessions


def test_demo_fixture_covers_secure_weak_and_plaintext_sessions():
    sessions = [apply_policy_assessment(session) for session in demo_sessions()]
    summary = build_summary(sessions)

    assert summary.total_sessions == 3
    assert summary.protocols["SMTP"] == 1
    assert summary.protocols["IMAP"] == 1
    assert summary.protocols["POP3"] == 1
    assert summary.tls_sessions == 2
    assert summary.plaintext_sessions == 1
    assert summary.findings_by_severity["CRITICAL"] >= 2
    assert any(session.policy_risk_class == "LOW" for session in sessions)
    assert any(session.policy_risk_class == "CRITICAL" for session in sessions)


def test_unknown_evidence_is_not_automatically_a_weakness():
    sessions = demo_sessions()
    secure = sessions[0]
    secure.tls.certificate_seen = False
    secure.certificate.present = False
    assessed = apply_policy_assessment(secure)
    assert assessed.certificate.present is False
    assert assessed.evidence_completeness < 1.0
    assert not any(finding.code == "CERTIFICATE_EXPIRED" for finding in assessed.findings)
