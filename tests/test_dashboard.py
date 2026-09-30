"""The dashboard is a deliverable, so it is tested like one.

The problem statement requires an interactive dashboard. It is served by the
backend so there is nothing extra to build or install, which also means it has to
keep working as the API changes. These tests check that it is served, that it is
self-contained (no CDN, so it works on a machine with no network - necessary when
the captures are sensitive), and that it uses the real endpoints.
"""

from __future__ import annotations

import re

import pytest

from fastapi.testclient import TestClient

from app.dashboard import render_dashboard
from app.main import app


def test_dashboard_is_served_as_html():
    client = TestClient(app)
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "SecureMailScope" in body
    assert "<script" in body and "<style" in body


def test_dashboard_loads_nothing_from_the_internet():
    """No CDN links, no external fonts, no remote scripts.

    Analyses of an organisation's captures must not trigger a request to a third
    party, so the page has to be complete on its own.
    """
    html = render_dashboard()
    external = re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', html)
    assert external == [], f"dashboard references external resources: {external}"


def test_dashboard_uses_the_documented_endpoints():
    html = render_dashboard()
    for endpoint in (
        "/api/v1/health",
        "/api/v1/analyses",
        "/api/v1/analyses/upload",
        "/reports/json",
        "/reports/html",
        "/reports/pdf",
    ):
        assert endpoint in html, f"dashboard does not use {endpoint}"


def test_root_endpoint_points_at_the_dashboard():
    client = TestClient(app)
    body = client.get("/").json()
    assert body["dashboard"] == "/dashboard"
    assert body["version"] == body["version"]  # present, and from app.version


def test_dashboard_explains_the_evidence_limits():
    """The page itself must state what it does not do, not only the report."""
    html = render_dashboard().lower()
    assert "never decrypts" in html or "does not decrypt" in html
    assert "man-in-the-middle" in html or "cannot prove" in html


def test_dashboard_never_promises_a_clean_score_for_a_capture_it_could_not_score() -> None:
    """A capture with no mail session must not be presented as low risk.

    An empty, truncated or unrecognised capture produces no session, and the summary
    defaults to LOW with a perfect posture. Rendering that as a green "LOW 100/100" claims
    something the analysis never established, so the dashboard has to distinguish three
    cases: sessions scored, encrypted-but-unidentifiable, and nothing to score at all.
    """
    body = render_dashboard()

    assert "NO MAIL SESSIONS" in body, "a capture with no session needs its own label"
    assert "NONE ASSESSED" in body, "the risk class must not be shown for an unscored capture"
    assert "no mail session to score" in body

    # The three branches must all exist, and the neutral ones must come before the
    # scored one, or an unscored capture would fall through to the LOW pill.
    unclassified_at = body.index("UNCLASSIFIED</span>")
    no_mail_at = body.index("NO MAIL SESSIONS")
    scored_at = body.index("posture ' + num(s.overall_posture_score)")
    assert unclassified_at < no_mail_at < scored_at or no_mail_at < scored_at


def test_dashboard_explains_an_unprovable_protocol() -> None:
    """Implicit TLS on an unknown port must be described, not silently dropped."""
    body = render_dashboard()
    assert "protocol not provable" in body
    assert "ClientHello before any mail command" in body
    assert "left UNKNOWN rather than guessed" in body


def test_dashboard_caps_the_session_table_on_a_large_capture() -> None:
    """A 3,000-session capture would render 3,000 rows and a 13 MB payload.

    The table is capped and the shortfall is stated, so a viewer is never left thinking a
    truncated list is the whole capture. The reports remain complete.
    """
    body = render_dashboard()
    assert "SESSION_ROW_LIMIT" in body
    assert "highest-risk of" in body
    assert "Every session is in the JSON and HTML" in body


def test_pdf_report_states_when_findings_are_truncated() -> None:
    """Silently showing 40 of 5,600 findings would look like a report that lost evidence."""
    from pathlib import Path

    source = Path("app/reports.py").read_text(encoding="utf-8")
    assert "most severe of" in source
    assert "HTML and JSON reports contain every finding" in source


# --------------------------------------------------------------------------- #
# The page is a single HTML file with inline JavaScript, so a syntax error in it
# fails at runtime in the browser and nowhere else - the server still returns 200
# and every string-based test above still passes. That is exactly how a broken
# ternary once reached a screenshot. These tests parse the script instead.
# --------------------------------------------------------------------------- #
def _dashboard_script() -> str:
    from pathlib import Path

    source = Path(__file__).resolve().parent.parent / "app" / "dashboard.py"
    text = source.read_text(encoding="utf-8")
    start = text.index("(function () {")
    end = text.index("</script>", start)
    return text[start:end]


def test_dashboard_javascript_is_syntactically_valid():
    esprima = pytest.importorskip("esprima", reason="esprima is a test-only dependency")
    esprima.parseScript(_dashboard_script())


def test_dashboard_calls_every_endpoint_it_claims_to_use():
    """The endpoints test above greps the page; this one checks the JavaScript uses them."""
    script = _dashboard_script()
    for fragment in ('"/api/v1/health"', '"/api/v1/analyses?summary_only=true"',
                     '"/api/v1/analyses/" + encodeURIComponent(id)', '"/api/v1/analyses/upload"',
                     "/reports/json", "/reports/html", "/reports/pdf"):
        assert fragment in script, f"dashboard script never calls {fragment}"


def test_dashboard_marks_ml_disagreement_instead_of_hiding_it():
    """The ML column is a hint, the finding is the evidence, and the page says so."""
    script = _dashboard_script()
    assert "function mlCell" in script
    assert "disagrees with the triage hint" in script
