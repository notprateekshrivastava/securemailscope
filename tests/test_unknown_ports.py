"""A capture taken on an unfamiliar port must be analysable, and must not be trusted blindly.

Two separate properties are locked down here, because they protect against two different
kinds of embarrassment:

* The analyzer identifies mail traffic from what the client and server actually say, not
  only from the port number. Before this, a capture of a mail service on a non-standard
  port produced zero sessions and an empty report - the tool looked like it had found
  nothing to worry about, when in truth it had found nothing at all.
* A capture that ends up with no session but does contain encrypted traffic is reported as
  unclassified, never as a clean posture score.

Everything here is hermetic: TShark is stubbed, so the tests run on any machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.analysis import tshark
from app.analysis.novelty import check_session
from app.analysis.unclassified import UnclassifiedReport, UnclassifiedStream


def packet(
    number: int,
    source_port: int,
    destination_port: int,
    seconds: float,
    **layers: Any,
) -> dict[str, Any]:
    """Build one TShark-JSON-shaped packet."""
    base: dict[str, Any] = {
        "frame": {
            "frame.number": str(number),
            "frame.time_epoch": str(seconds),
            "frame.len": "180",
        },
        "ip": {"ip.src": "127.0.0.1", "ip.dst": "127.0.0.1"},
        "tcp": {
            "tcp.stream": "0",
            "tcp.srcport": str(source_port),
            "tcp.dstport": str(destination_port),
            "tcp.len": "20",
        },
    }
    for key, value in layers.items():
        base[key] = value
    return {"_source": {"layers": base}}


class FakeCompleted:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


# --------------------------------------------------------------------------- #
# The vocabulary layer
# --------------------------------------------------------------------------- #
def test_vocabulary_separates_the_three_protocols() -> None:
    smtp = tshark._vocabulary_scores("220 mail.lab.test ESMTP Postfix\r\nEHLO client.test\r\nAUTH PLAIN\r\n")
    imap = tshark._vocabulary_scores("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\nA001 CAPABILITY\r\n")
    pop3 = tshark._vocabulary_scores("+OK POP3 ready\r\nUSER alice\r\nPASS secret\r\nSTLS\r\n")

    assert smtp["smtp"] > smtp["imap"] and smtp["smtp"] > smtp["pop"]
    assert imap["imap"] > imap["smtp"] and imap["imap"] > imap["pop"]
    assert pop3["pop"] > pop3["smtp"] and pop3["pop"] > pop3["imap"]


def test_encrypted_bytes_never_look_like_a_protocol() -> None:
    """TLS ciphertext is not vocabulary, so it must not produce a hint."""
    scores = tshark._vocabulary_scores("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" * 40)
    assert max(scores.values()) == 0


def test_starttls_alone_is_not_enough_to_claim_a_protocol() -> None:
    """SMTP and IMAP both say STARTTLS, so it cannot decide on its own."""
    scores = tshark._vocabulary_scores("STARTTLS\r\n")
    assert scores["smtp"] == scores["imap"]
    assert tshark.MIN_VOCABULARY_SCORE > 1


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def _stub_tshark(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    monkeypatch.setattr(tshark, "tshark_binary", lambda: "tshark")
    monkeypatch.setattr(tshark.subprocess, "run", lambda *a, **k: FakeCompleted(stdout))


def test_discovery_names_the_greeting_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """The server speaks first, so the greeting names the listening port."""
    _stub_tshark(
        monkeypatch,
        "8143\t49222\t2a204f4b205b4341504142494c49545920494d415034726576315d2072656164790d0a\n"
        "49222\t8143\t41303031204341504142494c4954590d0a\n",
    )
    assert tshark.discover_mail_ports(Path("capture.pcap")) == {8143: "IMAP"}


def test_discovery_ignores_a_port_tshark_already_dissects(monkeypatch: pytest.MonkeyPatch) -> None:
    """A known port needs no hint, and hinting it could override a correct dissection."""
    _stub_tshark(
        monkeypatch,
        "143\t49222\t2a204f4b204341504142494c49545920494d415034726576310d0a\n"
        "49222\t143\t41303031204341504142494c4954590d0a\n",
    )
    assert tshark.discover_mail_ports(Path("capture.pcap")) == {}


def test_discovery_declines_when_the_evidence_is_thin(monkeypatch: pytest.MonkeyPatch) -> None:
    """One packet of chatter is not an identification."""
    _stub_tshark(monkeypatch, "9000\t5000\t2a204f4b0d0a\n")
    assert tshark.discover_mail_ports(Path("capture.pcap")) == {}


# --------------------------------------------------------------------------- #
# The second pass
# --------------------------------------------------------------------------- #
def test_analyze_retries_with_decode_hints_when_nothing_was_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Port 8143 instead of 143 must produce a session, not silence."""
    packets = [
        packet(1, 8143, 49222, 1.0, imap={"imap.response": "* OK [CAPABILITY IMAP4rev1] ready"}),
        packet(2, 49222, 8143, 1.1, imap={"imap.request": "A001 LOGIN alice secret"}),
    ]
    calls: list[dict[int, str]] = []

    def fake_run(path: Path, port_map: dict[int, str] | None = None,
                 exclude_ports: set[int] | None = None) -> str:
        calls.append(port_map or {})
        return "[]" if len(calls) == 1 else json.dumps(packets)

    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    monkeypatch.setattr(tshark, "_run_tshark", fake_run)
    monkeypatch.setattr(tshark, "discover_mail_ports", lambda path, tshark=None: {8143: "IMAP"})

    sessions = tshark.analyze_pcap(Path("capture.pcap"))

    assert calls == [{}, {8143: "IMAP"}], "the hint must be used on a second pass"
    assert len(sessions) == 1
    assert sessions[0].protocol == "IMAP"
    assert sessions[0].server_port == 8143


def test_mixed_port_capture_keeps_both_port_families(monkeypatch: pytest.MonkeyPatch) -> None:
    """Standard-port and unusual-port mail in ONE capture must both be analysed.

    This is what real traffic looks like, and until this was fixed the capture silently
    lost the unusual ports: the first pass found the standard ones, the second pass never
    ran, and the report looked complete while missing whole sessions.
    """
    standard = [
        packet(1, 587, 5000, 1.0, smtp={"smtp.response": "220 mail.lab.test ESMTP"}),
        packet(2, 5000, 587, 1.1, smtp={"smtp.req.command": "EHLO client"}),
    ]
    unusual = [
        packet(3, 8143, 5001, 2.0, imap={"imap.response": "* OK [CAPABILITY IMAP4rev1] ready"}),
        packet(4, 5001, 8143, 2.1, imap={"imap.request": "A001 LOGIN alice secret"}),
    ]
    # Both packets belong to one IMAP stream, numbered differently from the SMTP stream
    # above - which is what a real capture does and the fixture helper does not.
    for item in unusual:
        item["_source"]["layers"]["tcp"]["tcp.stream"] = "1"
    calls: list[dict[int, str]] = []

    def fake_run(path: Path, port_map: dict[int, str] | None = None,
                 exclude_ports: set[int] | None = None) -> str:
        calls.append(port_map or {})
        return json.dumps(standard) if not port_map else json.dumps(unusual)

    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    monkeypatch.setattr(tshark, "_run_tshark", fake_run)
    monkeypatch.setattr(tshark, "discover_mail_ports", lambda path, tshark=None: {8143: "IMAP"})

    sessions = tshark.analyze_pcap(Path("capture.pcap"))

    assert calls == [{}, {8143: "IMAP"}], "the unusual ports must get their own pass"
    ports = sorted(session.server_port for session in sessions)
    assert ports == [587, 8143], f"both port families must survive, got {ports}"


def test_every_greeted_unusual_port_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery must name every protocol that greeted from an unusual port.

    It used to return after the first match, so a capture with mail on two unusual ports
    only ever had one of them dissected and the other was dropped without a word.
    """
    smtp_greeting = "220 mail.lab.test ESMTP SecureMailScope"
    imap_greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready"
    imap_command = "A001 LOGIN alice secret"
    rows = [
        f"2525\t5000\t{smtp_greeting.encode().hex()}\t",
        f"5000\t2525\t{'EHLO client'.encode().hex()}\t",
        f"8143\t5001\t{imap_greeting.encode().hex()}\t",
        f"5001\t8143\t{imap_command.encode().hex()}\t",
    ]
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    monkeypatch.setattr(
        tshark.subprocess, "run", lambda *a, **k: FakeCompleted("\n".join(rows))
    )

    discovered = tshark.discover_mail_ports(Path("capture.pcap"))

    assert discovered == {2525: "SMTP", 8143: "IMAP"}, discovered


# --------------------------------------------------------------------------- #
# Honest reporting instead of a false all-clear
# --------------------------------------------------------------------------- #
def test_unclassified_report_states_what_is_unknown() -> None:
    report = UnclassifiedReport(
        streams=[UnclassifiedStream(stream_number=0, server_port=9993, tls_version="TLS 1.0")],
        checked=True,
    )
    headline = report.headline()
    assert "9993" in headline
    assert "cannot be proven" in headline


def test_unclassified_report_is_quiet_when_everything_was_attributed() -> None:
    assert "identified session" in UnclassifiedReport(streams=[], checked=True).headline()


# --------------------------------------------------------------------------- #
# The model must stay out of its depth loudly, not quietly
# --------------------------------------------------------------------------- #
def test_a_session_outside_the_training_range_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard that stops an unfamiliar session from receiving a confident ML class."""
    packets = [
        packet(1, 587, 5000, 1.0, smtp={"smtp.response": "220 mail.lab.test ESMTP"}),
        packet(2, 5000, 587, 1.1, smtp={"smtp.req.command": "EHLO client"}),
    ]
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    monkeypatch.setattr(tshark, "_run_tshark",
                        lambda path, port_map=None, exclude_ports=None: json.dumps(packets))
    session = tshark.analyze_pcap(Path("capture.pcap"))[0]

    # Bounds the session cannot satisfy, standing in for a model trained on other traffic.
    ranges = {
        name: {"p01": high + 10_000, "p99": high + 20_000}
        for name, high in (
            ("server_port", session.server_port or 0),
            ("byte_count", session.features.byte_count),
            ("duration_ms", session.features.duration_ms),
        )
    }
    result = check_session(session, ranges)

    assert result.checked is True
    assert result.novel is True
    assert result.verdict == "OUTSIDE TRAINING RANGE"
    assert "not validated" in result.explain()


def test_without_training_ranges_the_guard_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    result = check_session(None, None)  # type: ignore[arg-type]
    assert result.checked is False
    assert result.novel is False
    assert result.verdict == "UNCHECKED"


# --------------------------------------------------------------------------- #
# The same honesty rule, in the layer a judge actually sees
# --------------------------------------------------------------------------- #
def test_api_carries_unclassified_streams_instead_of_a_clean_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unclassifiable capture must not reach the dashboard as "posture 100 / LOW".

    The CLI and the batch path already said this. The API did not, so the dashboard
    showed a perfect score for a capture holding encrypted traffic it could not name -
    the most misleading thing this tool could put in front of a reviewer.
    """
    import io
    from pathlib import Path as _Path

    from app import service as service_module
    from app.analysis.unclassified import UnclassifiedReport, UnclassifiedStream

    # save_upload writes to the configured upload directory, which is a read-only
    # property, so the storage step is replaced rather than reconfigured.
    monkeypatch.setattr(
        service_module, "save_upload", lambda upload, aid, name: (_Path("capture.pcap"), "0" * 64, 18)
    )
    monkeypatch.setattr(service_module, "analyze_pcap", lambda path: [])
    monkeypatch.setattr(
        service_module,
        "find_unclassified_tls",
        lambda path, ids=None: UnclassifiedReport(
            streams=[
                UnclassifiedStream(
                    stream_number=0,
                    server_port=9993,
                    tls_version="TLS 1.0",
                    tls_version_source="SERVER_HELLO_LEGACY",
                    server_name="mail.lab.test",
                    certificate_visible=True,
                )
            ],
            checked=True,
        ),
    )
    monkeypatch.setattr(service_module, "save_result", lambda result: None)

    result = service_module.service.analyze_upload(
        io.BytesIO(b"not really a pcap"), "unusual-port.pcapng"
    )

    assert result.sessions == []
    assert len(result.unclassified_streams) == 1
    stream = result.unclassified_streams[0]
    assert stream["server_port"] == 9993
    assert stream["tls_version_source"] == "SERVER_HELLO_LEGACY"
    assert "9993" in (result.unclassified_note or "")
    assert "cannot be proven" in (result.unclassified_note or "")


def test_api_leaves_a_normal_capture_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    """The diagnostic must not add noise to an ordinary analysis."""
    from app import service as service_module

    seen: list[object] = []

    def fake_check(path: object, ids: object = None) -> object:
        seen.append(path)
        raise AssertionError("must not be called when a session was found")

    monkeypatch.setattr(service_module, "find_unclassified_tls", fake_check)
    # A capture that produced a session short-circuits before the check, so the guard
    # above proves the diagnostic is skipped rather than merely harmless.
    assert service_module.service._unclassified_snapshot(__import__("pathlib").Path("x"), [object()]) is None  # type: ignore[list-item]
    assert seen == []


def test_list_endpoint_can_omit_the_heavy_parts() -> None:
    """A list of captures must not download every session of every capture.

    Eight stored analyses including one with 3,000 sessions produced a 16.6 MB list
    response. A list needs the summary only, and the per-capture endpoint returns the full
    record when a row is opened.
    """
    from app.main import analyses

    full = analyses(summary_only=False)
    thin = analyses(summary_only=True)

    assert len(full) == len(thin), "summary_only must not drop captures"
    for heavy, light in zip(full, thin):
        assert light.analysis_id == heavy.analysis_id
        assert light.summary.total_sessions == heavy.summary.total_sessions
        assert light.summary.overall_risk_class == heavy.summary.overall_risk_class
        assert light.sessions == [] and light.findings == []
        assert light.metadata.get("summary_only") is True
