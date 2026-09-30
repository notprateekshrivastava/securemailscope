"""Regression tests for STARTTLS/STLS, cipher and authentication evidence.

These tests reproduce the real Dovecot capture that produced a false
"STARTTLS/STLS negotiation was rejected" finding: the server greeting line

    * OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID
      ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.

contains the word "REFERRALS", which used to be matched by an unanchored
"ERR" search. A greeting is not a rejection, so the parser must not report
one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.analysis import tshark
from app.analysis.assessment import apply_policy_assessment

DOVECOT_GREETING = (
    "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID "
    "ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready."
)


def packet(
    number: int,
    source_port: int,
    destination_port: int,
    seconds: float,
    **layers: Any,
) -> dict[str, Any]:
    """Build one TShark-JSON-shaped packet for a loopback mail session."""
    base = {
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
    base.update(layers)
    return {"_source": {"layers": base}}


def analyse(monkeypatch: pytest.MonkeyPatch, packets: list[dict[str, Any]]):
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    # analyze_pcap may take a second pass with decode hints for captures on unusual
    # ports, so the stand-in accepts the optional port map.
    monkeypatch.setattr(tshark, "_run_tshark",
                        lambda path, port_map=None, exclude_ports=None: json.dumps(packets))
    sessions = tshark.analyze_pcap(Path("capture.pcap"))
    return [apply_policy_assessment(session) for session in sessions]


def imap_starttls_packets() -> list[dict[str, Any]]:
    """A complete IMAP STARTTLS upgrade on the standard port 143."""
    return [
        packet(1, 53477, 143, 1000.0, tcp={"tcp.stream": "0", "tcp.srcport": "53477", "tcp.dstport": "143", "tcp.flags.syn": "1"}),
        packet(2, 143, 53477, 1000.1, tcp={"tcp.stream": "0", "tcp.srcport": "143", "tcp.dstport": "53477"}),
        packet(3, 143, 53477, 1000.2, imap={"imap.response": DOVECOT_GREETING}),
        packet(4, 53477, 143, 1000.3, imap={"imap.request": ". CAPABILITY"}),
        packet(5, 143, 53477, 1000.4, imap={"imap.response": ". OK Pre-login capabilities listed, post-login capabilities have more."}),
        packet(6, 53477, 143, 1000.5, imap={"imap.request": ". STARTTLS"}),
        packet(7, 143, 53477, 1000.6, imap={"imap.response": ". OK Begin TLS negotiation now."}),
        packet(
            8,
            53477,
            143,
            1000.7,
            tcp={"tcp.stream": "0", "tcp.srcport": "53477", "tcp.dstport": "143", "tcp.len": "310"},
            tls={
                "tls.handshake.type": "1",
                "tls.handshake.version": "0x0303",
                "tls.handshake.extensions.supported_version": ["0x0304", "0x0303"],
                "tls.handshake.ciphersuite": ["0xc02f", "0xc030", "0x009c", "0x00ff"],
                "tls.handshake.extensions.server_name": "mail.example.test",
            },
        ),
        packet(
            9,
            143,
            53477,
            1000.8,
            tls={
                "tls.handshake.type": "2",
                "tls.handshake.version": "0x0303",
                "tls.handshake.extensions.supported_version": "0x0303",
                "tls.handshake.ciphersuite": "0xc02f",
                "tls.handshake.certificate": "30" + "00" * 120,
            },
        ),
    ]


def test_successful_imap_starttls_is_not_reported_as_rejected(monkeypatch):
    sessions = analyse(monkeypatch, imap_starttls_packets())
    assert len(sessions) == 1
    session = sessions[0]

    assert session.protocol == "IMAP"
    assert session.starttls.advertised is True
    assert session.starttls.command_seen is True
    assert session.starttls.accepted is True
    assert session.starttls.rejected is False
    assert session.starttls.upgrade_successful is True
    assert session.starttls.plaintext_authentication_seen is False

    codes = {finding.code for finding in session.findings}
    assert "STARTTLS_REJECTED" not in codes
    assert "STARTTLS_UPGRADE_NOT_COMPLETED" not in codes
    assert session.policy_risk_score < 25, codes


def test_negotiated_cipher_comes_from_the_server_hello(monkeypatch):
    sessions = analyse(monkeypatch, imap_starttls_packets())
    session = sessions[0]

    # The client's last offered value was the SCSV 0x00ff; the negotiated suite
    # is the one the server selected.
    assert session.tls.cipher_source == "SERVER_HELLO"
    assert session.tls.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)"
    assert session.tls.key_exchange == "ECDHE"
    assert session.tls.forward_secrecy is True
    assert session.tls.tls_version == "TLS 1.2"
    assert session.tls.version_source == "SERVER_HELLO"
    assert "0x00ff" not in " ".join(session.tls.offered_cipher_suites)
    assert session.features.cipher_strength_score >= 85


def test_rejected_starttls_is_reported(monkeypatch):
    # A real rejection leaves the session in cleartext: no TLS records follow.
    packets = imap_starttls_packets()[:7]
    packets[6] = packet(7, 143, 53477, 1000.6, imap={"imap.response": ". NO [PRIVACYREQUIRED] TLS required"})
    sessions = analyse(monkeypatch, packets)
    session = sessions[0]

    assert session.starttls.accepted is False
    assert session.starttls.rejected is True
    assert session.starttls.upgrade_successful is False
    codes = {finding.code for finding in session.findings}
    assert "STARTTLS_REJECTED" in codes
    assert session.policy_risk_score >= 30


def test_refusal_followed_by_a_real_handshake_is_not_scored_as_rejected(monkeypatch):
    packets = imap_starttls_packets()
    packets[6] = packet(7, 143, 53477, 1000.6, imap={"imap.response": ". NO [PRIVACYREQUIRED] TLS required"})
    session = analyse(monkeypatch, packets)[0]

    assert session.starttls.upgrade_successful is True
    assert session.starttls.rejected is False
    assert "STARTTLS_REJECTED" not in {finding.code for finding in session.findings}
    assert any("refusal response" in item.lower() for item in session.starttls.evidence)


def test_plaintext_imap_login_before_tls_is_critical(monkeypatch):
    packets = imap_starttls_packets()
    packets.insert(
        6,
        packet(6, 53477, 143, 1000.55, imap={"imap.request": ". LOGIN alice hunter2"}),
    )
    sessions = analyse(monkeypatch, packets)
    session = sessions[0]

    assert session.starttls.plaintext_authentication_seen is True
    assert session.features.plaintext_authentication == 1
    codes = {finding.code for finding in session.findings}
    assert "PLAINTEXT_AUTHENTICATION" in codes
    assert session.policy_risk_class in {"HIGH", "CRITICAL"}


def test_cleartext_pop3_session_without_tls(monkeypatch):
    packets = [
        packet(1, 40990, 110, 2000.0, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}),
        packet(2, 110, 40990, 2000.1, tcp={"tcp.stream": "1", "tcp.srcport": "110", "tcp.dstport": "40990"}, pop={"pop.response": "+OK POP3 server ready"}),
        packet(3, 40990, 110, 2000.2, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}, pop={"pop.request.command": "USER", "pop.request.parameter": "alice"}),
        packet(4, 40990, 110, 2000.3, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}, pop={"pop.request.command": "PASS", "pop.request.parameter": "hunter2"}),
    ]
    sessions = analyse(monkeypatch, packets)
    session = sessions[0]

    assert session.protocol == "POP3"
    assert session.tls.detected is False
    assert session.starttls.plaintext_authentication_seen is True
    codes = {finding.code for finding in session.findings}
    assert {"PLAINTEXT_AUTHENTICATION", "PLAINTEXT_EMAIL_SESSION"} <= codes
    assert session.policy_risk_class in {"HIGH", "CRITICAL"}


def test_certificate_is_never_invented_when_only_the_offer_is_visible(monkeypatch):
    packets = imap_starttls_packets()[:8]  # stop before the ServerHello
    sessions = analyse(monkeypatch, packets)
    session = sessions[0]

    assert session.tls.client_hello_seen is True
    assert session.tls.server_hello_seen is False
    assert session.tls.tls_version is None
    assert session.tls.cipher_suite is None
    assert session.tls.cipher_source == "CLIENT_OFFER"
    assert session.certificate.present is False
    codes = {finding.code for finding in session.findings}
    assert "DEPRECATED_TLS_VERSION" not in codes
    assert "INSECURE_CIPHER" not in codes


def test_pretty_alias_field_names_from_tshark_4x_are_understood(monkeypatch):
    """TShark prints a "_"-joined alias for every layer next to the dotted name.

    Depending on the Wireshark build, some captures only carry the alias form.
    The parser normalises underscores to dots, so both layouts work and the
    timestamp is no longer lost.
    """
    packets = [
        packet(
            1,
            40000,
            993,
            1700000000.5,
            frame={
                "frame_frame_number": "1",
                "frame_frame_time_epoch": "1700000000.5",
                "frame_frame_len": "240",
            },
            ip={"ip_ip_src": "10.0.0.5", "ip_ip_dst": "10.0.0.6"},
            tcp={
                "tcp_tcp_stream": "7",
                "tcp_tcp_srcport": "40000",
                "tcp_tcp_dstport": "993",
                "tcp_tcp_len": "180",
            },
            tls={
                "tls_tls_handshake_type": "2",
                "tls_tls_handshake_version": "0x0303",
                "tls_tls_handshake_ciphersuite": "0xc02f",
                "tls_tls_handshake_extensions_server_name": "imap.example.test",
            },
        )
    ]
    session = analyse(monkeypatch, packets)[0]

    assert session.tcp_stream_id == "7"
    assert session.start_time is not None
    assert session.server_port == 993
    assert session.starttls.implicit_tls is True
    assert session.starttls.upgrade_successful is True
    assert session.tls.tls_version == "TLS 1.2"
    assert session.tls.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)"
    assert session.tls.sni == "imap.example.test"
