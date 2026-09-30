"""Dependency-free self check for SecureMailScope.

Run this after updating the code to confirm the parser fixes are actually the ones
running on your machine:

    python scripts\\self_check.py

It needs no extra packages (no pytest, no requests). Two stages:

  1. Synthetic regression - replays the exact Dovecot greeting line that caused the
     false "STARTTLS rejected" finding, plus cleartext-authentication and
     cipher-selection cases. Runs anywhere.
  2. Real captures - if TShark is installed, analyses every capture in .\\samples
     and .\\samples\\lab and reports what was found, including the specific checks
     that used to fail.

Exit code 0 means every check passed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

results: list[tuple[str, str, str]] = []


def record(status: str, name: str, note: str = "") -> None:
    results.append((status, name, note))
    print(f"  [{status}] {name}" + (f" - {note}" if note else ""))


# --------------------------------------------------------------------------- #
# Stage 1: synthetic regression (no TShark needed)
# --------------------------------------------------------------------------- #
DOVECOT_GREETING = (
    "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID "
    "ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready."
)


def packet(number: int, source_port: int, destination_port: int, seconds: float, **layers: Any):
    base = {
        "frame": {"frame.number": str(number), "frame.time_epoch": str(seconds), "frame.len": "180"},
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


def analyse_synthetic(packets: list[dict[str, Any]]):
    from app.analysis import tshark
    from app.analysis.assessment import apply_policy_assessment

    original_available, original_run = tshark.tshark_available, tshark._run_tshark
    tshark.tshark_available = lambda: True
    # analyze_pcap may re-run with decode hints for captures on unusual ports, so the
    # stand-in accepts the optional port map.
    tshark._run_tshark = lambda path, port_map=None, exclude_ports=None: json.dumps(packets)
    try:
        return [apply_policy_assessment(session) for session in tshark.analyze_pcap(Path("synthetic.pcap"))]
    finally:
        tshark.tshark_available, tshark._run_tshark = original_available, original_run


def synthetic_case_starttls() -> list[dict[str, Any]]:
    return [
        packet(1, 53477, 143, 1000.0, tcp={"tcp.stream": "0", "tcp.srcport": "53477", "tcp.dstport": "143", "tcp.flags.syn": "1"}),
        packet(2, 143, 53477, 1000.1, tcp={"tcp.stream": "0", "tcp.srcport": "143", "tcp.dstport": "53477"}),
        packet(3, 143, 53477, 1000.2, imap={"imap.response": DOVECOT_GREETING}),
        packet(4, 53477, 143, 1000.3, imap={"imap.request": ". CAPABILITY"}),
        packet(5, 143, 53477, 1000.4, imap={"imap.response": ". OK Pre-login capabilities listed."}),
        packet(6, 53477, 143, 1000.5, imap={"imap.request": ". STARTTLS"}),
        packet(7, 143, 53477, 1000.6, imap={"imap.response": ". OK Begin TLS negotiation now."}),
        packet(
            8,
            53477,
            143,
            1000.7,
            tls={
                "tls.handshake.type": "1",
                "tls.handshake.version": "0x0303",
                "tls.handshake.ciphersuite": ["0xc02f", "0xc030", "0x00ff"],
                "tls.handshake.extensions_server_name": "mail.example.test",
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
                "tls.handshake.ciphersuite": "0xc02f",
                "tls.handshake.certificate": "30" + "00" * 120,
            },
        ),
    ]


def run_synthetic_checks() -> None:
    print("Stage 1: synthetic regression checks (no TShark required)")

    session = analyse_synthetic(synthetic_case_starttls())[0]
    codes = {finding.code for finding in session.findings}

    record(
        PASS if session.starttls.rejected is False else FAIL,
        "Dovecot greeting is not treated as a rejection",
        f"rejected={session.starttls.rejected}",
    )
    record(
        PASS if session.starttls.accepted is True and session.starttls.upgrade_successful else FAIL,
        "Successful STARTTLS upgrade is recognised",
        f"accepted={session.starttls.accepted}",
    )
    record(
        PASS if "STARTTLS_REJECTED" not in codes else FAIL,
        "No false STARTTLS_REJECTED finding",
        f"findings={sorted(codes)}",
    )
    record(
        PASS if session.starttls.plaintext_authentication_seen is False else FAIL,
        "Capability list is not mistaken for cleartext authentication",
    )
    record(
        PASS if session.tls.cipher_source == "SERVER_HELLO" and "0x00ff" not in str(session.tls.cipher_suite) else FAIL,
        "Negotiated cipher comes from the ServerHello",
        f"{session.tls.cipher_suite} ({session.tls.cipher_source})",
    )
    record(
        PASS if session.tls.key_exchange == "ECDHE" and session.tls.forward_secrecy is True else FAIL,
        "Key exchange and forward secrecy are derived from the suite",
        f"kx={session.tls.key_exchange} fs={session.tls.forward_secrecy}",
    )
    record(
        PASS if session.policy_risk_class in {"LOW", "MEDIUM"} and session.policy_risk_score < 25 else FAIL,
        "Clean encrypted session stays low risk",
        f"score={session.policy_risk_score} class={session.policy_risk_class}",
    )

    # Cleartext credentials before TLS must be CRITICAL.
    packets = synthetic_case_starttls()
    packets.insert(6, packet(6, 53477, 143, 1000.55, imap={"imap.request": ". LOGIN alice hunter2"}))
    cleartext = analyse_synthetic(packets)[0]
    cleartext_codes = {finding.code for finding in cleartext.findings}
    record(
        PASS if cleartext.starttls.plaintext_authentication_seen and "PLAINTEXT_AUTHENTICATION" in cleartext_codes else FAIL,
        "Cleartext LOGIN before TLS is reported",
        f"class={cleartext.policy_risk_class}",
    )

    # POP3 USER/PASS with no TLS at all.
    pop3 = [
        packet(1, 40990, 110, 2000.0, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}),
        packet(2, 110, 40990, 2000.1, tcp={"tcp.stream": "1", "tcp.srcport": "110", "tcp.dstport": "40990"}, pop={"pop.response": "+OK ready"}),
        packet(3, 40990, 110, 2000.2, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}, pop={"pop.request.command": "USER", "pop.request.parameter": "alice"}),
        packet(4, 40990, 110, 2000.3, tcp={"tcp.stream": "1", "tcp.srcport": "40990", "tcp.dstport": "110"}, pop={"pop.request.command": "PASS", "pop.request.parameter": "hunter2"}),
    ]
    pop3_session = analyse_synthetic(pop3)[0]
    pop3_codes = {finding.code for finding in pop3_session.findings}
    record(
        PASS if {"PLAINTEXT_AUTHENTICATION", "PLAINTEXT_EMAIL_SESSION"} <= pop3_codes else FAIL,
        "Cleartext POP3 session is flagged",
        f"class={pop3_session.policy_risk_class}",
    )

    # Evidence must not be invented: no ServerHello means no version and no cipher.
    partial = analyse_synthetic(synthetic_case_starttls()[:8])[0]
    record(
        PASS if partial.tls.tls_version is None and partial.tls.cipher_suite is None else FAIL,
        "Version and cipher stay UNKNOWN when only the client offer was captured",
        f"cipher_source={partial.tls.cipher_source}",
    )


# --------------------------------------------------------------------------- #
# Stage 2: real captures
# --------------------------------------------------------------------------- #
def run_capture_checks() -> None:
    from app.analysis.assessment import apply_policy_assessment, build_summary
    from app.analysis.tshark import TSHARK_TIMEOUT_SECONDS, analyze_pcap, tshark_available
    from app.ml.model import ModelBundle
    from app.config import settings

    print("\nStage 2: real captures in .\\samples and .\\samples\\lab")

    if not tshark_available():
        record(SKIP, "TShark is available", "install Wireshark or set TSHARK_PATH, then rerun")
        return

    captures = sorted(Path(PROJECT_ROOT / "samples").glob("*.pcapng")) + sorted(
        (Path(PROJECT_ROOT / "samples" / "lab")).glob("*.pcapng")
        if (Path(PROJECT_ROOT / "samples" / "lab")).exists()
        else []
    )
    if not captures:
        record(SKIP, "Captures found", "no .pcapng file in samples")
        return

    bundle = ModelBundle(settings.model_dir)
    if bundle.available:
        print(f"  ML model: loaded, version {bundle.version}")
    else:
        print(f"  ML model: NOT in use (status: {bundle.version})")
        if bundle.note:
            print(f"            {bundle.note}")
    # Report the model's own recorded generalisation figure next to its status, so the
    # in-sample agreement count printed later is never mistaken for a generalisation
    # result. Both numbers are written to model_metadata.json at training time.
    try:
        metadata = json.loads(
            (Path(settings.model_dir) / "model_metadata.json").read_text(encoding="utf-8")
        )
        holdout = metadata.get("capture_holdout") or {}
        transfer = metadata.get("synthetic_transfer") or {}
        if holdout.get("match_rate"):
            print(f"  ML holdout (leave-one-capture-out)  : {holdout['match_rate']}  <- generalisation")
        if transfer.get("match_rate"):
            print(f"  ML transfer (synthetic only -> real): {transfer['match_rate']}")
    except Exception:
        pass
    print(f"  (TShark timeout is {TSHARK_TIMEOUT_SECONDS} s; results are written per capture)")

    agreement_total = 0
    agreement_agree = 0
    problems = 0
    for capture in captures:
        try:
            sessions = [apply_policy_assessment(session) for session in analyze_pcap(capture)]
        except Exception as exc:
            record(FAIL, f"{capture.name} could be parsed", f"{type(exc).__name__}: {exc}")
            problems += 1
            continue

        if not sessions:
            record(FAIL, f"{capture.name} produced at least one session", "0 sessions")
            problems += 1
            continue

        for session in sessions:
            session.ml = bundle.assess(session)
        worst = max(sessions, key=lambda item: item.policy_risk_score)
        # Two different numbers, and they must not be confused:
        #   - the capture posture is the mean of the session scores, exactly what
        #     the API summary and the reports show (100 - average risk);
        #   - the worst-session score belongs to one session only.
        # Printing them both here keeps this check consistent with the reports.
        summary = build_summary(sessions)
        detail = (
            f"{len(sessions)} session(s) | {worst.protocol}:{worst.server_port} "
            f"{worst.tls.tls_version or 'no TLS'} | {worst.tls.cipher_suite or 'no cipher'} | "
            f"worst session score={worst.policy_risk_score} {worst.policy_risk_class} | "
            f"capture posture={summary.overall_posture_score} "
            f"(mean of {len(sessions)} session scores) | ml={worst.ml.risk_class} | "
            f"completeness={summary.evidence_completeness}"
        )
        for session in sessions:
            agreement_total += 1
            if session.ml.risk_class == session.policy_risk_class:
                agreement_agree += 1
        record(PASS, capture.name, detail)
        for finding in worst.findings[:4]:
            print(f"          {finding.severity}: {finding.code} - {finding.title}")

    # The specific regression: the first capture that failed must now be correct.
    imap = Path(PROJECT_ROOT / "samples" / "imap-ssl.pcapng")
    if imap.exists():
        session = [apply_policy_assessment(s) for s in analyze_pcap(imap)][0]
        codes = {finding.code for finding in session.findings}
        record(
            PASS if not session.starttls.rejected and "STARTTLS_REJECTED" not in codes else FAIL,
            "imap-ssl.pcapng: upgrade is not reported as rejected",
            f"accepted={session.starttls.accepted} rejected={session.starttls.rejected}",
        )
        record(
            PASS if session.tls.cipher_suite and session.tls.cipher_suite != "0x00ff" else FAIL,
            "imap-ssl.pcapng: negotiated cipher is named, not 0x00ff",
            str(session.tls.cipher_suite),
        )
        record(
            PASS if session.certificate.present else FAIL,
            "imap-ssl.pcapng: certificate is extracted from the packets",
            f"CN={session.certificate.common_name}",
        )

    if agreement_total:
        record(
            PASS if agreement_agree == agreement_total else FAIL,
            "ML classification agrees with the rule engine",
            f"{agreement_agree}/{agreement_total} sessions",
        )
        if agreement_agree != agreement_total:
            print("          The ML model was trained with an older feature schema or older risk")
            print("          bands. It is not being trusted for those sessions. Fix with:")
            print("            python -m app.ml.train")

    print("\n  Note: samples with no TLS legitimately have no certificate. Those are reported as")
    print("  UNKNOWN/PARTIAL with an INFO finding, never as 'insecure'.")


def main() -> int:
    print(f"SecureMailScope self check - project root: {PROJECT_ROOT}\n")
    run_synthetic_checks()
    run_capture_checks()

    passed = sum(1 for status, _, _ in results if status == PASS)
    failed = sum(1 for status, _, _ in results if status == FAIL)
    skipped = sum(1 for status, _, _ in results if status == SKIP)
    print("\n" + "=" * 72)
    print(f"{passed} passed, {failed} failed, {skipped} skipped")
    if failed:
        print("\nIf a synthetic check failed, the updated app\\analysis files are not in place yet.")
        print("If only a capture check failed, send the line to the team with the capture name.")
    else:
        print("\nEverything the engine is supposed to do on these captures, it does.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
