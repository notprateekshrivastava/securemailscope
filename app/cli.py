"""Command line entry points: batch analysis, feature export, and stats.

Why a CLI
---------
The API is for interactive use. For the work an organisation actually has - a
directory of captures, a training set to rebuild, a machine with many cores - a
command line tool is faster and can be scripted:

    python -m app.cli batch  C:\\captures --workers 8 --out data\\batch
    python -m app.cli export data\\batch\\session_features.csv --stats
    python -m app.cli doctor

Each command prints what it did and returns a non-zero exit code on failure, so it
can be used from a batch file or a CI job.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.version import ANALYZER_VERSION  # noqa: E402


def cmd_batch(args: argparse.Namespace) -> int:
    from app.analysis.batch import analyse_folder

    result = analyse_folder(
        root=Path(args.input),
        output_dir=Path(args.out),
        workers=args.workers,
        include_features=not args.no_features,
        resume=args.resume,
        limit=args.limit,
    )
    print()
    print("Batch complete")
    print(f"  captures           : {result['analysed']} analysed, {result['failed']} failed")
    print(f"  sessions           : {result.get('sessions', 0)}")
    print(f"  session feature rows: {result.get('session_feature_rows', 0)}")
    print(f"  workers            : {result.get('workers')}")
    print(f"  wall clock         : {result['seconds']}s")
    print(f"  summary CSV        : {result['csv']}")
    print(f"  full records       : {result['jsonl']}")
    if result.get("features"):
        print(f"  feature table      : {result['features']}")
    if result.get("failures"):
        print(f"  failures           : {result['failures']}")
    return 1 if result["failed"] and not result["analysed"] else 0


def cmd_export(args: argparse.Namespace) -> int:
    """Summarise (and optionally re-write) an exported session feature table."""
    from app.analysis.batch import iter_feature_rows

    path = Path(args.features)
    if not path.exists():
        print(f"No such file: {path}")
        print("Create it with:  python -m app.cli batch <capture folder> --out data\\batch")
        return 2

    labels: Counter[str] = Counter()
    ml_labels: Counter[str] = Counter()
    captures: set[str] = set()
    findings: Counter[str] = Counter()
    rows = 0
    agreed = 0
    for row in iter_feature_rows(path):
        rows += 1
        label = row.get("risk_label", "?")
        ml_label = row.get("ml_label", "?")
        labels[label] += 1
        ml_labels[ml_label] += 1
        if label == ml_label:
            agreed += 1
        captures.add(row.get("capture", "?"))
        for code in (row.get("finding_codes") or "").split("|"):
            if code:
                findings[code] += 1

    print(f"Feature table : {path}")
    print(f"Rows          : {rows}")
    print(f"Captures      : {len(captures)}")
    print(f"ML agrees with rules: {agreed}/{rows}")
    print()
    print("Rule labels       :", dict(sorted(labels.items())))
    print("ML labels         :", dict(sorted(ml_labels.items())))
    if args.stats:
        print()
        print("Most common findings")
        for code, count in findings.most_common(15):
            print(f"  {count:5d}  {code}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Analyse one capture and report rules, ML, their agreement, and whether the ML applies.

    This is the command to run on a capture that did not come from the lab, to find out
    whether the model is on solid ground for that file.
    """
    from app.analysis.assessment import apply_policy_assessment
    from app.analysis.novelty import check_capture, load_feature_ranges
    from app.analysis.tshark import analyze_pcap
    from app.analysis.unclassified import find_unclassified_tls
    from app.config import settings
    from app.ml.model import ModelBundle

    capture = Path(args.capture)
    if not capture.exists():
        print(f"No such file: {capture}")
        return 2

    bundle = ModelBundle(settings.model_dir)
    sessions = [apply_policy_assessment(session) for session in analyze_pcap(capture)]
    for session in sessions:
        session.ml = bundle.assess(session)

    print(f"Capture        : {capture}")
    print(f"Analyzer       : {ANALYZER_VERSION}")
    print(f"ML model       : {bundle.version}")
    print(f"Email sessions : {len(sessions)}")

    # A capture can hold encrypted mail traffic that cannot be attributed to a mail
    # protocol, which happens whenever the encryption is implicit (no STARTTLS step) and
    # the port is not one TShark recognises. Report it instead of returning "no sessions".
    unclassified = find_unclassified_tls(capture, {session.session_id for session in sessions})

    if not sessions:
        print()
        if unclassified.streams:
            print("No SMTP, IMAP or POP3 session could be identified, but this capture does")
            print("contain encrypted traffic:")
            for stream in unclassified.streams[:10]:
                print(f"  {stream.stream_id}: {stream.describe()}")
            print()
            print("Why the protocol cannot be named: this is implicit TLS, so the client")
            print("sent a TLS ClientHello before any mail command, and everything after the")
            print("handshake is encrypted. There is no protocol vocabulary in the capture")
            print("to read, and a port number on its own is a convention, not evidence.")
            print("Setting the port aside, ask the submitter for the server's configuration")
            print("or a capture that includes the connection setup from the client.")
        else:
            print("No SMTP, IMAP or POP3 sessions were found in this capture.")
            print("That is not a failure: the analyzer only reads mail traffic, and a capture")
            print("of other protocols has nothing for it to assess.")
        return 0

    if unclassified.streams:
        print()
        print(f"Not attributed : {unclassified.headline()}")

    ranges = load_feature_ranges(settings.model_dir)
    novelty = check_capture(sessions, ranges)

    agree = sum(1 for s in sessions if s.ml.risk_class == s.policy_risk_class)
    worst = max(sessions, key=lambda item: item.policy_risk_score)

    print()
    print(f"{'session':<18} {'proto:port':<12} {'TLS':<9} {'rules':<9} {'ML':<9} agree")
    print("-" * 72)
    for session in sessions[:25]:
        flags = "yes" if session.ml.risk_class == session.policy_risk_class else "NO"
        print(
            f"{session.session_id[:16]:<18} "
            f"{str(session.protocol) + ':' + str(session.server_port):<12} "
            f"{(session.tls.tls_version or 'cleartext'):<9} "
            f"{session.policy_risk_class:<9} {session.ml.risk_class:<9} {flags}"
        )
    if len(sessions) > 25:
        print(f"... and {len(sessions) - 25} more session(s)")

    print()
    print(f"Rule findings   : {sum(len(s.findings) for s in sessions)}")
    print(f"Worst session   : risk score {worst.policy_risk_score}, class {worst.policy_risk_class}")
    print(f"Capture posture : {round(sum(s.posture_score for s in sessions) / len(sessions))}/100")
    print(f"Rules vs ML     : {agree}/{len(sessions)} sessions agree")
    print()
    print(f"Training range  : {novelty.verdict}")
    print(f"                  {novelty.explain()}")

    if agree < len(sessions):
        print()
        print("Where they disagree, the RULE FINDINGS are the evidence. The ML class is a")
        print("triage hint and carries no evidence of its own.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report the environment, so a problem is diagnosed before a demo."""
    import platform

    from app.analysis.tshark import tshark_available, tshark_binary, tshark_version
    from app.config import settings
    from app.ml.model import ModelBundle
    from app.version import ANALYZER_VERSION

    bundle = ModelBundle(settings.model_dir)
    bundle.load()

    print("SecureMailScope environment")
    print(f"  analyzer version   : {ANALYZER_VERSION}")
    print(f"  python             : {platform.python_version()} ({platform.system()})")
    print(f"  CPU cores          : {__import__('os').cpu_count()}")
    print(f"  project root       : {PROJECT_ROOT}")
    print(f"  data directory     : {settings.data_dir.resolve()}")
    print(f"  tshark available   : {tshark_available()}")
    print(f"  tshark binary      : {tshark_binary()}")
    version = tshark_version()
    if version:
        print(f"  tshark version     : {version}")
    print(f"  ML model status    : {bundle.version}")
    if bundle.note:
        print(f"  ML model note      : {bundle.note}")
    captures = list((PROJECT_ROOT / "samples").rglob("*.pcap*"))
    print(f"  sample captures    : {len(captures)}")
    print()
    problems = []
    if not tshark_available():
        problems.append("TShark is not available - set SECUREMAILSCOPE_TSHARK_PATH or install Wireshark")
    if bundle.version in {"not_loaded", "load_failed", "stale"}:
        problems.append("The trained model is not in use - run: python -m app.ml.train")
    if not captures:
        problems.append("No sample captures found - run: python tools\\lab_capture_toolkit.py")
    print("Everything needed is present." if not problems else "Problems found:")
    for problem in problems:
        print(f"  - {problem}")
    return 1 if problems else 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Compare a batch run against the stored per-capture results."""
    from app.analysis.batch import summarise_records

    jsonl = Path(args.records)
    if not jsonl.exists():
        print(f"No such file: {jsonl}")
        return 2
    rows = list(summarise_records(jsonl))
    print(f"{'capture':<40} {'sessions':>8}  risk")
    print("-" * 60)
    for name, sessions, risk in sorted(rows):
        print(f"{name:<40} {sessions:>8}  {risk}")
    print()
    print(f"Captures: {len(rows)}   Sessions: {sum(s for _, s, _ in rows)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="SecureMailScope command line tools",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    batch = sub.add_parser("batch", help="analyse every capture in a folder, in parallel")
    batch.add_argument("input", help="folder to search for .pcap / .pcapng files")
    batch.add_argument("--out", default=str(PROJECT_ROOT / "data" / "batch"), help="output folder")
    batch.add_argument("--workers", type=int, default=0, help="parallel processes (default: CPU count)")
    batch.add_argument("--limit", type=int, default=0, help="stop after N captures (0 = all)")
    batch.add_argument("--resume", action="store_true", help="skip captures already in captures.jsonl")
    batch.add_argument("--no-features", action="store_true", help="skip the session feature table")
    batch.set_defaults(func=cmd_batch)

    export = sub.add_parser("export", help="summarise an exported session feature table")
    export.add_argument("features", help="path to session_features.csv")
    export.add_argument("--stats", action="store_true", help="also list the most common findings")
    export.set_defaults(func=cmd_export)

    check = sub.add_parser(
        "check",
        help="analyse ONE capture and report whether the ML applies to it",
    )
    check.add_argument("capture", help="path to a .pcap / .pcapng file")
    check.set_defaults(func=cmd_check)

    doctor = sub.add_parser("doctor", help="check the environment before a demo")
    doctor.set_defaults(func=cmd_doctor)

    verify = sub.add_parser("verify", help="summarise a batch run from captures.jsonl")
    verify.add_argument("records", help="path to captures.jsonl")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
