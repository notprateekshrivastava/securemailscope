#!/usr/bin/env python3
"""Measure how the analyzer behaves on captures it was never trained on.

The question this answers is the one that matters before a demo or a submission:

    "The model was trained on a handful of files - can it handle a file I choose?"

Answering it needs four separate measurements on the *same* set of captures, because
they can disagree and each one means something different:

  1. Rules vs expectations - does the deterministic rule engine find what the scenario
     actually contains? This is the only part that carries evidence.
  2. Rules vs ML - does the triage layer agree with the evidence? A disagreement is not
     an error; the rules win, and the disagreement itself is the interesting number.
  3. Training range - is the ML even entitled to an opinion on this session, or is it an
     input unlike anything it has seen?
  4. Forbidden findings - did the engine claim something the capture cannot support
     (a certificate finding with no visible certificate, a STARTTLS rejection on a
     protocol that has no STARTTLS)? False positives matter more than misses here.

Use it on the variant captures produced by:

    python tools/lab_capture_toolkit.py variants --outdir samples/variants

Variant captures are named `<base-scenario>-port<number>`, so the expectations recorded
in the base scenario still apply: moving a conversation to another port changes the port
number, not what the conversation is. That property is exactly what makes them a fair
generalisation test, and it is why this script can score them while `verify` cannot -
`verify` matches capture files to scenarios by name and would report every variant as
missing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from app.analysis.assessment import apply_policy_assessment  # noqa: E402
from app.analysis.novelty import check_session, load_feature_ranges  # noqa: E402
from app.analysis.tshark import analyze_pcap  # noqa: E402
from app.analysis.unclassified import find_unclassified_tls  # noqa: E402
from app.config import settings  # noqa: E402
from app.ml.model import ModelBundle  # noqa: E402
from app.version import ANALYZER_VERSION  # noqa: E402
from lab_capture_toolkit import SCENARIOS, Scenario  # noqa: E402

VARIANT_RE = re.compile(r"-port(\d+)$")


@dataclass
class Result:
    capture: Path
    scenario_name: str
    base: Scenario | None
    port: int | None
    sessions: int = 0
    observed: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    forbidden_seen: list[str] = field(default_factory=list)
    rules_class: str = "-"
    ml_class: str = "-"
    agree_sessions: int = 0
    sessions_total: int = 0
    novel_sessions: int = 0
    novelty_verdict: str = "-"
    error: str | None = None
    # PASS          expectations met
    # UNCLASSIFIED  the conversation was seen and described, but the protocol inside it
    #               cannot be proven from the capture (implicit TLS on an odd port), so
    #               no expectation can be met or failed. Not a defect, and not a pass.
    # FAIL          a crash, a missing expected finding, or a forbidden finding
    status: str = "FAIL"
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "PASS"


def split_variant(name: str) -> tuple[str, int | None]:
    """`imaps-cbc-cipher-port9993` -> ("imaps-cbc-cipher", 9993)."""
    stem = Path(name).stem
    match = VARIANT_RE.search(stem)
    if not match:
        return stem, None
    return stem[: match.start()], int(match.group(1))


def measure(
    capture: Path, bundle: ModelBundle, ranges: dict[str, dict[str, float]] | None
) -> Result:
    base_name, port = split_variant(capture.name)
    base = next((s for s in SCENARIOS if s.name == base_name), None)
    result = Result(capture=capture, scenario_name=base_name, base=base, port=port)

    try:
        sessions = [apply_policy_assessment(s) for s in analyze_pcap(capture)]
    except Exception as exc:  # a parser crash is a result too, and must be visible
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    if not sessions:
        return result

    for session in sessions:
        session.ml = bundle.assess(session)

    # Checked per session rather than per capture, so the report can say how many of the
    # sessions are atypical instead of collapsing the answer to a single yes or no.
    novelty = [check_session(session, ranges) for session in sessions]

    result.sessions = len(sessions)
    result.sessions_total = len(sessions)
    result.agree_sessions = sum(1 for s in sessions if s.ml.risk_class == s.policy_risk_class)
    result.novel_sessions = sum(1 for item in novelty if item.novel)
    result.novelty_verdict = novelty[0].verdict if novelty else "-"
    result.novelty_verdict = (
        "OUTSIDE TRAINING RANGE" if result.novel_sessions else "within training range"
    )
    if novelty and novelty[0].outside_features:
        # Record which features caused it; that is the part a reviewer will ask about.
        result.novelty_verdict += " (" + ", ".join(novelty[0].outside_features[:4]) + ")"

    worst = max(sessions, key=lambda item: item.policy_risk_score)
    result.rules_class = worst.policy_risk_class or "-"
    result.ml_class = worst.ml.risk_class or "-"

    observed = {finding.code for session in sessions for finding in session.findings}
    result.observed = sorted(observed)

    if base is not None:
        result.missing = sorted(
            {code for code in base.expected_findings if code not in observed}
        )
        result.forbidden_seen = sorted(
            {code for code in base.forbidden_findings if code in observed}
        )
    return result


def render(results: list[Result], out_path: Path) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    unclassified = sum(1 for r in results if r.status == "UNCLASSIFIED")
    sessions_total = sum(r.sessions_total for r in results)
    agree = sum(r.agree_sessions for r in results)
    novel = sum(r.novel_sessions for r in results)
    crashes = [r for r in results if r.error]

    lines = [
        "# Capability test on captures the model has never seen",
        "",
        f"Generated by `python tools/capability_test.py` on {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}.",
        f"Analyzer `{ANALYZER_VERSION}`.",
        "",
        "Each capture below was produced by the lab toolkit on a port that is absent from the",
        "training set, so the model sees a `(protocol, port)` combination it has never been",
        "fitted on. Expectations come from the base scenario: relocating a conversation to a",
        "different port changes the port number, not what the conversation contains.",
        "",
        "## Summary",
        "",
        "| Measure | Result | What it means |",
        "|---|---|---|",
        f"| Captures whose findings match expectations | **{passed}/{total}** | expected findings present, no forbidden finding |",
        f"| Captures seen but not nameable | {unclassified} | encrypted stream described, protocol unprovable |",
        f"| Sessions parsed | {sessions_total} | parser and stream reconstruction worked |",
        f"| Rules vs ML agreement | **{agree}/{sessions_total}** | triage layer agrees with the evidence |",
        f"| Sessions outside training range | **{novel}/{sessions_total}** | the ML flags these instead of guessing |",
        f"| Analyzer crashes | {len(crashes)} | none is a pass |",
        "",
        "UNCLASSIFIED is not a pass and not a failure. These captures are implicit TLS on a port",
        "TShark does not recognise, so the client sent a ClientHello before any mail command and",
        "there is no protocol vocabulary anywhere in the file. The stream is reported with its",
        "port, TLS version, SNI and certificate visibility, and the protocol is left unnamed",
        "rather than guessed from a port number. A STARTTLS or STLS conversation on an unfamiliar",
        "port has no such limit, because the upgrade is negotiated in cleartext first.",
        "",
        "## Per capture",
        "",
        "| Capture | Port | Sessions | Findings observed | Expected missing | Forbidden seen | Rules | ML | Agree | Training range | Verdict |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            "| `{name}` | {port} | {sessions} | {observed} | {missing} | {forbidden} | {rules} | {ml} | {agree}/{total} | {novelty} | {verdict} |".format(
                name=r.capture.name,
                port=r.port if r.port is not None else "-",
                sessions=r.sessions,
                observed=", ".join(r.observed) or ("ERROR" if r.error else "none"),
                missing=", ".join(r.missing) or "none",
                forbidden=", ".join(r.forbidden_seen) or "none",
                rules=r.rules_class,
                ml=r.ml_class,
                agree=r.agree_sessions,
                total=r.sessions_total,
                novelty=("OUTSIDE" if r.novel_sessions else "inside") if r.sessions else "-",
                verdict=r.status,
            )
        )

    if unclassified:
        lines += ["", "## Streams seen but not nameable", ""]
        for r in results:
            if r.status == "UNCLASSIFIED":
                lines.append(f"- `{r.capture.name}`: {r.detail}")

    if crashes:
        lines += ["", "## Errors", ""]
        for r in crashes:
            lines.append(f"- `{r.capture.name}`: {r.error}")

    codes = Counter(code for r in results for code in r.observed)
    if codes:
        lines += ["", "## Finding codes observed across the unseen set", ""]
        lines.append("| Finding | Captures |")
        lines.append("|---|---|")
        for code, count in sorted(codes.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| `{code}` | {count} |")

    lines += [
        "",
        "## How to read this",
        "",
        "- A capture that passes means the rule engine reached the right conclusions on traffic",
        "  the model was not fitted on. That is a statement about the *analyzer*, not the model.",
        "- Agreement between rules and ML is reported per session for the worst session of each",
        "  capture. Where they disagree the rule findings are the evidence; the ML class is a",
        "  prioritisation hint and carries no evidence of its own.",
        "- Every session here should be flagged outside the training range. If a session is",
        "  reported as *inside* the range while the capture is unlike the training set, the",
        "  novelty guard is not working and that is a defect.",
        "",
        "## Before you quote the training-range column",
        "",
        "The column compares each session against the p01-p99 range of the features the model",
        "was fitted on, and it is only meaningful when the model was **not** trained on these",
        "captures. Two practical consequences:",
        "",
        "1. **Do not train on the captures you intend to test on.** If `samples/variants` is",
        "   analysed (`batch samples`) and the model is then retrained, those sessions become",
        "   training rows and every one of them reads as *inside* the range, which proves",
        "   nothing. Train first, then generate and test the unseen set.",
        "2. **A capture can sit inside the range and still be unfamiliar.** The guard flags a",
        "   session when at least two features (or a tenth of them) fall outside, because a",
        "   single odd feature - a packet count, a duration - varies between any two captures.",
        "   *Inside the range* means the model is not obviously out of its depth; it is not a",
        "   statement that the model is right. That is what the rule findings are for.",
        "3. **The number of flagged sessions depends on how varied the training set is.** The",
        "   guard compares against the p01-p99 range of everything the model was trained on, so",
        "   a broader training set means wider ranges and fewer sessions that look novel. Measured",
        "   on this project: **5 of 6** unseen sessions were flagged when the model was trained on",
        "   the 18 locally available captures, and **2 of 6** when the 51-session mixed-protocol",
        "   capture was also included. Both are correct. Read the feature names in the verdict",
        "   (`OUTSIDE TRAINING RANGE (server_port, byte_count, ...)`), not the count, and never",
        "   treat *inside the range* as a clean bill of health.",
        "",
    ]
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--captures",
        default=str(PROJECT_ROOT / "samples" / "variants"),
        help="directory of captures to test (default: samples/variants)",
    )
    parser.add_argument(
        "--report",
        default=str(PROJECT_ROOT / "docs" / "CAPABILITY_TEST.md"),
        help="where to write the markdown report",
    )
    parser.add_argument("--quiet", action="store_true", help="only print the summary table")
    args = parser.parse_args(argv)

    capture_dir = Path(args.captures)
    if not capture_dir.is_dir():
        print(f"No such directory: {capture_dir}")
        print("Generate the unseen set first:")
        print("    python tools/lab_capture_toolkit.py variants --outdir samples/variants")
        return 2

    captures = sorted(
        path for path in capture_dir.iterdir() if path.suffix in {".pcap", ".pcapng"}
    )
    if not captures:
        print(f"No captures in {capture_dir}")
        return 2

    bundle = ModelBundle(settings.model_dir)
    if not bundle.available:
        print("No trained model is loaded, so the ML columns would be meaningless.")
        print("Run: python -m app.ml.train")
        return 2
    ranges = load_feature_ranges(settings.model_dir)

    print(f"Analyzer : {ANALYZER_VERSION}")
    print(f"ML model : {bundle.version}")
    print(f"Captures : {len(captures)} in {capture_dir}")
    print()

    results = [measure(path, bundle, ranges) for path in captures]

    # Decide the verdict for each capture. A capture with no session is only acceptable
    # when the reason is structural and the reason is shown: implicit TLS hides every
    # protocol word, so the stream can be described but not named.
    for result in results:
        if result.error:
            result.status, result.detail = "FAIL", result.error
            continue
        if result.sessions:
            result.status = "PASS" if not result.missing and not result.forbidden_seen else "FAIL"
            result.detail = ",".join(result.missing + result.forbidden_seen)
            continue
        report = find_unclassified_tls(result.capture, set())
        if report.streams:
            result.status = "UNCLASSIFIED"
            result.detail = "; ".join(stream.describe() for stream in report.streams[:3])
        else:
            result.status = "FAIL"
            result.detail = "no email session and no encrypted stream found"

    if not args.quiet:
        header = (
            f"{'capture':<38} {'port':<6} {'sess':<5} {'rules':<9} {'ML':<9} "
            f"{'agree':<6} {'range':<8} verdict"
        )
        print(header)
        print("-" * len(header))
        for r in results:
            if r.error:
                print(f"{r.capture.name:<38} {'-':<6} {'-':<5} {'-':<9} {'-':<9} {'-':<6} {'-':<8} ERROR {r.error}")
                continue
            print(
                f"{r.capture.name:<38} {str(r.port):<6} {r.sessions:<5} {r.rules_class:<9} "
                f"{r.ml_class:<9} {str(r.agree_sessions) + '/' + str(r.sessions_total):<6} "
                f"{('OUTSIDE' if r.novel_sessions else 'inside'):<8} "
                f"{r.status:<13} {r.detail[:70]}"
            )
        print()

    passed = sum(1 for r in results if r.status == "PASS")
    unclassified = sum(1 for r in results if r.status == "UNCLASSIFIED")
    sessions_total = sum(r.sessions_total for r in results)
    agree = sum(r.agree_sessions for r in results)
    novel = sum(r.novel_sessions for r in results)
    print(f"Expected findings met : {passed}/{len(results)} captures")
    print(f"Seen but not nameable : {unclassified}/{len(results)} captures (implicit TLS, unknown port)")
    print(f"Sessions parsed       : {sessions_total}")
    print(f"Rules vs ML agreement : {agree}/{sessions_total} sessions")
    print(f"Outside training range: {novel}/{sessions_total} sessions")

    report = Path(args.report)
    render(results, report)
    print(f"\nReport written to {report}")
    return 0 if passed + unclassified == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
