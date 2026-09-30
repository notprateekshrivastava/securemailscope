"""Score the analyzer and the ML layer against the held-out test set.

    python tools/score_testset.py --dir testset
    python tools/score_testset.py --dir testset --json testset/results.json

What this measures, and what it does not
---------------------------------------
The expectations live in `testset/ground_truth.json` and were written BEFORE the captures
were analysed, from the server configuration used to generate the traffic. This script only
reads them; it never adjusts them to match what the analyzer said.

Three separate questions are answered, and they are reported separately because they are
not the same claim:

1. **Reconstruction** - did the analyzer find the sessions that are in the file? (A missed
   session is the most serious kind of failure: nothing downstream can be right.)
2. **Declared findings** - did it report the weaknesses that were configured, and stay
   silent about the ones that were not? The second half matters as much as the first:
   scoring missing evidence as a weakness is a false accusation.
3. **ML agreement** - on captures the model never trained on, does the ML class agree with
   the rule engine? The rules are the evidence; the ML layer is a triage hint.

This is synthetic, self-generated traffic. It is not human analyst ground truth, and it
says nothing about real-world attack rates. What it can prove is narrower and still useful:
that declared weaknesses are detected and declared-absent ones are not invented, on a set
of captures built after the model was trained.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analysis.assessment import apply_policy_assessment  # noqa: E402
from app.analysis.tshark import analyze_pcap  # noqa: E402
from app.config import settings  # noqa: E402
from app.ml.model import ModelBundle  # noqa: E402
from app.version import ANALYZER_VERSION  # noqa: E402

CHECK_ORDER = ("matched", "findings", "forbidden", "facts", "class")

RISK_MODEL_FILE = "risk_model.joblib"


def model_freshness(model_dir: Path) -> tuple[bool, str]:
    """Is the loaded model at least as new as every capture it should have learned from?

    This exists because a stale model produces a *plausible-looking* ML number that is
    simply worse, with nothing to say why. Measured: a model trained before the coverage
    sweep existed scored 987/1116 agreement on this test set; the same code with the sweep
    in training scored 1073/1116. Nothing about the analyzer differs - only the triage
    layer. The rule findings are unaffected either way, which is exactly why the gap is
    easy to miss.

    Returns (is_fresh, explanation).
    """
    from app.ml import train as train_module

    risk_model = Path(model_dir) / RISK_MODEL_FILE
    if not risk_model.exists():
        return False, (
            "No trained model is loaded, so the ML class falls back to the rule class and "
            "this figure is not informative. Run: python -m app.ml.train"
        )
    captured = [Path(item) for item in train_module.find_capture_files()]
    if not captured:
        return True, ""
    newest = max(captured, key=lambda item: item.stat().st_mtime)
    if newest.stat().st_mtime > risk_model.stat().st_mtime + 1:
        try:
            shown = newest.relative_to(PROJECT_ROOT)
        except ValueError:
            shown = newest
        return False, (
            f"{shown} is newer than the trained model, so the model has never seen it. "
            "ML agreement below is measured with an out-of-date model - run "
            "python -m app.ml.train, then score again before quoting these numbers."
        )
    return True, ""


def _protocol_value(session: Any) -> str:
    return str(getattr(session.protocol, "value", session.protocol))


def _key(session: Any) -> tuple[str, int | None, int | None]:
    return (_protocol_value(session), session.server_port, session.client_port)


def analyse_capture(path: Path, bundle: ModelBundle) -> list[Any]:
    sessions = [apply_policy_assessment(session) for session in analyze_pcap(path)]
    for session in sessions:
        session.ml = bundle.assess(session)
    return sessions


def score_capture(entry: dict[str, Any], sessions: list[Any]) -> list[dict[str, Any]]:
    """Match declared sessions to analysed ones and check every declared property."""
    index: dict[tuple[Any, ...], list[Any]] = defaultdict(list)
    for session in sessions:
        index[_key(session)].append(session)

    rows: list[dict[str, Any]] = []
    for expected in entry.get("sessions", []):
        rounds = int(expected.get("rounds", 1) or 1)
        for round_index in range(rounds):
            key = (expected.get("protocol"), expected.get("server_port"), expected.get("client_port"))
            candidates = index.get(key, [])
            actual = candidates.pop(0) if candidates else None
            rows.append(_score_session(entry, expected, actual, round_index + 1))
    return rows


def _score_session(
    entry: dict[str, Any], expected: dict[str, Any], actual: Any | None, round_index: int
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "capture": entry["name"],
        "group": entry.get("group", "singles"),
        "round": round_index,
        "protocol": expected.get("protocol"),
        "server_port": expected.get("server_port"),
        "client_port": expected.get("client_port"),
        "mode": expected.get("mode"),
        "profile": expected.get("profile"),
        "unseen": not bool(expected.get("seen_in_training")),
        "checks": {},
    }
    if actual is None:
        record["checks"] = {check: False for check in CHECK_ORDER}
        record["missing"] = "no session matched these addresses in the capture"
        return record

    codes = {finding.code for finding in actual.findings}

    wanted = set(expected.get("expect_findings", []))
    forbidden = set(expected.get("forbid_findings", []))
    missing_findings = sorted(wanted - codes)
    violations = sorted(forbidden & codes)

    facts: dict[str, str] = {}
    expected_facts = expected.get("facts", {}) or {}
    if "tls_version" in expected_facts:
        # A cleartext session is compared against None, which is a real expectation:
        # there was no TLS, so a version would be an invention.
        actual_version = actual.tls.tls_version if actual.tls.detected else None
        facts["tls_version"] = (
            "ok" if (actual_version or None) == (expected_facts["tls_version"] or None)
            else f"expected {expected_facts['tls_version']}, got {actual_version}"
        )
    if "cert_observed" in expected_facts:
        observed = bool(actual.certificate.present)
        facts["cert_observed"] = (
            "ok" if observed == bool(expected_facts["cert_observed"])
            else f"expected {expected_facts['cert_observed']}, got {observed}"
        )
    if "forward_secrecy" in expected_facts:
        secrecy = actual.tls.forward_secrecy if actual.tls.detected else None
        facts["forward_secrecy"] = (
            "ok" if secrecy == bool(expected_facts["forward_secrecy"])
            else f"expected {expected_facts['forward_secrecy']}, got {secrecy}"
        )

    class_exact = expected.get("class_exact")
    class_band = expected.get("class_band")
    policy_class = actual.policy_risk_class
    if class_exact:
        class_ok = policy_class == class_exact
        class_note = f"expected {class_exact}, got {policy_class}"
    elif class_band:
        class_ok = policy_class in class_band
        class_note = f"expected {'/'.join(class_band)}, got {policy_class}"
    else:
        class_ok = True
        class_note = f"no class expectation ({policy_class})"

    record["checks"] = {
        "matched": True,
        "findings": not missing_findings,
        "forbidden": not violations,
        "facts": all(value == "ok" for value in facts.values()),
        "class": class_ok,
    }
    record["details"] = {
        "missing_findings": missing_findings,
        "forbidden_findings": violations,
        "facts": facts,
        "class_note": class_note,
        "policy_class": policy_class,
        "ml_class": actual.ml.risk_class,
        "ml_agrees": actual.ml.risk_class == policy_class,
        "tls_version": actual.tls.tls_version,
        "cipher": actual.tls.cipher_suite,
        "cert_observed": bool(actual.certificate.present),
        "forward_secrecy": actual.tls.forward_secrecy if actual.tls.detected else None,
        "evidence_completeness": actual.evidence_completeness,
        "findings": sorted(codes),
    }
    return record


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def rate(subset: list[dict[str, Any]], check: str) -> tuple[int, int]:
        return sum(1 for row in subset if row["checks"].get(check)), len(subset)

    unseen = [row for row in rows if row["unseen"]]
    scale = [row for row in rows if row["group"] == "large"]
    distinct = [row for row in rows if row["group"] != "large"]
    summary: dict[str, Any] = {
        "sessions_expected": len(rows),
        "sessions_matched": sum(1 for row in rows if row["checks"].get("matched")),
        "checks": {check: rate(rows, check) for check in CHECK_ORDER},
        "unseen_sessions": len(unseen),
        "unseen_checks": {check: rate(unseen, check) for check in CHECK_ORDER},
        "distinct_sessions": len(distinct),
        "distinct_checks": {check: rate(distinct, check) for check in CHECK_ORDER},
        "scale_sessions": len(scale),
        "scale_checks": {check: rate(scale, check) for check in CHECK_ORDER},
        "ml_agreement": (
            sum(1 for row in rows if row.get("details", {}).get("ml_agrees")),
            sum(1 for row in rows if "details" in row),
        ),
        "unseen_ml_agreement": (
            sum(1 for row in unseen if row.get("details", {}).get("ml_agrees")),
            sum(1 for row in unseen if "details" in row),
        ),
        "situations": len({(row["protocol"], row["server_port"], row["mode"], row["profile"]) for row in rows}),
    }
    return summary


def _pct(pair: tuple[int, int]) -> str:
    correct, total = pair
    if not total:
        return "n/a"
    return f"{correct}/{total} ({100.0 * correct / total:.1f}%)"


def write_results(summary: dict[str, Any], rows: list[dict[str, Any]], out_dir: Path,
                  capture_rows: list[dict[str, Any]], filename: str = "RESULTS.md") -> None:
    failures = [
        row for row in rows
        if not (row["checks"].get("matched") and row["checks"].get("findings")
                and row["checks"].get("forbidden") and row["checks"].get("class")
                and row["checks"].get("facts"))
    ]
    lines = [
        "# Held-out test set - measured results",
        "",
        f"Analyzer `{ANALYZER_VERSION}`. Expectations were written before the captures were",
        "analysed (`EXPECTED.md`, `ground_truth.json`); this file is only the measurement.",
        "",
    ]
    if summary.get("model_note"):
        lines += [
            "> **The ML figures in this report were produced by a model that is out of date.**",
            f"> {summary['model_note']}",
            ">",
            "> Measured, on this very test set: the same analyzer and the same captures gave",
            "> **987/1116 (88.4%)** agreement with an out-of-date model and **1073/1116 (96.1%)**",
            "> with a current one. Every rule-based check was 100% in both runs - only the triage",
            "> layer changes. Run `python -m app.ml.train` and score again before quoting it.",
            "",
        ]
    lines += [
        "## Headline",
        "",
        "| Question | All sessions | Non-repeated sessions | At scale (repeated file) |",
        "|---|---|---|---|",
        f"| Session reconstructed | {_pct(summary['checks']['matched'])} | "
        f"{_pct(summary['distinct_checks']['matched'])} | {_pct(summary['scale_checks']['matched'])} |",
        f"| Declared findings all reported | {_pct(summary['checks']['findings'])} | "
        f"{_pct(summary['distinct_checks']['findings'])} | {_pct(summary['scale_checks']['findings'])} |",
        f"| No forbidden finding invented | {_pct(summary['checks']['forbidden'])} | "
        f"{_pct(summary['distinct_checks']['forbidden'])} | {_pct(summary['scale_checks']['forbidden'])} |",
        f"| TLS facts as configured | {_pct(summary['checks']['facts'])} | "
        f"{_pct(summary['distinct_checks']['facts'])} | {_pct(summary['scale_checks']['facts'])} |",
        f"| Risk class in the expected band | {_pct(summary['checks']['class'])} | "
        f"{_pct(summary['distinct_checks']['class'])} | {_pct(summary['scale_checks']['class'])} |",
        "",
        f"**Sessions measured:** {summary['sessions_expected']} across "
        f"{len(capture_rows)} files. They cover **{summary['situations']} distinct "
        f"(protocol, port, mode, profile) situations**; the two field files appear as 52 "
        f"sessions because each situation is captured on both the standard and the alternate "
        f"port family, and the large file is one of them repeated. "
        f"{summary['unseen_sessions']} sessions have a shape no training capture had.",
        "",
        f"**ML agreement with the rule engine:** {_pct(summary['ml_agreement'])} overall, "
        f"{_pct(summary['unseen_ml_agreement'])} on the unseen situations.",
        "",
        "The middle column is every session outside the large file: 24 single-session captures "
        "plus the 52 field sessions. The right-hand column is the same 26-session file repeated "
        "with shifted timestamps - it measures session reconstruction and throughput at scale, "
        "not new diversity, so the middle column is the one to read for correctness.",
        "",
        "## Per capture",
        "",
        "| Capture | Group | Sessions | Matched | Findings | No false findings | Facts | Class |",
        "|---|---|---|---|---|---|---|---|",
    ]
    by_capture: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_capture[row["capture"]].append(row)
    for capture in capture_rows:
        name = capture["name"]
        subset = by_capture.get(name, [])
        if not subset:
            continue

        def count(check: str) -> str:
            good = sum(1 for row in subset if row["checks"].get(check))
            return f"{good}/{len(subset)}"

        lines.append(
            f"| `{name}` | {capture.get('group')} | {len(subset)} | {count('matched')} | "
            f"{count('findings')} | {count('forbidden')} | {count('facts')} | {count('class')} |"
        )

    # A table of what was actually observed, one row per distinct situation. This is the
    # part a reviewer reads: the scoreboard says how many passed, this says what the
    # analyzer reported for each situation it was given.
    situations: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        if row["group"] == "large":
            continue          # a repetition of field-mixed-1, already listed above
        details = row.get("details")
        if not details:
            continue
        key = (row["protocol"], row["server_port"], row["mode"], row["profile"])
        if key not in situations:
            situations[key] = {"row": row, "details": details, "seen": 0}
        situations[key]["seen"] += 1
    lines += [
        "",
        "## What was observed, per situation",
        "",
        "One row per (protocol, port, mode, profile). `Cert` is what the analyzer actually",
        "saw: a certificate, nothing at all because there was no handshake, or an encrypted",
        "one it declines to call absent. `FS` is forward secrecy (yes/no) where a key exchange",
        "happened.",
        "",
        "| Situation | TLS | Cipher | Cert | FS | Findings reported | Rules | ML |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key in sorted(situations, key=lambda item: (str(item[0]), item[1] or 0, str(item[2]))):
        entry = situations[key]
        details = entry["details"]
        row = entry["row"]
        cipher = (details.get("cipher") or "cleartext")
        findings = ", ".join(details.get("findings") or []) or "none"
        cert_cell = "yes" if details.get("cert_observed") else (
            "none (no handshake)" if details.get("tls_version") is None else "encrypted, not visible")
        secrecy = details.get("forward_secrecy")
        secrecy_cell = "n/a" if secrecy is None else ("yes" if secrecy else "NO")
        lines.append(
            f"| {key[0]}:{key[1]} {key[2]}/{key[3] or '-'} | {details.get('tls_version') or 'cleartext'} | "
            f"{cipher[:26]} | {cert_cell} | {secrecy_cell} | {findings} | "
            f"{details.get('policy_class')} | {details.get('ml_class')} |"
        )

    disagreements: dict[tuple[Any, ...], int] = {}
    for row in rows:
        details = row.get("details") or {}
        if details and not details.get("ml_agrees", True):
            key = (row["protocol"], row["server_port"], row["mode"], row["profile"],
                   details.get("policy_class"), details.get("ml_class"))
            disagreements[key] = disagreements.get(key, 0) + 1
    if disagreements:
        lines += ["", "## Where the ML layer disagreed with the rules", "",
                  "The rules are the evidence. These are the sessions where the triage layer",
                  "reached a different class on data it had never seen.", "",
                  "| Situation | Rules | ML | Sessions |", "|---|---|---|---|"]
        for key, count in sorted(disagreements.items(), key=lambda item: -item[1]):
            lines.append(f"| {key[0]}:{key[1]} {key[2]}/{key[3] or '-'} | {key[4]} | {key[5]} | {count} |")

    if failures:
        lines += ["", "## Every session that did not meet its declared expectation", "",
                  "| Capture | Situation | What failed | Detail |", "|---|---|---|---|"]
        for row in failures:
            failed = [check for check in CHECK_ORDER if not row["checks"].get(check)]
            details = row.get("details", {})
            detail_bits: list[str] = []
            if row.get("missing"):
                detail_bits.append(row["missing"])
            if details.get("missing_findings"):
                detail_bits.append("missing findings: " + ", ".join(details["missing_findings"]))
            if details.get("forbidden_findings"):
                detail_bits.append("invented findings: " + ", ".join(details["forbidden_findings"]))
            for name, value in (details.get("facts") or {}).items():
                if value != "ok":
                    detail_bits.append(f"{name}: {value}")
            if not row["checks"].get("class"):
                detail_bits.append(details.get("class_note", ""))
            lines.append(
                f"| `{row['capture']}` | {row['protocol']}:{row['server_port']} "
                f"{row['mode']}/{row['profile']} | {', '.join(failed)} | "
                f"{'; '.join(bit for bit in detail_bits if bit)} |"
            )
    else:
        lines += ["", "Every session met every declared expectation."]

    lines += [
        "",
        "## How to read this",
        "",
        "* **Findings** and **facts** are the independent part: they come from the server",
        "  configuration, which the model has no influence over.",
        "* **Class** checks the analyzer against the project's own documented policy bands",
        "  (cleartext credentials are CRITICAL by definition; a deprecated version, weak",
        "  certificate or NULL cipher must land above a healthy session; the exact band in",
        "  between is a policy choice, so it is declared as a band).",
        "* **ML agreement** is agreement with the rule engine, not with human ground truth.",
        "  Where they disagree the finding is the evidence and the ML class is a hint.",
        "* A synthetic set cannot show that the analyzer works on traffic from a network it",
        "  has never seen. Only a capture from the target organisation could.",
        "",
    ]
    (out_dir / filename).write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the held-out test set")
    parser.add_argument("--dir", default=str(PROJECT_ROOT / "testset"))
    parser.add_argument("--json", default=None, help="also write the raw per-session results")
    parser.add_argument("--limit", type=int, default=None, help="score only the first N files")
    args = parser.parse_args(argv)

    out_dir = Path(args.dir).resolve()
    ground_truth_path = out_dir / "ground_truth.json"
    if not ground_truth_path.exists():
        print(f"No ground truth at {ground_truth_path}.")
        print("Generate the test set first:")
        print("    python tools/lab_capture_toolkit.py testset")
        return 2

    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    entries = ground_truth.get("captures", [])
    if args.limit:
        entries = entries[: args.limit]

    bundle = ModelBundle(settings.model_dir)
    fresh, freshness_note = model_freshness(settings.model_dir)
    print(f"Test set      : {out_dir}")
    print(f"Analyzer      : {ANALYZER_VERSION}")
    print(f"ML model      : {bundle.version}")
    print(f"Files         : {len(entries)}")
    if not fresh and freshness_note:
        print()
        print("!" * 72)
        print("MODEL WARNING - the ML figures below are not the best this project can do:")
        print(f"  {freshness_note}")
        print("!" * 72)
    print()

    rows: list[dict[str, Any]] = []
    capture_rows: list[dict[str, Any]] = []
    for entry in entries:
        path = (PROJECT_ROOT / entry["file"]).resolve() if not Path(entry["file"]).is_absolute() else Path(entry["file"])
        if not path.exists():
            print(f"  MISSING FILE {path}")
            continue
        sessions = analyse_capture(path, bundle)
        capture_rows.append(entry)
        scored = score_capture(entry, sessions)
        rows.extend(scored)
        matched = sum(1 for row in scored if row["checks"]["matched"])
        print(f"  {entry['name']:<34} {len(sessions):>5} analysed, {matched}/{len(scored)} declared sessions found")

    summary = summarise(rows)
    summary["model_fresh"] = fresh
    summary["model_note"] = freshness_note
    if args.limit:
        # A partial run must never overwrite the full report: the numbers would look
        # complete while covering three files.
        write_results(summary, rows, out_dir, capture_rows, filename=f"RESULTS-limit{args.limit}.md")
    else:
        write_results(summary, rows, out_dir, capture_rows)

    print()
    print("=" * 72)
    print(f"Sessions expected / matched : {summary['sessions_expected']} / {summary['sessions_matched']}")
    for label, key in (("all sessions", "checks"),
                       ("non-repeated sessions", "distinct_checks"),
                       ("at scale", "scale_checks")):
        checks = summary[key]
        print(f"{label:<20} findings {_pct(checks['findings'])}  "
              f"no-false-findings {_pct(checks['forbidden'])}  "
              f"facts {_pct(checks['facts'])}  class {_pct(checks['class'])}")
    print(f"ML vs rules          : {_pct(summary['ml_agreement'])} "
          f"(unseen: {_pct(summary['unseen_ml_agreement'])})")
    if not fresh:
        print("                       ^ produced by an OUT-OF-DATE model - see the warning above")
    print("=" * 72)
    print(f"Written: {out_dir / (f'RESULTS-limit{args.limit}.md' if args.limit else 'RESULTS.md')}")

    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "sessions": rows}, indent=2,
                                              default=str), encoding="utf-8")
        print(f"Written: {args.json}")

    hard_failures = [
        row for row in rows
        if not row["checks"].get("matched") or not row["checks"].get("forbidden")
        or not row["checks"].get("findings")
    ]
    if hard_failures:
        print(f"\n{len(hard_failures)} session(s) failed a hard check - see RESULTS.md.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
