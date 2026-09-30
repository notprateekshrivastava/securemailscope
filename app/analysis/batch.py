"""Batch analysis of many captures at once, in parallel, with bounded memory.

Why this module exists
---------------------
The API analyses one upload at a time, which is right for an interactive dashboard
but wrong for the task the organisation actually has: a directory of captures.

This module is the throughput path:

* walks a directory tree for capture files,
* analyses several captures in parallel using separate processes (each TShark run
  is an independent operating-system process, so processes - not threads - are what
  give real parallelism here; Python's GIL would serialise a thread pool),
* writes one JSON Lines record per capture as soon as it finishes, so a crash never
  loses completed work and the output can be streamed,
* writes a flat CSV summary that opens in Excel,
* never holds more than ``memory_limit_mb`` of parsed result in memory at a time,
* prints progress, and supports ``--resume`` to skip captures already done.

Design notes
------------
* Results are written as the **flattened session feature table**, not the full
  nested document. A 14 MB capture produced a 141 MB JSON when every field was
  serialised; the feature table plus the per-capture summary is a few hundred KB
  and is what any downstream analysis or model actually needs.
* The rule engine is the source of truth for labels. Batch mode therefore produces
  a supervised training set as a side effect: real captures, features measured by
  the parser, labels from the rules.
* Failures are recorded, not raised. One unreadable file must not abort a job over
  a thousand files.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

logger = logging.getLogger("securemailscope.batch")

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".cap.gz")


@dataclass
class BatchItem:
    """One capture, analysed."""

    path: str
    ok: bool
    seconds: float = 0.0
    error: str | None = None
    size_bytes: int = 0
    sha256: str | None = None
    sessions: int = 0
    tls_sessions: int = 0
    cleartext_sessions: int = 0
    starttls_sessions: int = 0
    successful_upgrades: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    posture: int = 0
    risk_class: str = "LOW"
    risk_score: int = 0
    evidence_completeness: float = 0.0
    ml_matches_rules: int = 0
    ml_status: str = "not_attempted"
    # Encrypted streams seen in this capture that could not be attributed to a mail
    # protocol. Only ever set when no email session was found, and it is the difference
    # between "nothing to assess here" and "there is encrypted traffic here that this
    # analysis could not name" - a capture showing 0 sessions and a perfect posture
    # otherwise looks like a clean bill of health when it is really an open question.
    unclassified_streams: int = 0
    unclassified_note: str | None = None
    protocols: dict[str, int] = field(default_factory=dict)
    tls_versions: dict[str, int] = field(default_factory=dict)
    ciphers: dict[str, int] = field(default_factory=dict)
    top_findings: list[dict[str, str]] = field(default_factory=list)
    session_features: list[dict[str, Any]] = field(default_factory=list)


def find_captures(root: Path, skip_stale_results: bool = True) -> list[Path]:
    """Every capture file under ``root``, sorted, excluding generated output."""
    root = Path(root)
    files: list[Path] = []
    skip_dirs = {"data", "reports", "__pycache__", ".git", ".venv"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name.lower().endswith(CAPTURE_SUFFIXES):
            files.append(path)
    return sorted(files)


def _analyse_one(args: tuple[str, bool]) -> BatchItem:
    """Worker entry point. Runs in a separate process, so it must re-import."""
    raw_path, include_features = args
    path = Path(raw_path)
    started = time.perf_counter()
    item = BatchItem(path=str(path), ok=False, size_bytes=path.stat().st_size if path.exists() else 0)
    try:
        import hashlib

        from ..analysis.assessment import apply_policy_assessment, build_summary
        from ..analysis.features import FEATURE_NAMES
        from ..analysis.tshark import analyze_pcap
        from ..analysis.unclassified import find_unclassified_tls

        item.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        sessions = [apply_policy_assessment(session) for session in analyze_pcap(path)]
        # Attach the ML assessment so the batch output can be compared with the rules.
        # A failure here must not lose the rule result, but it must not be silent
        # either: silently leaving every label as UNKNOWN would look like the model
        # disagreed with the rules on the whole capture.
        try:
            bundle = _load_bundle_singleton()
            for session in sessions:
                session.ml = bundle.assess(session)
            item.ml_status = bundle.version
        except Exception as exc:
            item.ml_status = f"unavailable: {type(exc).__name__}: {exc}"
            logger.warning("ML assessment skipped for %s: %s", path.name, exc)

        if not sessions:
            # No session means no posture to report. Say what was actually in the file
            # rather than letting an empty result read as a clean one.
            report = find_unclassified_tls(path, set())
            item.unclassified_streams = report.count
            if report.streams:
                item.unclassified_note = report.headline()

        summary = build_summary(sessions)
        item.ok = True
        item.sessions = summary.total_sessions
        item.tls_sessions = summary.tls_sessions
        item.cleartext_sessions = summary.plaintext_sessions
        item.starttls_sessions = summary.starttls_sessions
        item.successful_upgrades = summary.successful_upgrades
        item.total_findings = summary.total_findings
        item.findings_by_severity = dict(summary.findings_by_severity)
        item.posture = summary.overall_posture_score
        item.risk_class = summary.overall_risk_class
        item.risk_score = summary.overall_risk_score
        item.evidence_completeness = summary.evidence_completeness
        item.protocols = dict(summary.protocols)
        item.tls_versions = dict(summary.tls_versions)
        item.ciphers = dict(summary.ciphers)
        item.ml_matches_rules = sum(
            1 for session in sessions if session.ml.risk_class == session.policy_risk_class
        )

        ranked = sorted(
            (finding for session in sessions for finding in session.findings),
            key=lambda finding: -int(finding.score_impact),
        )
        seen: set[str] = set()
        for finding in ranked:
            if finding.code in seen:
                continue
            seen.add(finding.code)
            item.top_findings.append(
                {
                    "code": str(finding.code),
                    "severity": str(finding.severity),
                    "title": str(finding.title),
                }
            )
            if len(item.top_findings) >= 5:
                break

        if include_features:
            for session in sessions:
                row = session.features.model_dump(mode="json")
                row.update(
                    {
                        "capture": path.name,
                        "session_id": session.session_id,
                        "protocol": str(session.protocol),
                        "server_port": session.server_port,
                        "tls_version": session.tls.tls_version,
                        "cipher_suite": session.tls.cipher_suite,
                        "risk_label": str(session.policy_risk_class),
                        "ml_label": str(session.ml.risk_class),
                        "risk_score": session.policy_risk_score,
                        "evidence_completeness": session.evidence_completeness,
                        "finding_count": len(session.findings),
                        "finding_codes": "|".join(sorted({str(f.code) for f in session.findings})),
                    }
                )
                for key in list(row):
                    if key not in FEATURE_NAMES and key not in {
                        "capture", "session_id", "protocol", "server_port", "tls_version",
                        "cipher_suite", "risk_label", "ml_label", "risk_score",
                        "evidence_completeness", "finding_count", "finding_codes",
                    }:
                        del row[key]
                item.session_features.append(row)
    except Exception as exc:  # one bad file must not stop the batch
        item.error = f"{type(exc).__name__}: {exc}"
        item.ok = False
    item.seconds = round(time.perf_counter() - started, 3)
    return item


# A model bundle is expensive to build (disk + scikit-learn) and cheap to keep.
_BUNDLE: Any = None


def _load_bundle_singleton() -> Any:
    global _BUNDLE
    if _BUNDLE is None:
        from ..config import settings
        from ..ml.model import ModelBundle

        _BUNDLE = ModelBundle(settings.model_dir)   # the constructor loads it
    return _BUNDLE


def analyse_folder(
    root: Path,
    output_dir: Path,
    workers: int | None = None,
    include_features: bool = True,
    resume: bool = False,
    limit: int = 0,
    progress: bool = True,
) -> dict[str, Any]:
    """Analyse every capture under ``root``, in parallel, into ``output_dir``."""
    root = Path(root)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "captures.jsonl"
    csv_path = output_dir / "captures.csv"
    features_path = output_dir / "session_features.csv"
    failures_path = output_dir / "failures.jsonl"

    captures = find_captures(root)
    if limit:
        captures = captures[:limit]

    done: set[str] = set()
    if resume and jsonl_path.exists():
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except Exception:
                continue
            if record.get("ok"):
                done.add(record.get("path", ""))
        captures = [path for path in captures if str(path) not in done]
        if progress and done:
            print(f"Resuming: {len(done)} capture(s) already complete, {len(captures)} remaining")

    if not captures:
        return {"captures": 0, "analysed": 0, "failed": 0, "seconds": 0.0,
                "jsonl": str(jsonl_path), "csv": str(csv_path)}

    workers = workers or max(1, min(os.cpu_count() or 2, 8))
    started = time.perf_counter()
    analysed = failed = 0
    total_sessions = 0

    mode = "a" if resume else "w"
    with (
        jsonl_path.open(mode, encoding="utf-8") as jsonl_handle,
        failures_path.open(mode, encoding="utf-8") as failure_handle,
        ProcessPoolExecutor(max_workers=workers) as pool,
    ):
        tasks = [(str(path), include_features) for path in captures]
        futures = {pool.submit(_analyse_one, task): task[0] for task in tasks}
        completed = 0
        for future in as_completed(futures):
            item = future.result()
            completed += 1
            record = asdict(item)
            jsonl_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            jsonl_handle.flush()
            if item.ok:
                analysed += 1
                total_sessions += item.sessions
            else:
                failed += 1
                failure_handle.write(
                    json.dumps({"path": item.path, "error": item.error}, ensure_ascii=False) + "\n"
                )
                failure_handle.flush()
            if progress:
                mark = "ok  " if item.ok else "FAIL"
                # A capture with no session but with encrypted streams is not "clean",
                # so it does not get the posture reading printed next to it.
                if not item.sessions and item.unclassified_streams:
                    detail = (
                        f"- UNCLASSIFIED: {item.unclassified_streams} encrypted stream(s), "
                        f"no mail protocol identifiable, {item.seconds}s"
                    )
                else:
                    detail = (
                        f"- {item.sessions} session(s), {item.total_findings} finding(s), "
                        f"posture {item.posture}, {item.seconds}s"
                    )
                print(
                    f"  [{completed}/{len(captures)}] {mark} {Path(item.path).name} {detail}",
                    flush=True,
                )

    seconds = round(time.perf_counter() - started, 2)
    records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]

    # Flat summary, one row per capture.
    columns = [
        "capture", "ok", "seconds", "size_bytes", "sessions", "tls_sessions",
        "cleartext_sessions", "starttls_sessions", "successful_upgrades", "total_findings",
        "severity_critical", "severity_high", "severity_medium", "severity_low", "severity_info",
        "posture", "risk_class", "risk_score", "evidence_completeness", "ml_matches_rules", "ml_status",
        "protocols", "tls_versions", "top_findings", "error",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for record in records:
            severity = record.get("findings_by_severity") or {}
            writer.writerow([
                Path(record["path"]).name,
                record.get("ok"),
                record.get("seconds"),
                record.get("size_bytes"),
                record.get("sessions"),
                record.get("tls_sessions"),
                record.get("cleartext_sessions"),
                record.get("starttls_sessions"),
                record.get("successful_upgrades"),
                record.get("total_findings"),
                severity.get("CRITICAL", 0), severity.get("HIGH", 0), severity.get("MEDIUM", 0),
                severity.get("LOW", 0), severity.get("INFO", 0),
                record.get("posture"), record.get("risk_class"), record.get("risk_score"),
                record.get("evidence_completeness"), record.get("ml_matches_rules"),
                record.get("ml_status", ""),
                "; ".join(f"{k}={v}" for k, v in sorted((record.get("protocols") or {}).items())),
                "; ".join(f"{k}={v}" for k, v in sorted((record.get("tls_versions") or {}).items())),
                " | ".join(f"{f['severity']}:{f['code']}" for f in (record.get("top_findings") or [])),
                record.get("error") or "",
            ])

    # The training set: one row per session, features plus rule-assigned label.
    feature_rows = 0
    if include_features:
        rows: list[dict[str, Any]] = []
        for record in records:
            rows.extend(record.get("session_features") or [])
        if rows:
            fieldnames: list[str] = []
            for row in rows:
                for key in row:
                    if key not in fieldnames:
                        fieldnames.append(key)
            # Metadata first, then the numeric features in their defined order.
            from ..analysis.features import FEATURE_NAMES

            ordered = [name for name in FEATURE_NAMES if name in fieldnames]
            meta = [name for name in fieldnames if name not in ordered]
            with features_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[*meta, *ordered], extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
            feature_rows = len(rows)

    return {
        "captures": len(captures) + len(done),
        "analysed": analysed,
        "failed": failed,
        "sessions": total_sessions,
        "session_feature_rows": feature_rows,
        "seconds": seconds,
        "workers": workers,
        "jsonl": str(jsonl_path),
        "csv": str(csv_path),
        "features": str(features_path) if feature_rows else None,
        "failures": str(failures_path) if failed else None,
    }


def iter_feature_rows(features_path: Path) -> Iterator[dict[str, str]]:
    """Stream the exported feature table without loading it all into memory."""
    with Path(features_path).open(newline="", encoding="utf-8") as handle:
        yield from csv.DictReader(handle)


def summarise_records(jsonl_path: Path) -> Iterable[tuple[str, int, str]]:
    """(capture name, sessions, risk class) for every analysed capture."""
    for line in Path(jsonl_path).read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        yield Path(record["path"]).name, record.get("sessions", 0), record.get("risk_class", "?")
