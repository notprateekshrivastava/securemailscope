from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .analysis.assessment import apply_policy_assessment, build_summary, flatten_findings
from .analysis.fixtures import demo_sessions
from .analysis.recommendations import build_recommendations
from .analysis.tshark import MAIL_TLS_DISPLAY_FILTER, analyze_pcap
from .analysis.unclassified import count_readable_packets, find_unclassified_tls
from .config import settings
from .ml.model import ModelBundle
from .schemas import AnalysisResult, SessionAnalysis
from .storage import save_result, save_upload
from .version import ANALYZER_VERSION

logger = logging.getLogger("securemailscope")


class AnalysisService:
    def __init__(self) -> None:
        self.model_bundle = ModelBundle(settings.model_dir)

    def reload_models(self) -> None:
        self.model_bundle.load()

    def _complete_sessions(self, sessions: list[SessionAnalysis]) -> list[SessionAnalysis]:
        completed: list[SessionAnalysis] = []
        for session in sessions:
            session = apply_policy_assessment(session)
            session.ml = self.model_bundle.assess(session)
            if not session.ml.explanation:
                session.ml.explanation = [
                    finding.title
                    for finding in session.findings
                    if finding.severity not in {"INFO", "LOW"}
                ][:5]
            completed.append(session)
        return completed

    def build_result(
        self,
        *,
        analysis_id: str,
        source_filename: str,
        source_sha256: str,
        source_size_bytes: int,
        sessions: list[SessionAnalysis],
        input_type: str = "PCAP",
        metadata: dict[str, object] | None = None,
        uploaded_by: str = "user",
    ) -> AnalysisResult:
        sessions = self._complete_sessions(sessions)
        summary = build_summary(sessions)
        findings = flatten_findings(sessions)
        return AnalysisResult(
            analysis_id=analysis_id,
            created_at=datetime.now(timezone.utc),
            source_filename=source_filename,
            source_sha256=source_sha256,
            source_size_bytes=source_size_bytes,
            uploaded_by=uploaded_by,
            analyzer_version=ANALYZER_VERSION,
            input_type=input_type,
            summary=summary,
            sessions=sessions,
            findings=findings,
            recommendations=build_recommendations(sessions),
            metadata=metadata or {},
        )

    def analyze_upload(self, file_object, filename: str, uploaded_by: str = "user") -> AnalysisResult:
        analysis_id = uuid.uuid4().hex
        path, digest, size = save_upload(file_object, analysis_id, filename)
        if size == 0:
            # Refused here rather than analysed: an empty file would otherwise be stored,
            # reported as "0 sessions, posture 100, LOW", and look like a clean capture.
            path.unlink(missing_ok=True)
            raise ValueError("The uploaded file is empty. Nothing was analysed.")
        logger.info(
            "Analysis %s: stored %s (%.2f MB) from %s",
            analysis_id,
            path.name,
            size / 1_048_576,
            uploaded_by,
        )
        sessions = analyze_pcap(path)
        logger.info("Analysis %s: %d email session(s) parsed", analysis_id, len(sessions))
        unclassified = self._unclassified_snapshot(path, sessions)
        if not sessions and unclassified is None:
            # No mail session and nothing encrypted to describe. Before reporting a clean
            # result, check that there was anything to read at all: a truncated or corrupt
            # file also yields zero sessions, and calling that "LOW risk, posture 100" is
            # the same false all-clear in a different disguise.
            packets = count_readable_packets(path)
            if packets == 0:
                raise ValueError(
                    "No readable packets in this file. It looks empty, truncated or "
                    "incomplete. Re-export the capture and upload it again."
                )
        result = self.build_result(
            analysis_id=analysis_id,
            source_filename=Path(filename).name,
            source_sha256=digest,
            source_size_bytes=size,
            sessions=sessions,
            metadata={
                "analyzer": "tshark",
                "capture_path": str(path.name),
                "upload_source": uploaded_by,
                "display_filter": MAIL_TLS_DISPLAY_FILTER,
                "scope": "SMTP/IMAP/POP3 traffic only (mail ports and mail-dissected streams)",
            },
            uploaded_by=uploaded_by,
        )
        if unclassified is not None:
            result.unclassified_streams = unclassified["streams"]
            result.unclassified_note = unclassified["note"]
        save_result(result)
        return result

    def _unclassified_snapshot(
        self, path: Path, sessions: list[SessionAnalysis]
    ) -> dict[str, object] | None:
        """Describe encrypted streams that produced no email session.

        Returns None when there is nothing to report, so a normal capture is unaffected.

        This exists because an upload that yields no session used to be returned as
        "0 sessions, posture 100, LOW" - which looks like a clean capture. When such a
        capture does contain encrypted streams, the honest answer is that traffic was
        found but the protocol inside it could not be proven, and that has to reach the
        dashboard and the reports rather than staying in the log.
        """
        if sessions:
            return None
        try:
            report = find_unclassified_tls(path, set())
        except Exception as exc:  # never fail an analysis over a diagnostic
            logger.info("Analysis: unclassified-stream check skipped (%s)", exc)
            return None
        if not report.streams:
            return None
        return {
            "streams": [
                {
                    "stream_id": stream.stream_id,
                    "server_port": stream.server_port,
                    "tls_version": stream.tls_version,
                    "tls_version_source": stream.tls_version_source,
                    "server_name": stream.server_name,
                    "certificate_visible": stream.certificate_visible,
                    "description": stream.describe(),
                }
                for stream in report.streams
            ],
            "note": report.headline(),
        }

    def create_demo(self) -> AnalysisResult:
        analysis_id = f"demo-{uuid.uuid4().hex[:12]}"
        sessions = demo_sessions()
        source = "securemailscope-demo.pcap"
        digest = hashlib.sha256(source.encode()).hexdigest()
        result = self.build_result(
            analysis_id=analysis_id,
            source_filename=source,
            source_sha256=digest,
            source_size_bytes=0,
            sessions=sessions,
            input_type="DEMO_FIXTURE",
            metadata={
                "analyzer": "controlled-demo-fixture",
                "training_note": "Synthetic controlled sessions for UI/integration testing",
            },
            uploaded_by="demo",
        )
        save_result(result)
        return result


service = AnalysisService()
