"""Traceability of stored results: every analysis names the build that made it.

Why this matters for the submission: the reports are read as evidence, so a report
has to say which version of the analyzer produced it. Without that stamp a result
made before a parser fix is indistinguishable from a current one, and the stored
folder fills up with results that contradict the code.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.service import AnalysisService
from app.storage import save_result
from app.version import ANALYZER_VERSION


def _write_result(tmp_path: Path, monkeypatch) -> Path:
    from app import storage

    # analysis_dir is derived from data_dir, which is what can be redirected.
    monkeypatch.setattr(storage.settings, "data_dir", tmp_path)
    (tmp_path / "analyses").mkdir(parents=True, exist_ok=True)
    service = AnalysisService()
    result = service.build_result(
        analysis_id="version-test",
        source_filename="sample.pcapng",
        source_sha256="0" * 64,
        source_size_bytes=1024,
        sessions=[],
        uploaded_by="team",
    )
    return save_result(result)


def test_stored_analysis_records_the_analyzer_version(tmp_path: Path, monkeypatch):
    path = _write_result(tmp_path, monkeypatch)
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["analyzer_version"] == ANALYZER_VERSION
    # Not the old hardcoded placeholder: that value could never detect a stale result.
    assert stored["analyzer_version"] != "0.1.0"


def test_version_is_single_sourced_from_the_version_module():
    """The API version, the report version and the stored version are one number."""
    from app.config import settings
    from app.schemas import AnalysisResult

    assert settings.version == ANALYZER_VERSION
    assert AnalysisResult.model_fields["analyzer_version"].default == ANALYZER_VERSION
