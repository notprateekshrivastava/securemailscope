from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import BinaryIO

from .config import settings
from .schemas import AnalysisResult


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_upload(upload: BinaryIO, analysis_id: str, filename: str) -> tuple[Path, str, int]:
    safe_name = Path(filename).name or "capture.pcap"
    destination = settings.upload_dir / f"{analysis_id}_{safe_name}"
    total = 0
    limit = settings.max_upload_mb * 1024 * 1024
    with destination.open("wb") as handle:
        while True:
            chunk = upload.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                destination.unlink(missing_ok=True)
                raise ValueError(f"Upload exceeds {settings.max_upload_mb} MB limit")
            handle.write(chunk)
    return destination, sha256_file(destination), total


def save_result(result: AnalysisResult) -> Path:
    destination = settings.analysis_dir / f"{result.analysis_id}.json"
    destination.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return destination


def load_result(analysis_id: str) -> AnalysisResult:
    source = settings.analysis_dir / f"{analysis_id}.json"
    if not source.exists():
        raise FileNotFoundError(analysis_id)
    return AnalysisResult.model_validate_json(source.read_text(encoding="utf-8"))


def list_results() -> list[AnalysisResult]:
    results: list[AnalysisResult] = []
    for path in sorted(settings.analysis_dir.glob("*.json"), reverse=True):
        try:
            results.append(AnalysisResult.model_validate_json(path.read_text(encoding="utf-8")))
        except Exception:
            continue
    return results
