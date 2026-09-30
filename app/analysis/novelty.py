"""Is this capture something the model has actually seen before?

The honest answer to "can it handle any file I upload?" has two parts:

1. The parser and the rule engine handle **any** capture. They are deterministic and
   evidence-based: no training is involved, so an unseen mail server, an unseen port
   or an unseen cipher is analysed on its own evidence.
2. The machine learning layer was trained on a known set of sessions. Given something
   unlike that set it still returns a class, and that class has no basis. This module
   detects that situation so the interface can say so, instead of presenting a number
   that looks authoritative.

The check is deliberately simple and explainable: compare each feature of a session
with the percentile range of the data the model was trained on, and count how many
features fall outside. Several outside means the session is unlike the training set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analysis.features import FEATURE_NAMES
from ..schemas import SessionAnalysis


@dataclass
class NoveltyResult:
    """How far a session sits from what the model was trained on."""

    compared_features: int = 0
    outside_features: list[str] = field(default_factory=list)
    checked: bool = False
    note: str | None = None

    @property
    def outside_count(self) -> int:
        return len(self.outside_features)

    @property
    def novel(self) -> bool:
        # Two or more features outside the training range, or a tenth of them, is
        # enough to say the model is out of its depth. One odd feature is normal:
        # packet counts and durations vary between any two captures.
        if not self.checked:
            return False
        return self.outside_count >= max(2, self.compared_features // 10)

    @property
    def verdict(self) -> str:
        if not self.checked:
            return "UNCHECKED"
        return "OUTSIDE TRAINING RANGE" if self.novel else "within training range"

    def explain(self) -> str:
        if not self.checked:
            return self.note or "No training ranges available; train the model first."
        if not self.outside_features:
            return "Every feature is inside the range the model was trained on."
        listed = ", ".join(self.outside_features[:6])
        extra = "" if self.outside_count <= 6 else f" (+{self.outside_count - 6} more)"
        if self.novel:
            return (
                f"{self.outside_count} of {self.compared_features} features are outside the "
                f"training range: {listed}{extra}. The ML class is not validated for this "
                "session - rely on the rule findings."
            )
        return f"Features slightly outside the training range: {listed}{extra}."


def load_feature_ranges(model_dir: Path) -> dict[str, dict[str, float]] | None:
    """Read the training ranges written into model_metadata.json."""
    path = Path(model_dir) / "model_metadata.json"
    if not path.exists():
        return None
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    ranges = metadata.get("feature_ranges")
    return ranges if isinstance(ranges, dict) and ranges else None


def check_session(
    session: SessionAnalysis, ranges: dict[str, dict[str, float]] | None
) -> NoveltyResult:
    """Compare one session's features with the training ranges."""
    if not ranges:
        return NoveltyResult(checked=False, note="No feature ranges in the model metadata.")

    values: dict[str, Any] = session.features.model_dump(mode="json")
    result = NoveltyResult(checked=True)
    for name in FEATURE_NAMES:
        if name not in ranges or name not in values:
            continue
        value = values[name]
        if value is None:
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        result.compared_features += 1
        bounds = ranges[name]
        low = bounds.get("p01", bounds.get("min"))
        high = bounds.get("p99", bounds.get("max"))
        if low is None or high is None:
            continue
        if numeric < low or numeric > high:
            result.outside_features.append(name)
    return result


def check_capture(
    sessions: list[SessionAnalysis], ranges: dict[str, dict[str, float]] | None
) -> NoveltyResult:
    """Check a whole capture, reporting how many sessions are unlike the training set."""
    if not ranges:
        return NoveltyResult(checked=False, note="No feature ranges in the model metadata.")
    if not sessions:
        return NoveltyResult(checked=False, note="No email sessions found in this capture.")

    per_session = [check_session(session, ranges) for session in sessions]
    novel_sessions = [item for item in per_session if item.novel]
    combined = NoveltyResult(checked=True)
    combined.compared_features = per_session[0].compared_features
    # Union of the features that are outside range anywhere in the capture.
    seen: list[str] = []
    for item in per_session:
        for name in item.outside_features:
            if name not in seen:
                seen.append(name)
    combined.outside_features = seen

    if novel_sessions:
        combined.note = (
            f"{len(novel_sessions)} of {len(sessions)} session(s) fall outside the training "
            "range. The rule findings still apply; treat the ML class as unvalidated here."
        )
    else:
        combined.note = (
            f"All {len(sessions)} session(s) are within the range the model was trained on."
        )
    return combined
