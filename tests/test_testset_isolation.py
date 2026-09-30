"""The held-out test set must stay out of training.

A test set that leaks into training measures nothing, and it leaks quietly: the numbers go
up, nothing errors, and the only symptom is a claim that no longer means anything. These
tests are the guard, so the isolation does not depend on anybody remembering.

They cover both directions:

* `testset/` is not in the folders `train.py` scans, and no capture inside it is ever
  returned by the file scanner, whatever the folder happens to contain.
* The declarations the test set is scored against are still marked as written before the
  captures were analysed, and every session has an expectation - an empty expectation would
  make a failing session pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ml import train as train_module

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTSET_DIR = PROJECT_ROOT / "testset"


def test_testset_is_not_a_training_directory() -> None:
    scanned = {str(Path(entry)) for entry in train_module.CAPTURE_DIRS}
    assert "testset" not in scanned
    assert not any("testset" in entry for entry in scanned), (
        "the held-out test set must never be one of the folders train.py reads"
    )


def test_scanner_never_returns_a_testset_capture() -> None:
    """Even with the folder present and full of captures, the scanner ignores it."""
    if not TESTSET_DIR.exists():
        pytest.skip("test set has not been generated on this machine")

    found = [Path(item) for item in train_module.find_capture_files()]
    leaked = [str(item) for item in found if "testset" in item.parts]
    assert not leaked, f"training would read held-out captures: {leaked[:3]}"
    assert found, "the scanner should still find the ordinary sample captures"


def test_expectations_are_complete_and_written_up_front() -> None:
    ground_truth_path = TESTSET_DIR / "ground_truth.json"
    if not ground_truth_path.exists():
        pytest.skip("test set has not been generated on this machine")

    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    assert ground_truth["expectations_written"] == "before capture"
    assert ground_truth["captures"], "a test set with no captures scores nothing"

    for capture in ground_truth["captures"]:
        assert capture["sessions"], f"{capture['name']} declares no sessions"
        for session in capture["sessions"]:
            declared = (
                session.get("expect_findings")
                or session.get("forbid_findings")
                or session.get("class_exact")
                or session.get("class_band")
                or session.get("facts")
            )
            assert declared, (
                f"{capture['name']} declares a session with no expectation at all, which "
                "would let a wrong result pass silently"
            )


def test_profiles_declare_what_they_must_and_must_not_show() -> None:
    """Every TLS profile the test set uses has both a requirement and a prohibition."""
    from tools import lab_capture_toolkit  # type: ignore[import-not-found]

    for profile in lab_capture_toolkit.TESTSET_PROFILE_VERSIONS:
        assert profile in lab_capture_toolkit.TESTSET_PROFILE_FINDINGS
        assert lab_capture_toolkit.TESTSET_PROFILE_FORBIDDEN[profile], (
            f"{profile} forbids nothing, so a false accusation on it would go unnoticed"
        )
