import json
from pathlib import Path

from app.ml.train import generate_dataset, train_models
from app.ml.model import ModelBundle
from app.analysis.assessment import apply_policy_assessment
from app.analysis.fixtures import demo_sessions


def test_synthetic_dataset_can_be_generated():
    X, y, features = generate_dataset(rows=120, seed=7)
    assert X.shape[0] == 120
    assert X.shape[1] == len(features[0].as_vector())
    assert set(y).issubset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


def test_model_training_and_prediction(tmp_path: Path):
    train_models(rows=240, seed=7, output_dir=tmp_path)
    bundle = ModelBundle(tmp_path)
    assert bundle.available
    result = bundle.assess(demo_sessions()[1])
    assert result.risk_class in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.confidence is not None


def test_stale_model_is_refused_instead_of_contradicting_the_rules(tmp_path: Path):
    """A model trained with a different schema must not be used.

    Reports are read as evidence. A model whose features or risk bands no longer
    match the code would disagree with the findings in the same report, so it is
    rejected and the deterministic rule result is returned instead.
    """
    train_models(rows=240, seed=3, output_dir=tmp_path, include_captures=False)
    assert ModelBundle(tmp_path).available is True

    metadata_path = tmp_path / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["schema_fingerprint"] = "0" * 16  # pretend an older training run
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    bundle = ModelBundle(tmp_path)
    assert bundle.available is False
    assert bundle.version == "stale"
    assert bundle.note and "python -m app.ml.train" in bundle.note

    session = apply_policy_assessment(demo_sessions()[1])
    assessed = bundle.assess(session)
    assert assessed.risk_class == session.policy_risk_class


def test_api_works_before_any_model_is_trained(tmp_path: Path):
    """A fresh clone has no .joblib files yet.

    The service must still answer, using the deterministic rule result as the
    fallback, instead of raising NameError/AttributeError on the first upload.
    """
    bundle = ModelBundle(tmp_path)  # deliberately empty directory
    assert bundle.available is False

    for session in demo_sessions():
        assessed = bundle.assess(session)
        assert assessed.risk_class in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert assessed.model_version.startswith("rule-fallback")
        assert assessed.explanation
