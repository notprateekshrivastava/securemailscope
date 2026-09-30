from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..analysis.constants import RISK_CLASS_BANDS, risk_class_from_findings
from ..analysis.features import FEATURE_NAMES
from ..schemas import MLAssessment, SessionAnalysis

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None  # type: ignore[assignment]


def read_stored_fingerprint(model_dir: Path) -> str | None:
    """Return the schema fingerprint recorded next to a trained model, if any."""
    metadata_path = model_dir / METADATA_FILE
    if not metadata_path.exists():
        return None
    try:
        return json.loads(metadata_path.read_text(encoding="utf-8")).get("schema_fingerprint")
    except Exception:
        return None


RISK_MODEL_FILE = "risk_model.joblib"
ANOMALY_MODEL_FILE = "anomaly_model.joblib"
METADATA_FILE = "model_metadata.json"
# v2: the synthetic labeller no longer scores unobserved evidence (no cipher, no
# certificate) as a weakness, and captures are repeated twice instead of sixty
# times. Both changes move the decision boundary, so a v1 model must not be reused.
MODEL_VERSION = "synthetic-v2"


def schema_fingerprint() -> str:
    """Fingerprint of everything a trained model depends on.

    A saved model is only meaningful together with the exact feature order and
    the exact risk-class definition it was trained with. If either changes, the
    model's answers silently stop matching the rule engine - which is worse than
    having no model at all in a forensic report. The fingerprint is stored in
    ``model_metadata.json`` at training time and compared at load time.
    """
    payload = json.dumps(
        {
            "model_version": MODEL_VERSION,
            "features": FEATURE_NAMES,
            "risk_class_bands": RISK_CLASS_BANDS,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class ModelBundle:
    def __init__(self, model_dir: Path) -> None:
        self.model_dir = model_dir
        self.risk_model: Any = None
        self.anomaly_model: Any = None
        self.version = "not_loaded"
        self.note: str | None = None
        self.load()

    @property
    def available(self) -> bool:
        return self.risk_model is not None and self.anomaly_model is not None

    def load(self) -> None:
        self.version = "not_loaded"
        self.note = None
        if joblib is None:
            self.note = "joblib is not installed; rule-based classification is used."
            return
        risk_path = self.model_dir / RISK_MODEL_FILE
        anomaly_path = self.model_dir / ANOMALY_MODEL_FILE
        if risk_path.exists() and anomaly_path.exists():
            try:
                risk_model = joblib.load(risk_path)
                anomaly_model = joblib.load(anomaly_path)
            except Exception as exc:
                self.risk_model = None
                self.anomaly_model = None
                self.version = "load_failed"
                self.note = f"the saved model could not be read: {type(exc).__name__}"
                return

            stored = read_stored_fingerprint(self.model_dir)
            if stored != schema_fingerprint():
                # Do not use a model whose feature schema or risk bands no longer
                # match the code: it would contradict the evidence-based findings.
                self.risk_model = None
                self.anomaly_model = None
                self.version = "stale"
                self.note = (
                    "the saved model was trained with a different feature schema or risk-class "
                    "definition, so it was not loaded. Rule-based classification is used instead. "
                    "Run: python -m app.ml.train"
                )
                return

            self.risk_model = risk_model
            self.anomaly_model = anomaly_model
            self.version = MODEL_VERSION
            self.note = None

    def _heuristic(self, session: SessionAnalysis) -> MLAssessment:
        score = session.policy_risk_score
        risk = risk_class_from_findings(
            [str(finding.severity) for finding in session.findings], score
        )
        explanation = [
            "No trained model is in use, so the deterministic rule result is reported: "
            "the classification follows the findings above."
        ]
        if self.note:
            explanation.append(self.note)
        return MLAssessment(
            risk_class=risk,
            confidence=None,
            anomaly_score=None,
            anomalous=False,
            model_version=f"rule-fallback ({self.version})",
            explanation=explanation,
        )

    def assess(self, session: SessionAnalysis) -> MLAssessment:
        if not self.available:
            return self._heuristic(session)
        vector = [session.features.as_vector()]
        try:
            probabilities = self.risk_model.predict_proba(vector)[0]
            classes = list(self.risk_model.classes_)
            index = int(max(range(len(probabilities)), key=lambda i: probabilities[i]))
            risk_class = str(classes[index]).upper()
            confidence = round(float(probabilities[index]) * 100, 2)
            anomaly_prediction = int(self.anomaly_model.predict(vector)[0])
            raw = float(self.anomaly_model.decision_function(vector)[0])
            anomaly_score = max(0.0, min(1.0, 0.5 - raw))
            return MLAssessment(
                risk_class=risk_class,
                confidence=confidence,
                anomaly_score=round(anomaly_score, 4),
                anomalous=anomaly_prediction == -1,
                model_version=self.version,
                explanation=[],
            )
        except Exception as exc:
            fallback = self._heuristic(session)
            fallback.explanation.append(f"ML prediction fallback: {type(exc).__name__}")
            return fallback


def model_available(model_dir: Path) -> bool:
    if joblib is None:
        return False
    return (model_dir / RISK_MODEL_FILE).exists() and (model_dir / ANOMALY_MODEL_FILE).exists()
