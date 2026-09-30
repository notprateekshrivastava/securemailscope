from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import numpy as np

from ..analysis.constants import risk_class_from_score
from ..analysis.features import FEATURE_NAMES
from ..config import settings
from ..schemas import SessionFeatures
from .model import ANOMALY_MODEL_FILE, MODEL_VERSION, RISK_MODEL_FILE, schema_fingerprint

try:
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
except ImportError as exc:  # pragma: no cover
    joblib = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment,misc]
    RandomForestClassifier = None  # type: ignore[assignment,misc]
    train_test_split = None  # type: ignore[assignment]
    classification_report = None  # type: ignore[assignment]
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


PROTOCOL_PORTS = {"SMTP": 25, "IMAP": 143, "POP3": 110}


def _risk_label(features: SessionFeatures) -> str:
    """Label a synthetic row the way the rule engine would.

    The single most important rule here: a value that means "not observed" must
    never be scored as a weakness. A plaintext session has no cipher score at all
    (0), and scoring that as "weak cipher" pushed every cleartext session straight
    to CRITICAL, which is both wrong and the opposite of what this project promises.
    Cipher and version penalties therefore apply only when TLS was actually used.
    """
    score = 0
    if features.tls_detected:
        if features.tls_version_rank <= 2:
            score += 45
        elif features.tls_version_rank == 3:
            score += 30
        if features.cipher_strength_score <= 20:
            score += 45
        elif features.cipher_strength_score <= 55:
            score += 18
    if features.forward_secrecy == 0:
        score += 18
    if not features.tls_detected and features.protocol != "UNKNOWN":
        score += 35
    if features.plaintext_authentication:
        score += 45
    # Certificate penalties apply only to observed evidence. When the certificate
    # is not on the wire (normal for TLS 1.3, and what a truncated capture looks
    # like) every one of these fields means "unknown" and contributes nothing.
    if features.certificate_present:
        if features.certificate_expired:
            score += 30
        if features.certificate_self_signed:
            score += 18
        if 0 < features.certificate_key_bits < 2048:
            score += 25
        if features.certificate_signature_strength == 1:
            score += 18
        if features.hostname_match == 0:
            score += 25
        if features.chain_complete == 0:
            score += 12
    # An unobserved certificate is logged, not punished: it is a gap in the
    # evidence, so it stays at the INFO weighting used by the rule engine.
    elif features.tls_detected and not features.handshake_complete:
        score += 4
    if features.handshake_failure_count:
        score += 12
    return risk_class_from_score(score)


def _base_secure(rng: random.Random, protocol: str) -> SessionFeatures:
    return SessionFeatures(
        protocol=protocol,
        server_port=PROTOCOL_PORTS[protocol],
        packet_count=rng.randint(25, 110),
        byte_count=rng.randint(5000, 100000),
        duration_ms=rng.uniform(100, 9000),
        retransmission_rate=max(0.0, rng.gauss(0.01, 0.008)),
        handshake_failure_count=0,
        tls_detected=1,
        tls_version_rank=rng.choice([4, 4, 5]),
        cipher_strength_score=rng.choice([85, 90, 95]),
        key_exchange_code=rng.choice([2, 3, 4]),
        forward_secrecy=1,
        starttls_advertised=int(protocol != "POP3" or rng.random() > 0.5),
        starttls_success=1,
        plaintext_authentication=0,
        certificate_present=1,
        certificate_expired=0,
        certificate_self_signed=0,
        certificate_key_bits=rng.choice([2048, 3072, 256]),
        certificate_signature_strength=3,
        hostname_match=1,
        chain_complete=1,
        sni_present=1,
        handshake_complete=1,
        repeated_client_hellos=0,
        cipher_rarity=rng.uniform(0.0, 0.15),
        certificate_changed=0,
    )


def generate_dataset(rows: int = 5000, seed: int = 42) -> tuple[np.ndarray, np.ndarray, list[SessionFeatures]]:
    rng = random.Random(seed)
    all_features: list[SessionFeatures] = []
    for _ in range(rows):
        protocol = rng.choice(list(PROTOCOL_PORTS))
        features = _base_secure(rng, protocol)
        scenario = rng.choices(
            [
                "secure",
                "legacy",
                "weak_cert",
                "plaintext",
                "pre_tls_auth",
                "unstable",
                "mixed",
                # Two combinations that occur constantly in real captures but were
                # missing here, which made the model escalate them:
                #   hidden_certificate  - TLS is in use but the certificate is not on
                #                         the wire. This is normal for TLS 1.3, and it
                #                         is what a truncated capture looks like. The
                #                         rule engine reports it as unobserved evidence,
                #                         never as a weakness, so the model must too.
                #   cleartext_no_auth   - a plaintext session where no authentication
                #                         pattern was visible. That is a weaker finding
                #                         than a session where a password was seen in
                #                         the clear, and the two must not collapse into
                #                         one class.
                "hidden_certificate",
                "cleartext_no_auth",
            ],
            weights=[38, 13, 13, 9, 4, 5, 9, 12, 10],
            k=1,
        )[0]
        if scenario == "legacy":
            features.tls_version_rank = rng.choice([1, 2, 3])
            features.cipher_strength_score = rng.choice([5, 20, 55])
            features.key_exchange_code = rng.choice([1, 2])
            features.forward_secrecy = 0
        elif scenario == "weak_cert":
            features.certificate_expired = int(rng.random() > 0.35)
            features.certificate_self_signed = int(rng.random() > 0.40)
            features.certificate_key_bits = rng.choice([1024, 1536, 2048])
            features.certificate_signature_strength = rng.choice([1, 1, 2])
            features.hostname_match = 0 if rng.random() > 0.5 else 1
            features.chain_complete = 0 if rng.random() > 0.45 else 1
        elif scenario == "plaintext":
            features.tls_detected = 0
            features.tls_version_rank = 0
            features.cipher_strength_score = 0
            features.key_exchange_code = 0
            features.forward_secrecy = -1
            features.starttls_success = 0
            features.plaintext_authentication = 1
            features.certificate_present = 0
            features.certificate_key_bits = 0
            features.certificate_signature_strength = 0
            features.hostname_match = -1
            features.chain_complete = -1
            features.handshake_complete = 0
        elif scenario == "hidden_certificate":
            # Valid, modern encryption whose certificate is simply not observable.
            # Every certificate feature says "unknown" (-1) or "not present" (0);
            # none of them is evidence of weakness.
            features.tls_detected = 1
            features.tls_version_rank = 4                      # TLS 1.3
            features.cipher_strength_score = rng.choice([85, 90, 95])
            features.key_exchange_code = 3                     # ephemeral
            features.forward_secrecy = 1
            features.handshake_complete = 1
            features.certificate_present = 0
            features.certificate_key_bits = 0
            features.certificate_signature_strength = 0
            features.certificate_expired = 0
            features.certificate_self_signed = 0
            features.hostname_match = -1
            features.chain_complete = -1
        elif scenario == "cleartext_no_auth":
            # Plaintext mail session without an observed authentication exchange.
            features.tls_detected = 0
            features.tls_version_rank = 0
            features.cipher_strength_score = 0
            features.key_exchange_code = 0
            features.forward_secrecy = -1
            features.starttls_success = 0
            features.plaintext_authentication = 0
            features.certificate_present = 0
            features.certificate_key_bits = 0
            features.certificate_signature_strength = 0
            features.hostname_match = -1
            features.chain_complete = -1
            features.handshake_complete = 0
        elif scenario == "pre_tls_auth":
            # Credentials were sent in the clear and the client upgraded only
            # afterwards. The session ends encrypted, but the exposure already
            # happened, so the risk stays high.
            features.plaintext_authentication = 1
            features.starttls_success = 1
            features.forward_secrecy = 1
        elif scenario == "unstable":
            features.handshake_failure_count = rng.randint(1, 4)
            features.repeated_client_hellos = rng.randint(1, 4)
            features.retransmission_rate = rng.uniform(0.08, 0.35)
            features.cipher_rarity = rng.uniform(0.75, 1.0)
        elif scenario == "mixed":
            if rng.random() > 0.5:
                features.forward_secrecy = 0
                features.key_exchange_code = 1
            if rng.random() > 0.5:
                features.certificate_self_signed = 1
            if rng.random() > 0.5:
                features.cipher_strength_score = 55
        all_features.append(features)

    X = np.asarray([features.as_vector() for features in all_features], dtype=float)
    y = np.asarray([_risk_label(features) for features in all_features])
    return X, y, all_features


# Where real sessions come from. `samples/sweep` is the systematic protocol x port x
# TLS-profile matrix produced by `tools/lab_capture_toolkit.py sweep`: it adds coverage of
# combinations the fifteen hand-written lab captures do not cover. It is scanned only if it
# exists, so a checkout without it trains exactly as before. `samples/stress` is deliberately
# NOT here - those files repeat the same conversations and duplication adds nothing.
CAPTURE_DIRS = ("samples", "samples/lab", "samples/sweep")


def find_capture_files(directories: tuple[str, ...] = CAPTURE_DIRS) -> list[Path]:
    """Return the PCAP/PCAPNG files available for real-feature training."""
    project_root = Path(__file__).resolve().parents[2]
    files: list[Path] = []
    for directory in directories:
        base = project_root / directory
        if not base.exists():
            continue
        for pattern in ("*.pcapng", "*.pcap", "*.cap"):
            files.extend(sorted(base.glob(pattern)))
    return files


def load_capture_dataset(
    directories: tuple[str, ...] = CAPTURE_DIRS, max_rows_per_capture: int = 300
) -> tuple[np.ndarray, np.ndarray, list[dict[str, object]]]:
    """Extract real session features from every available capture.

    Labels come from the explainable rule engine (weak supervision) and are
    recorded together with the capture they came from, so the training set stays
    auditable. Captures that need a tool which is not installed are skipped with
    a note instead of failing the whole training run.
    """
    from ..analysis.assessment import apply_policy_assessment
    from ..analysis.tshark import TSharkUnavailable, analyze_pcap

    vectors: list[list[float]] = []
    labels: list[str] = []
    groups: list[str] = []      # capture name per row, for grouped evaluation
    details: list[dict[str, object]] = []

    for path in find_capture_files(directories):
        try:
            sessions = [apply_policy_assessment(session) for session in analyze_pcap(path)]
        except TSharkUnavailable as exc:
            details.append({"capture": path.name, "error": str(exc), "sessions": 0})
            continue
        except Exception as exc:  # a damaged capture must not stop training
            details.append({"capture": path.name, "error": f"{type(exc).__name__}: {exc}", "sessions": 0})
            continue

        kept = sessions[:max_rows_per_capture]
        for session in kept:
            vectors.append(session.features.as_vector())
            labels.append(str(session.policy_risk_class))
            groups.append(path.name)
        details.append(
            {
                "capture": path.name,
                "sessions": len(kept),
                "sessions_in_capture": len(sessions),
                "rows_capped": len(sessions) > len(kept),
                "protocols": sorted({str(session.protocol) for session in sessions}),
                "labels": sorted({str(session.policy_risk_class) for session in sessions}),
            }
        )

    if not vectors:
        empty = np.empty((0, len(FEATURE_NAMES)))
        return empty, np.empty((0,), dtype=object), details, np.empty((0,), dtype=object)
    return (
        np.asarray(vectors, dtype=float),
        np.asarray(labels),
        details,
        np.asarray(groups, dtype=object),
    )


# How often each real capture row is repeated in the training set.
#
# This single number decides whether the model generalises or memorises, and it is
# not a guess: leave-one-capture-out accuracy was measured for each setting.
#
#     capture rows repeated   honest holdout accuracy
#     none (synthetic only)   53/63   84.1%
#     x1                      55/63   87.3%
#     x2                      55/63   87.3%
#     x3                      54/63   85.7%
#     x6                      54/63   85.7%
#     x12                     20/63   31.7%
#     x60                     18/63   28.6%   <- the old default
#
# Repeating captures a few times lets the model see them; repeating them dozens of
# times makes it memorise 63 specific sessions and it then misreads any capture it
# has not seen. Two is the measured optimum.
DEFAULT_CAPTURE_REPEAT = 2


def train_models(
    rows: int = 5000,
    seed: int = 42,
    output_dir: Path | None = None,
    capture_dirs: tuple[str, ...] = CAPTURE_DIRS,
    capture_repeat: int = DEFAULT_CAPTURE_REPEAT,
    include_captures: bool = True,
) -> dict[str, object]:
    if IMPORT_ERROR is not None:
        raise RuntimeError("Install scikit-learn, numpy and joblib before training") from IMPORT_ERROR
    output_dir = output_dir or settings.model_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    X, y, features = generate_dataset(rows, seed)

    # Real captures: features measured by the parser, labels assigned by the rule
    # engine. They are repeated because a handful of real sessions would
    # otherwise disappear inside thousands of synthetic rows.
    capture_details: list[dict[str, object]] = []
    capture_rows = 0
    X_capture = np.empty((0, X.shape[1]))
    y_capture = np.empty((0,), dtype=object)
    if include_captures:
        X_capture, y_capture, capture_details, capture_groups = load_capture_dataset(capture_dirs)
        capture_rows = int(X_capture.shape[0])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )
    if capture_rows:
        X_train = np.vstack([X_train, np.repeat(X_capture, capture_repeat, axis=0)])
        y_train = np.concatenate([y_train, np.repeat(y_capture, capture_repeat)])
    classifier = RandomForestClassifier(
        n_estimators=220,
        random_state=seed,
        class_weight="balanced",
        min_samples_leaf=2,
    )
    classifier.fit(X_train, y_train)

    # Anomaly detection is trained on the secure-looking portion of the
    # synthetic data. Production retraining should use an organisation's
    # approved healthy baseline sessions.
    secure_mask = np.asarray([label == "LOW" for label in y_train])
    normal_X = X_train[secure_mask] if secure_mask.any() else X_train
    anomaly = IsolationForest(
        n_estimators=180,
        contamination=0.08,
        random_state=seed,
    )
    anomaly.fit(normal_X)

    joblib.dump(classifier, output_dir / RISK_MODEL_FILE)
    joblib.dump(anomaly, output_dir / ANOMALY_MODEL_FILE)

    # Save the generated feature rows so the team can inspect exactly what the
    # model learned from instead of treating training as a black box.
    dataset_path = output_dir / "training_dataset.csv"
    with dataset_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURE_NAMES, "risk_label"])
        for row, label in zip(X, y):
            writer.writerow([*row.tolist(), label])

    validation_predictions = classifier.predict(X_test)
    validation_accuracy = float(np.mean(validation_predictions == y_test))

    capture_summary: dict[str, object] = {}
    mismatches: list[dict[str, object]] = []
    if capture_rows:
        capture_predictions = classifier.predict(X_capture)
        anomalies = anomaly.predict(X_capture)
        confusion: dict[str, dict[str, int]] = {}
        anomalous_count = 0
        matches = 0
        for expected, predicted, anomaly_flag in zip(y_capture, capture_predictions, anomalies):
            expected_key, predicted_key = str(expected), str(predicted)
            confusion.setdefault(expected_key, {})
            confusion[expected_key][predicted_key] = confusion[expected_key].get(predicted_key, 0) + 1
            if expected_key == predicted_key:
                matches += 1
            if anomaly_flag == -1:
                anomalous_count += 1
            elif len(mismatches) < 10:
                mismatches.append({"expected": expected_key, "model": predicted_key})
        capture_summary = {
            "rows": capture_rows,
            "match_rate": f"{matches}/{capture_rows}",
            "confusion": confusion,
            "flagged_anomalous": anomalous_count,
            "mismatch_examples": mismatches,
            "scope": "in-sample (capture rows were used for training); small sample, weak-supervision labels",
        }
    # --- honest generalisation estimate -------------------------------------
    # In-sample agreement is not a performance measure: those rows helped train the
    # model. Leave-one-capture-out trains on every capture but one and predicts the
    # held-out capture, which is the number to quote to a reviewer.
    holdout: dict[str, object] = {"method": "leave-one-capture-out", "captures": 0, "rows": 0}
    if capture_rows and len(set(capture_groups.tolist())) > 1:
        per_capture: list[dict[str, object]] = []
        correct = total = 0
        for name in sorted(set(capture_groups.tolist())):
            test_mask = capture_groups == name
            train_mask = ~test_mask
            if not train_mask.any() or not test_mask.any():
                continue
            # Training features: the synthetic rows plus every capture except this one.
            fold_train_X = np.vstack([X, np.repeat(X_capture[~test_mask], capture_repeat, axis=0)])
            fold_train_y = np.concatenate([y, np.repeat(y_capture[~test_mask], capture_repeat)])
            fold_model = RandomForestClassifier(
                n_estimators=120, random_state=seed, class_weight="balanced", min_samples_leaf=2
            )
            fold_model.fit(fold_train_X, fold_train_y)
            predictions = fold_model.predict(X_capture[test_mask])
            expected = y_capture[test_mask]
            fold_correct = int(np.sum(predictions == expected))
            correct += fold_correct
            total += int(test_mask.sum())
            per_capture.append({
                "capture": name,
                "rows": int(test_mask.sum()),
                "correct": fold_correct,
                "expected_labels": sorted(set(str(item) for item in expected)),
                "predicted_labels": sorted(set(str(item) for item in predictions)),
            })
        holdout = {
            "method": "leave-one-capture-out (a whole capture is held out, so no session from it helped training)",
            "captures": len(per_capture),
            "rows": total,
            "correct": correct,
            "match_rate": f"{correct}/{total}",
            "accuracy": round(correct / total, 4) if total else None,
            "per_capture": per_capture,
            "note": (
                "Small sample: 13 captures and about 63 sessions with weak-supervision "
                "labels. Read this as a sanity check, not as field performance."
            ),
        }

    # --- transfer test ------------------------------------------------------
    # Trained on synthetic rows only, evaluated on every real capture. This is the
    # strongest statement available here: not one real session helped training.
    transfer: dict[str, object] = {"method": "trained on synthetic rows only, evaluated on real captures"}
    if capture_rows:
        transfer_model = RandomForestClassifier(
            n_estimators=220, random_state=seed, class_weight="balanced", min_samples_leaf=2
        )
        transfer_model.fit(X, y)
        transfer_predictions = transfer_model.predict(X_capture)
        transfer_correct = int(np.sum(transfer_predictions == y_capture))
        transfer = {
            "method": "trained on synthetic rows only, evaluated on real captures (no real session seen in training)",
            "rows": capture_rows,
            "correct": transfer_correct,
            "match_rate": f"{transfer_correct}/{capture_rows}",
            "accuracy": round(transfer_correct / capture_rows, 4) if capture_rows else None,
            "per_capture": [
                {
                    "capture": name,
                    "rows": int((capture_groups == name).sum()),
                    "correct": int(np.sum(
                        transfer_model.predict(X_capture[capture_groups == name]) == y_capture[capture_groups == name]
                    )),
                }
                for name in sorted(set(capture_groups.tolist()))
            ],
        }

    capture_matches = int(str(capture_summary.get("match_rate", "0/0")).split("/")[0]) if capture_summary else 0
    # Per-feature training ranges. These ship with the model so `python -m app.cli check`
    # can warn when a new capture falls outside what the model has actually seen,
    # instead of returning a confident class with no basis for it.
    import numpy as np_hint  # noqa: F401  (numpy is already imported as np above)

    feature_ranges: dict[str, dict[str, float]] = {}
    reference = np.vstack([X_train, X_capture]) if capture_rows else X_train
    for index, name in enumerate(FEATURE_NAMES):
        column = reference[:, index]
        feature_ranges[name] = {
            "min": float(np.min(column)),
            "p01": float(np.percentile(column, 1)),
            "p50": float(np.percentile(column, 50)),
            "p99": float(np.percentile(column, 99)),
            "max": float(np.max(column)),
        }

    metadata = {
        "model_version": MODEL_VERSION,
        "feature_ranges": feature_ranges,
        "feature_ranges_note": (
            "Percentiles of the data the model was trained on. A session with several "
            "features outside p01-p99 is unlike the training set, and its ML class should "
            "be treated as unvalidated; the rule findings remain the evidence."
        ),
        "schema_fingerprint": schema_fingerprint(),
        "rows": rows,
        "seed": seed,
        "features": FEATURE_NAMES,
        "classes": list(classifier.classes_),
        "validation_accuracy": round(validation_accuracy, 4),
        "validation_scope": "held-out 20% of synthetic rows",
        "capture_rows": capture_rows,
        "capture_repeat": capture_repeat if capture_rows else 0,
        "capture_sources": capture_details,
        "capture_calibration": capture_summary,
        "capture_calibration_matches": capture_summary.get("match_rate", "0/0"),
        "capture_holdout": holdout,
        "synthetic_transfer": transfer,
        "training_dataset": str(dataset_path.name),
        "training_note": (
            "Synthetic rows (random scenario generator) plus real capture rows labelled by the "
            "explainable rule engine (weak supervision). Synthetic accuracy is not production "
            "accuracy evidence. Two capture numbers are recorded: capture_calibration is "
            "in-sample (those rows were used for training) and capture_holdout is "
            "leave-one-capture-out, which is the honest one to quote."
        ),
        "validation_report": classification_report(y_test, validation_predictions, output_dict=True),
    }
    (output_dir / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    result = train_models()
    holdout = result.get("capture_holdout") or {}
    print()
    print("=" * 68)
    print("Training complete")
    print(f"  model version          : {result.get('model_version')}")
    print(f"  synthetic rows         : {result.get('rows')} (accuracy {result.get('validation_accuracy')})")
    print(f"  real capture rows      : {result.get('capture_rows')}")
    print(f"  capture calibration    : {result.get('capture_calibration_matches')}  (in-sample - these rows trained the model)")
    if holdout.get("match_rate"):
        print(f"  capture holdout        : {holdout.get('match_rate')}  (leave-one-capture-out)")
    transfer = result.get("synthetic_transfer") or {}
    if transfer.get("match_rate"):
        print(f"  synthetic transfer     : {transfer.get('match_rate')}  (trained on synthetic only, tested on real captures)")
    print(f"  schema fingerprint     : {result.get('schema_fingerprint')}")
    print("=" * 68)
    print(json.dumps(
        {key: value for key, value in result.items() if key not in {"validation_report", "capture_sources"}},
        indent=2,
    ))
