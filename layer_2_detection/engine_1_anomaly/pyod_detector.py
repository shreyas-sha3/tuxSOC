import logging
import numpy as np
import joblib
import os

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../models/pyod_model.pkl"
)

_models = None


def load_models():

    global _models

    if _models is None:

        if not os.path.exists(MODEL_PATH):
            raise RuntimeError(
                "PyOD model not trained. Run training/train_pyod.py first."
            )

        logger.info("Loading PyOD models from disk...")
        _models = joblib.load(MODEL_PATH)

    return _models


def build_feature_vector(event):

    df = event.get("detection_features", {})
    ff = event.get("family_detection_features", {})

    family_map = {
        "network":0,
        "endpoint":1,
        "auth":2,
        "firewall":3,
        "iot":4
    }

    family = family_map.get(event.get("log_family","network"),0)

    return [
        int(df.get("is_off_hours", False)),
        df.get("event_count_5m", 0),
        df.get("deviation_score", 0.0),

        int(ff.get("spike_detected", False)),
        int(ff.get("protocol_anomaly_detected", False)),
        ff.get("unique_destinations_seen", 0),

        family
    ]


def score_event(feature_vector):

    iforest, lof, hbos, scaler = load_models()

    X = np.array(feature_vector).reshape(1, -1)

    # apply same scaling used during training
    X = scaler.transform(X)

    if_label = int(iforest.predict(X)[0])
    lof_label = int(lof.predict(X)[0])
    hbos_label = int(hbos.predict(X)[0])

    if_score = float(iforest.decision_function(X)[0])
    lof_score = float(lof.decision_function(X)[0])
    hbos_score = float(hbos.decision_function(X)[0])

    def norm(s):
        return float(1 / (1 + np.exp(-s)))

    scores = [norm(if_score), norm(lof_score), norm(hbos_score)]
    avg_score = float(np.mean(scores))

    votes = {
        "iforest": if_label,
        "lof": lof_label,
        "hbos": hbos_label
    }

    outlier_votes = sum(votes.values())

    fidelity = round(outlier_votes / 3, 2)
    is_outlier = outlier_votes >= 2

    return {
        "pyod_score": round(avg_score, 4),
        "is_outlier": is_outlier,
        "fidelity_score": fidelity,
        "model_votes": votes
    }