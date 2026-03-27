import json
import numpy as np
import joblib
import os

from sklearn.preprocessing import StandardScaler
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.hbos import HBOS


BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATA_PATH = os.path.join(BASE_DIR, "data", "baseline_logs_750.json")
MODEL_PATH = os.path.join(BASE_DIR, "models", "pyod_model.pkl")


def build_feature_vector(event):

    df = event.get("detection_features", {})
    ff = event.get("family_detection_features", {})

    family_map = {
        "network": 0,
        "endpoint": 1,
        "auth": 2,
        "firewall": 3,
        "iot": 4
    }

    family = family_map.get(event.get("log_family", "network"), 0)

    return [

        int(df.get("is_off_hours", False)),
        df.get("event_count_5m", 0),
        df.get("deviation_score", 0.0),

        int(ff.get("spike_detected", False)),
        int(ff.get("protocol_anomaly_detected", False)),
        ff.get("unique_destinations_seen", 0),

        family
    ]


def main():

    print("Loading training data...")

    with open(DATA_PATH) as f:
        data = json.load(f)

    events = data.get("sample_enriched") or data.get("enriched_logs")

    if not events:
        raise ValueError("No events found in dataset")

    X = np.array([build_feature_vector(e) for e in events], dtype=float)

    print("Training on", X.shape)

    # ─── Feature Scaling ─────────────────────

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ─── Models ──────────────────────────────

    iforest = IForest(contamination=0.05, random_state=42)
    lof = LOF(contamination=0.05)
    hbos = HBOS(contamination=0.05)

    iforest.fit(X_scaled)
    lof.fit(X_scaled)
    hbos.fit(X_scaled)

    # ─── Save model + scaler ─────────────────

    joblib.dump((iforest, lof, hbos, scaler), MODEL_PATH)

    print("Model saved to:", MODEL_PATH)


if __name__ == "__main__":
    main()