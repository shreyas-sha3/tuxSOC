"""
pyod_detector.py
----------------
PyOD ensemble anomaly detector (IForest + LOF).
Receives the feature matrix from layer_1 and produces:
  - pyod_score   : 0.0–1.0 continuous outlier score
  - is_outlier   : bool
  - fidelity_score: model agreement (0.33 = one model, 0.67 = two, 1.0 = all three)

Uses IForest + LOF (+ HBOS for tiebreaking) as an ensemble.
"""

import logging
import numpy as np
from typing import Any

logger = logging.getLogger(__name__)

# Lazy imports — only load pyod when actually called, to keep startup fast
_iforest = None
_lof     = None
_hbos    = None
_fitted  = False


def _get_models():
    global _iforest, _lof, _hbos
    if _iforest is None:
        try:
            from pyod.models.iforest import IForest
            from pyod.models.lof    import LOF
            from pyod.models.hbos   import HBOS
            _iforest = IForest(contamination=0.05, n_estimators=100, random_state=42)
            _lof     = LOF(contamination=0.05, n_neighbors=20)
            _hbos    = HBOS(contamination=0.05, n_bins=10)
        except ImportError as e:
            logger.error("PyOD not installed: %s", e)
            raise
    return _iforest, _lof, _hbos


def fit(X: np.ndarray) -> None:
    """Fit the ensemble on a training matrix. Call this at startup with historical data."""
    global _fitted
    iforest, lof, hbos = _get_models()
    logger.info("Fitting PyOD ensemble on shape %s", X.shape)
    iforest.fit(X)
    lof.fit(X)
    hbos.fit(X)
    _fitted = True
    logger.info("PyOD ensemble fitted.")


def score_event(feature_vector: list[float]) -> dict:
    """
    Score a single event's feature vector.

    Returns:
        {
          "pyod_score": float,       # average decision score across ensemble
          "is_outlier": bool,
          "fidelity_score": float,   # 0.33 | 0.67 | 1.0 — fraction of models agreeing
          "model_votes": dict        # per-model verdict for transparency
        }
    """
    iforest, lof, hbos = _get_models()

    if not _fitted:
        logger.warning("Models not fitted — using untrained scores (high false positive risk).")

    X = np.array(feature_vector, dtype=float).reshape(1, -1)

    try:
        if_label  = int(iforest.predict(X)[0])   # 1 = outlier, 0 = normal
        lof_label = int(lof.predict(X)[0])
        hbos_label= int(hbos.predict(X)[0])

        if_score  = float(iforest.decision_function(X)[0])
        lof_score = float(lof.decision_function(X)[0])
        hbos_score= float(hbos.decision_function(X)[0])

        # Normalise scores to 0–1 range (sigmoid-style clamp)
        def norm(s): return float(1 / (1 + np.exp(-s)))

        scores = [norm(if_score), norm(lof_score), norm(hbos_score)]
        avg_score = float(np.mean(scores))

        votes = {"iforest": if_label, "lof": lof_label, "hbos": hbos_label}
        outlier_votes = sum(votes.values())

        fidelity = round(outlier_votes / 3, 2)    # 0.0 | 0.33 | 0.67 | 1.0
        is_outlier = outlier_votes >= 2             # majority vote

        return {
            "pyod_score":    round(avg_score, 4),
            "is_outlier":    is_outlier,
            "fidelity_score": fidelity,
            "model_votes":   votes,
        }

    except Exception as e:
        logger.error("PyOD scoring failed: %s", e)
        return {
            "pyod_score": 0.0,
            "is_outlier": False,
            "fidelity_score": 0.0,
            "model_votes": {},
            "error": str(e),
        }