"""
pipeline/l2_nlp.py — TF-IDF + Logistic Regression phishing classifier.

Mirrors Microsoft MDO's semantic intent classification layer.

The model is loaded ONCE at module import time from disk.
If the model files are not found, the module logs a warning and returns
a safe score of 0 — the pipeline continues without NLP.

Run models/train_classifier.py once before starting the app to generate:
    models/vectorizer.pkl
    models/classifier.pkl

Maximum contribution: 3 points (L2N_CAP in scoring.py).
"""

import os
import logging

logger = logging.getLogger(__name__)

# ── Load model at import time ─────────────────────────────────────────────────
_vectorizer = None
_classifier = None
_model_available = False

try:
    import joblib
    from config import NLP_MODEL_DIR

    _vec_path = os.path.join(NLP_MODEL_DIR, "vectorizer.pkl")
    _clf_path = os.path.join(NLP_MODEL_DIR, "classifier.pkl")

    if os.path.exists(_vec_path) and os.path.exists(_clf_path):
        _vectorizer = joblib.load(_vec_path)
        _classifier = joblib.load(_clf_path)
        _model_available = True
        logger.info("[L2-NLP] Models loaded from %s", NLP_MODEL_DIR)
    else:
        logger.warning(
            "[L2-NLP] Model files not found at %s — NLP stage will return score 0. "
            "Run: python models/train_classifier.py",
            NLP_MODEL_DIR,
        )
except Exception as exc:
    logger.warning("[L2-NLP] Failed to load models: %s — NLP stage disabled.", exc)


def classify_email(body_text: str) -> tuple[str, float]:
    """
    Classify an email body as phishing or ham.

    Args:
        body_text: Plain text email body (HTML already stripped by email_parser).

    Returns:
        (label, confidence) where label is "phish" or "ham" and confidence
        is the probability of the predicted class (0.0–1.0).

    If models are not loaded, returns ("ham", 0.0) safely.
    """
    if not _model_available or not body_text.strip():
        return "ham", 0.0

    try:
        features = _vectorizer.transform([body_text])
        proba = _classifier.predict_proba(features)[0]

        # The classifier was trained with labels ["ham", "phish"]
        # Check which index corresponds to "phish"
        classes = list(_classifier.classes_)
        if "phish" in classes:
            phish_idx = classes.index("phish")
        else:
            # Fallback: assume class 1 = phish
            phish_idx = 1

        phish_confidence = float(proba[phish_idx])
        label = "phish" if phish_confidence >= 0.5 else "ham"
        confidence = phish_confidence if label == "phish" else float(proba[1 - phish_idx])

        return label, confidence

    except Exception as exc:
        logger.error("[L2-NLP] Classification failed: %s", exc)
        return "ham", 0.0


def score_classification(label: str, confidence: float) -> int:
    """
    Convert a (label, confidence) pair into an SCL score contribution.

    Scoring:
        phish, confidence > 0.85  → +3
        phish, confidence 0.60–0.85 → +2
        phish, confidence < 0.60  → +1
        ham   → 0

    Args:
        label:      "phish" or "ham"
        confidence: Probability of the predicted class.

    Returns:
        Score delta (0–3).
    """
    if label != "phish":
        return 0
    if confidence > 0.85:
        return 3
    if confidence >= 0.60:
        return 2
    return 1


def check_nlp(body_text: str, message_id: str = "") -> tuple[int, str, float]:
    """
    Full NLP stage: classify + score.

    Args:
        body_text:   Plain text body.
        message_id:  For structured logging.

    Returns:
        (score, label, confidence)
    """
    label, confidence = classify_email(body_text)
    score = score_classification(label, confidence)

    logger.info(
        "[L2-NLP] [%s] label=%s confidence=%.3f score=%d",
        message_id, label, confidence, score,
    )

    return score, label, confidence
