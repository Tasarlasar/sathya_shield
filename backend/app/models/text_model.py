"""Message-text scam classifier inference.

Measured behaviour, which callers should keep in proportion:

- English SMS, in distribution: ROC AUC 0.995
- Current Indian scam text: caught 2 of 8 hand-written probes, and scored a
  Devanagari example at 0.045
- Benign Indian messages: 0 of 6 false positives

So a positive score is worth something and a negative score means very little.
That asymmetry is why this only ever contributes AMBER, and why the deterministic
rules in `pillars/text_intent` remain the primary text detector. Section 12.3
records the fix: a hand-collected Indian corpus, not a larger model.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from ..pillars.text_intent import attach_model_score
from ..schemas import Signal

logger = logging.getLogger(__name__)

# Below this the model is not informative enough to show anyone.
#
# Set from a measured false positive, not from the ROC curve: a real HDFC
# transaction SMS ("Rs.2500 debited... Never share your OTP") scores 0.75,
# because legitimate bank messages resemble the promotional spam in the UCI
# corpus. A 0.50 floor turned that message AMBER, which is precisely the
# false-positive behaviour section 14.3 says destroys trust.
MIN_PROBABILITY = 0.85

# Longer inputs are truncated: the classifier was trained on SMS-length text and
# a long email body dilutes the signal.
MAX_CHARS = 2_000


@lru_cache(maxsize=1)
def _load() -> dict[str, Any] | None:
    try:
        import joblib

        from ml.paths import TEXT_MODEL_PATH
    except ImportError:
        logger.info("text model dependencies unavailable; skipping")
        return None

    if not TEXT_MODEL_PATH.exists():
        logger.info("text model artifact missing at %s; skipping", TEXT_MODEL_PATH)
        return None

    try:
        return joblib.load(TEXT_MODEL_PATH)
    except Exception:
        logger.warning("failed to load text model", exc_info=True)
        return None


def is_available() -> bool:
    return _load() is not None


def model_metrics() -> dict[str, Any]:
    bundle = _load()
    return dict(bundle.get("metrics", {})) if bundle else {}


def score_text(text: str) -> float | None:
    """Probability that a message is a scam, or None if the model is unavailable."""
    bundle = _load()
    if bundle is None or not text or not text.strip():
        return None
    try:
        return float(bundle["model"].predict_proba([text[:MAX_CHARS]])[0][1])
    except Exception:
        logger.warning("text model scoring failed", exc_info=True)
        return None


def analyse_text(text: str) -> list[Signal]:
    probability = score_text(text)
    if probability is None or probability < MIN_PROBABILITY:
        return []
    # attach_model_score is the single place that constructs a non-deterministic
    # text signal, so the deterministic flag cannot drift between callers.
    return [attach_model_score(probability, model_name="tfidf-logreg-v1")]
