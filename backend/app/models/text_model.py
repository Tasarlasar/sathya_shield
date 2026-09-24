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
import re
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

# The text model must never score a URL as prose.
#
# The UCI training corpus ties URLs to spam, so the classifier learned
# "contains a link => scam" and scores bare bank homepages 0.58-0.88
# (axisbank.com 0.86, irctc.co.in 0.84, google.com 0.65). When a message is
# essentially just a link, running the text model on it produces a confident
# false positive on a legitimate site. URLs are the URL pillar's job; the text
# model judges the words a human wrote around them.
_URL_RE = re.compile(r"""(?xi)\b(?:https?://|www\.)[^\s<>"'\]\[{}|\\^`]+""")

# After URLs are stripped, a message with fewer than this many alphanumeric
# characters left is treated as "just a link" and the model is not consulted.
# Long enough to drop a bare URL, short enough to keep "Pay here: <link>".
_MIN_PROSE_WORD_CHARS = 12


def strip_urls(text: str) -> str:
    """Remove URLs so the model scores only the surrounding prose."""
    return _URL_RE.sub(" ", text or "").strip()


def _prose_char_count(text: str) -> int:
    return sum(1 for c in text if c.isalnum())


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
    """Probability that a message is a scam, or None if not scored.

    Returns None both when the model is unavailable AND when the message is
    essentially just a URL, because the model cannot judge a link as prose.
    """
    bundle = _load()
    if bundle is None or not text or not text.strip():
        return None

    prose = strip_urls(text)
    if _prose_char_count(prose) < _MIN_PROSE_WORD_CHARS:
        # Nothing but a link (and maybe a word or two). Leave URL judgement to
        # the URL pillar; scoring this as prose is what flagged bank homepages.
        return None

    try:
        return float(bundle["model"].predict_proba([prose[:MAX_CHARS]])[0][1])
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
