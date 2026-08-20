"""Domain-reputation model inference.

Scope is narrow and deliberately so: the model scores a *registrable domain*, not
a URL. See `ml/url_features` for the measurement that forced that, and
`ml/train_url` for the shared-hosting exclusion.

Measured held-out behaviour (ROC AUC 0.815) makes this a supporting signal, not a
load-bearing one. The thresholds come from the observed precision curve, chosen so
we only ever surface the model where its precision is high:

    measured on held-out data
        p >= 0.50   83.0% precision   <- too noisy to show anyone
        p >= 0.70   93.3% precision
        p >= 0.90   97.8% precision, 32.5% recall
        p >= 0.95   98.5% precision, 27.1% recall

    mapping used
        p >= 0.95  ->  HIGH
        p >= 0.90  ->  MEDIUM
        below      ->  no signal at all

Trading recall for precision is deliberate. Section 14.3 argues that a noisy
warning costs the install, and while a model can only reach AMBER, a stream of
unjustified ambers still teaches the user to ignore us. Recall is the rule
engine's job.

Even at HIGH this cannot raise RED, because `deterministic=False`.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from ..schemas import Pillar, Severity, Signal

logger = logging.getLogger(__name__)

# Below 0.90 the measured precision is 93% or worse, which is not good enough to
# put in front of the primary persona even as an amber.
MIN_PROBABILITY = 0.90
HIGH_THRESHOLD = 0.95
MEDIUM_THRESHOLD = 0.90


@lru_cache(maxsize=1)
def _load() -> dict[str, Any] | None:
    """Load the trained artifact once, or return None if unavailable."""
    try:
        import joblib

        from ml.paths import URL_MODEL_PATH
    except ImportError:
        logger.info("url model dependencies unavailable; skipping")
        return None

    if not URL_MODEL_PATH.exists():
        logger.info("url model artifact missing at %s; skipping", URL_MODEL_PATH)
        return None

    try:
        return joblib.load(URL_MODEL_PATH)
    except Exception:
        logger.warning("failed to load url model", exc_info=True)
        return None


def is_available() -> bool:
    return _load() is not None


def model_metrics() -> dict[str, Any]:
    bundle = _load()
    return dict(bundle.get("metrics", {})) if bundle else {}


def _registrable(url: str) -> str | None:
    from ml.url_features import registrable_of

    candidate = url if "://" in url else f"http://{url}"
    try:
        host = (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return None
    return registrable_of(host) if host else None


def score_domain(domain: str) -> float | None:
    """Probability that a registrable domain was maliciously registered."""
    bundle = _load()
    if bundle is None or not domain:
        return None
    try:
        from ml.url_features import extract

        return float(bundle["model"].predict_proba([extract(domain)])[0][1])
    except Exception:
        logger.warning("url model scoring failed", exc_info=True)
        return None


def analyse_urls(urls: list[str]) -> list[Signal]:
    """Score each URL's registrable domain, one signal per distinct domain."""
    if not urls or not is_available():
        return []

    seen: set[str] = set()
    signals: list[Signal] = []

    for url in urls:
        domain = _registrable(url)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        probability = score_domain(domain)
        if probability is None or probability < MIN_PROBABILITY:
            continue

        severity = (
            Severity.HIGH if probability >= HIGH_THRESHOLD else Severity.MEDIUM
        )

        signals.append(
            Signal(
                code="URL_MODEL_DOMAIN_REPUTATION",
                pillar=Pillar.URL,
                severity=severity,
                # The whole point: a model may inform, never interrupt.
                deterministic=False,
                weight=1.0,
                detail={
                    "domain": domain,
                    "probability": round(probability, 4),
                },
            )
        )

    return signals
